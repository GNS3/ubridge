/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2015 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   ubridge is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <string.h>

#include "gso.h"

#define ETH_ADDRS_LEN       12      /* destination + source MAC */
#define ETHTYPE_IPV4        0x0800
#define ETHTYPE_IPV6        0x86dd
#define ETHTYPE_8021Q       0x8100
#define ETHTYPE_8021AD      0x88a8
#define VLAN_TAG_LEN        4
#define MAX_VLAN_TAGS       2

#define IPV4_MIN_HLEN       20
#define IPV6_HLEN           40
#define TCP_MIN_HLEN        20
#define PROTO_TCP           6

#define TCP_FIN             0x01
#define TCP_PSH             0x08
#define TCP_CWR             0x80

static uint16_t rd16(const unsigned char *p)
{
   return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t rd32(const unsigned char *p)
{
   return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void wr16(unsigned char *p, uint16_t v)
{
   p[0] = v >> 8;
   p[1] = v & 0xff;
}

static void wr32(unsigned char *p, uint32_t v)
{
   p[0] = v >> 24;
   p[1] = (v >> 16) & 0xff;
   p[2] = (v >> 8) & 0xff;
   p[3] = v & 0xff;
}

/* RFC 1071 one's complement sum of big-endian 16-bit words */
static uint64_t csum_add(uint64_t sum, const unsigned char *p, size_t len)
{
   while (len > 1) {
      sum += rd16(p);
      p += 2;
      len -= 2;
   }
   if (len)
      sum += (uint32_t)p[0] << 8;
   return sum;
}

static uint16_t csum_fold(uint64_t sum)
{
   while (sum >> 16)
      sum = (sum & 0xffff) + (sum >> 16);
   return (uint16_t)~sum;
}

int gso_tcp_init(gso_tcp_t *gso, const unsigned char *frame, size_t len, size_t gso_size, size_t mtu)
{
   size_t l3, l4, end, hdr_len, hdrs, mss;
   uint16_t type;
   int tags, ipv6;

   if (len < ETH_ADDRS_LEN + 2)
      return 0;
   l3 = ETH_ADDRS_LEN;
   type = rd16(frame + l3);
   for (tags = 0; (type == ETHTYPE_8021Q || type == ETHTYPE_8021AD) && tags < MAX_VLAN_TAGS; tags++) {
      l3 += VLAN_TAG_LEN;
      if (len < l3 + 2)
         return 0;
      type = rd16(frame + l3);
   }
   l3 += 2;

   if (type == ETHTYPE_IPV4) {
      size_t ihl;

      if (len < l3 + IPV4_MIN_HLEN || frame[l3] >> 4 != 4)
         return 0;
      ihl = (size_t)(frame[l3] & 0x0f) * 4;
      /* TCP only, and never a fragment */
      if (ihl < IPV4_MIN_HLEN || frame[l3 + 9] != PROTO_TCP || (rd16(frame + l3 + 6) & 0x3fff))
         return 0;
      ipv6 = 0;
      l4 = l3 + ihl;
      end = l3 + rd16(frame + l3 + 2);
   } else if (type == ETHTYPE_IPV6) {
      if (len < l3 + IPV6_HLEN || frame[l3] >> 4 != 6)
         return 0;
      /* TCP right after the fixed header. Extension headers and jumbograms
       * (payload length 0) are left alone */
      if (frame[l3 + 6] != PROTO_TCP || rd16(frame + l3 + 4) == 0)
         return 0;
      ipv6 = 1;
      l4 = l3 + IPV6_HLEN;
      end = l4 + rd16(frame + l3 + 4);
   } else
      return 0;

   if (end > len || end < l4 + TCP_MIN_HLEN)
      return 0;
   hdr_len = l4 + (size_t)(frame[l4 + 12] >> 4) * 4;
   /* nothing to split without payload */
   if (hdr_len < l4 + TCP_MIN_HLEN || hdr_len >= end)
      return 0;

   /* a frame of wire size that the kernel did not merge */
   if (!gso_size && (!mtu || end - l3 <= mtu))
      return 0;

   mss = gso_size;
   hdrs = hdr_len - l3;
   if (mtu) {
      if (mtu <= hdrs)
         return 0;
      if (!mss || mss > mtu - hdrs)
         mss = mtu - hdrs;
   }

   gso->frame = frame;
   gso->l3_off = l3;
   gso->l4_off = l4;
   gso->hdr_len = hdr_len;
   gso->end = end;
   gso->mss = mss;
   gso->pos = hdr_len;
   gso->ipv6 = ipv6;
   return 1;
}

ssize_t gso_tcp_next(gso_tcp_t *gso, unsigned char *seg, size_t max_len)
{
   const unsigned char *frame = gso->frame;
   size_t l3 = gso->l3_off, l4 = gso->l4_off, hdr_len = gso->hdr_len;
   size_t n, seg_len, offset;
   unsigned char *th;
   uint64_t sum;

   if (gso->pos >= gso->end)
      return 0;
   n = gso->end - gso->pos;
   if (n > gso->mss)
      n = gso->mss;
   seg_len = hdr_len + n;
   if (seg_len > max_len)
      return -1;

   memcpy(seg, frame, hdr_len);
   memcpy(seg + hdr_len, frame + gso->pos, n);
   /* sequence offset of this segment into the merged payload */
   offset = gso->pos - hdr_len;

   if (gso->ipv6) {
      wr16(seg + l3 + 4, (uint16_t)(seg_len - l3 - IPV6_HLEN));
   } else {
      wr16(seg + l3 + 2, (uint16_t)(seg_len - l3));
      /* consecutive IDs from the first segment's, as the kernel's GSO does */
      wr16(seg + l3 + 4, (uint16_t)(rd16(frame + l3 + 4) + offset / gso->mss));
      wr16(seg + l3 + 10, 0);
      wr16(seg + l3 + 10, csum_fold(csum_add(0, seg + l3, l4 - l3)));
   }

   th = seg + l4;
   wr32(th + 4, rd32(frame + l4 + 4) + (uint32_t)offset);
   /* CWR only on the first segment, FIN and PSH only on the last
    * (the kernel's tcp_gso_segment does the same) */
   if (offset)
      th[13] &= ~TCP_CWR;
   if (gso->pos + n < gso->end)
      th[13] &= ~(TCP_FIN | TCP_PSH);

   /* the full checksum: pseudo header, then TCP header and payload */
   wr16(th + 16, 0);
   if (gso->ipv6)
      sum = csum_add(0, seg + l3 + 8, 32);   /* source + destination */
   else
      sum = csum_add(0, seg + l3 + 12, 8);
   sum += PROTO_TCP + (seg_len - l4);
   sum = csum_add(sum, th, seg_len - l4);
   wr16(th + 16, csum_fold(sum));

   gso->pos += n;
   return (ssize_t)seg_len;
}

int gso_csum_complete(unsigned char *frame, size_t len, size_t csum_start, size_t csum_offset)
{
   uint16_t csum;

   if (csum_start > len || csum_offset + 2 > len - csum_start)
      return -1;
   /* the field already holds the pseudo-header sum, so it is summed in */
   csum = csum_fold(csum_add(0, frame + csum_start, len - csum_start));
   /* 0 means "no checksum" to UDP; 0xffff is the same value to TCP */
   wr16(frame + csum_start + csum_offset, csum ? csum : 0xffff);
   return 0;
}
