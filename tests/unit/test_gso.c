#include <criterion/criterion.h>
#include <stdint.h>
#include <string.h>

#include "gso.h"

/* Segments of TCP frames merged by GRO/LRO or built by TSO (src/gso.c) */

#define TCP_HLEN    32      /* with a timestamps option, as Linux sends it */
#define F_FIN       0x01
#define F_PSH       0x08
#define F_ACK       0x10
#define F_CWR       0x80

typedef struct {
  int    ipv6;
  size_t l3, l4, len;
} layout_t;

static unsigned char frame[70000];
static unsigned char seg[70000];

static void put16(unsigned char *p, unsigned v)
{
  p[0] = (v >> 8) & 0xff;
  p[1] = v & 0xff;
}

static void put32(unsigned char *p, uint32_t v)
{
  put16(p, v >> 16);
  put16(p + 2, v & 0xffff);
}

static unsigned get16(const unsigned char *p)
{
  return (unsigned)p[0] << 8 | p[1];
}

static uint32_t get32(const unsigned char *p)
{
  return (uint32_t)get16(p) << 16 | get16(p + 2);
}

static uint32_t sum16(uint32_t sum, const unsigned char *p, size_t len)
{
  for (; len > 1; p += 2, len -= 2)
    sum += get16(p);
  if (len)
    sum += (uint32_t)p[0] << 8;
  return sum;
}

static unsigned fold(uint32_t sum)
{
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return sum;
}

static uint32_t pseudo_sum(const unsigned char *f, const layout_t *l, size_t len)
{
  uint32_t sum = l->ipv6 ? sum16(0, f + l->l3 + 8, 32) : sum16(0, f + l->l3 + 12, 8);
  return sum + 6 + (uint32_t)(len - l->l4);
}

static int ipv4_csum_ok(const unsigned char *f, const layout_t *l)
{
  return fold(sum16(0, f + l->l3, 20)) == 0xffff;
}

static int tcp_csum_ok(const unsigned char *f, size_t len, const layout_t *l)
{
  return fold(sum16(pseudo_sum(f, l, len), f + l->l4, len - l->l4)) == 0xffff;
}

/* One TCP segment of payload_len bytes in an Ethernet frame, as GRO leaves
 * a merged one: the IP length covers the whole payload, the TCP checksum is
 * not valid for it */
static layout_t build(int ipv6, int vlan, size_t payload_len, unsigned flags, unsigned ip_id, uint32_t seq)
{
  layout_t       l = { .ipv6 = ipv6 };
  unsigned char *p;

  memset(frame, 0, sizeof(frame));
  memcpy(frame, "\x52\x54\x00\x12\x34\x56\x52\x54\x00\xab\xcd\xef", 12);
  l.l3 = 14;
  if (vlan) {
    put16(frame + 12, 0x8100);
    put16(frame + 14, 100);
    l.l3 = 18;
  }
  put16(frame + l.l3 - 2, ipv6 ? 0x86dd : 0x0800);

  p = frame + l.l3;
  if (ipv6) {
    p[0] = 0x60;
    put16(p + 4, TCP_HLEN + payload_len);
    p[6] = 6;
    p[7] = 64;
    p[8] = 0xfd;
    p[23] = 2;   /* fd00::2 */
    p[24] = 0xfd;
    p[39] = 1;   /* fd00::1 */
    l.l4 = l.l3 + 40;
  } else {
    p[0] = 0x45;
    put16(p + 2, 20 + TCP_HLEN + payload_len);
    put16(p + 4, ip_id);
    put16(p + 6, 0x4000);   /* DF */
    p[8] = 64;
    p[9] = 6;
    memcpy(p + 12, "\x0a\xc7\x00\x02\x0a\xc7\x00\x01", 8);
    put16(p + 10, ~fold(sum16(0, p, 20)) & 0xffff);
    l.l4 = l.l3 + 20;
  }

  p = frame + l.l4;
  put16(p, 443);
  put16(p + 2, 50000);
  put32(p + 4, seq);
  put32(p + 8, 0x01020304);
  p[12] = (TCP_HLEN / 4) << 4;
  p[13] = flags;
  put16(p + 14, 502);
  put16(p + 16, 0x1234);   /* partial or stale */
  memcpy(p + 20, "\x01\x01\x08\x0a\x00\x00\x03\xe8\x00\x00\x07\xd0", 12);
  for (size_t i = 0; i < payload_len; i++)
    p[TCP_HLEN + i] = (unsigned char)(i * 7 + i / 251);

  l.len = l.l4 + TCP_HLEN + payload_len;
  return l;
}

/* Segment the frame and check every segment against it: mss payload bytes
 * each, headers fixed up, payload in order, checksums valid */
static void expect_segments(const layout_t *l, size_t payload_len, size_t gso_size, size_t mtu, size_t mss)
{
  gso_tcp_t gso;
  size_t    hdr = l->l4 + TCP_HLEN, off = 0, i = 0;
  unsigned  flags = frame[l->l4 + 13];
  ssize_t   len;

  cr_assert_eq(gso_tcp_init(&gso, frame, l->len, gso_size, mtu), 1);
  while ((len = gso_tcp_next(&gso, seg, sizeof(seg))) > 0) {
    size_t   n = payload_len - off < mss ? payload_len - off : mss;
    unsigned want = flags;

    cr_assert_eq((size_t)len, hdr + n, "segment %zu is %zd bytes", i, len);
    cr_assert(memcmp(seg, frame, l->l3) == 0, "segment %zu: link-layer header changed", i);
    if (l->ipv6) {
      cr_assert_eq(get16(seg + l->l3 + 4), TCP_HLEN + n);
    } else {
      cr_assert_eq(get16(seg + l->l3 + 2), 20 + TCP_HLEN + n);
      cr_assert_eq(get16(seg + l->l3 + 4), (get16(frame + l->l3 + 4) + i) & 0xffff,
                   "segment %zu: IPv4 ID", i);
      cr_assert(ipv4_csum_ok(seg, l), "segment %zu: IPv4 header checksum", i);
    }

    /* ports, sequence, acknowledgment, window, options */
    cr_assert(memcmp(seg + l->l4, frame + l->l4, 4) == 0);
    cr_assert_eq(get32(seg + l->l4 + 4), (uint32_t)(get32(frame + l->l4 + 4) + off),
                 "segment %zu: sequence number", i);
    cr_assert(memcmp(seg + l->l4 + 8, frame + l->l4 + 8, 5) == 0);
    cr_assert(memcmp(seg + l->l4 + 14, frame + l->l4 + 14, 2) == 0);
    cr_assert(memcmp(seg + l->l4 + 20, frame + l->l4 + 20, TCP_HLEN - 20) == 0);
    if (i)
      want &= ~F_CWR;
    if (off + n < payload_len)
      want &= ~(F_FIN | F_PSH);
    cr_assert_eq(seg[l->l4 + 13], want, "segment %zu: flags %#x", i, seg[l->l4 + 13]);

    cr_assert(memcmp(seg + hdr, frame + hdr + off, n) == 0, "segment %zu: payload", i);
    cr_assert(tcp_csum_ok(seg, (size_t)len, l), "segment %zu: TCP checksum", i);
    off += n;
    i++;
  }
  cr_assert_eq(len, 0);
  cr_assert_eq(off, payload_len, "segments carry %zu of %zu payload bytes", off, payload_len);
}

Test(gso, gro_frame_back_to_its_segments)
{
  /* 4 x MSS 1300 minus timestamps, as in the field: a 5218-byte frame */
  layout_t l = build(0, 0, 4 * 1288, F_ACK | F_PSH, 0x1234, 1000);

  cr_assert_eq(l.len, 5218);
  expect_segments(&l, 4 * 1288, 1288, 1500, 1288);
}

Test(gso, odd_tail_and_wrapping_id_and_sequence)
{
  layout_t l = build(0, 0, 3 * 1448 + 500, F_ACK | F_PSH, 0xfffe, 0xfffff800);

  expect_segments(&l, 3 * 1448 + 500, 1448, 1500, 1448);
}

Test(gso, lro_frame_without_gso_size_cut_to_the_mtu)
{
  /* hv_netvsc RSC: coalesced, no gso_size, longer than the MTU */
  layout_t l = build(0, 0, 4 * 1288, F_ACK, 7, 1);

  expect_segments(&l, 4 * 1288, 0, 1500, 1500 - 20 - TCP_HLEN);
}

Test(gso, gso_size_never_exceeds_the_mtu)
{
  /* GRO on top of LRO reports the first merged unit as gso_size */
  layout_t l = build(0, 0, 3 * 5152, F_ACK, 7, 1);

  expect_segments(&l, 3 * 5152, 5152, 1500, 1500 - 20 - TCP_HLEN);
}

Test(gso, gso_size_kept_without_an_mtu)
{
  layout_t l = build(0, 0, 2 * 1000 + 1, F_ACK, 7, 1);

  expect_segments(&l, 2 * 1000 + 1, 1000, 0, 1000);
}

Test(gso, ipv6_frame)
{
  layout_t l = build(1, 0, 2 * 1428 + 3, F_ACK | F_PSH, 0, 0x80000000);

  expect_segments(&l, 2 * 1428 + 3, 1428, 1500, 1428);
}

Test(gso, vlan_tagged_frame)
{
  layout_t l = build(0, 1, 3 * 1448, F_ACK, 42, 5);

  expect_segments(&l, 3 * 1448, 1448, 1500, 1448);
}

Test(gso, cwr_on_the_first_segment_fin_and_psh_on_the_last)
{
  layout_t l = build(0, 0, 3 * 1000, F_CWR | F_ACK | F_PSH | F_FIN, 1, 1);

  expect_segments(&l, 3 * 1000, 1000, 1500, 1000);
}

Test(gso, small_gso_frame_still_resegmented)
{
  /* GRO also merges short segments into a frame within the MTU */
  layout_t l = build(0, 0, 2 * 400, F_ACK, 1, 1);

  expect_segments(&l, 2 * 400, 400, 1500, 400);
}

Test(gso, wire_sized_frames_left_alone)
{
  gso_tcp_t gso;
  layout_t  l = build(0, 0, 1500 - 20 - TCP_HLEN, F_ACK, 1, 1);

  cr_assert_eq(gso_tcp_init(&gso, frame, l.len, 0, 1500), 0);
  cr_assert_eq(gso_tcp_init(&gso, frame, l.len, 0, 0), 0);
  l = build(0, 0, 1500 - 20 - TCP_HLEN + 1, F_ACK, 1, 1);
  cr_assert_eq(gso_tcp_init(&gso, frame, l.len, 0, 1500), 1);
}

Test(gso, other_frames_left_alone)
{
  gso_tcp_t gso;
  layout_t  l;

  l = build(0, 0, 3000, F_ACK, 1, 1);
  frame[l.l3 + 9] = 17;   /* UDP */
  cr_assert_eq(gso_tcp_init(&gso, frame, l.len, 1000, 1500), 0);

  l = build(0, 0, 3000, F_ACK, 1, 1);
  put16(frame + l.l3 + 6, 0x2000);   /* more fragments */
  cr_assert_eq(gso_tcp_init(&gso, frame, l.len, 1000, 1500), 0);

  l = build(0, 0, 3000, F_ACK, 1, 1);
  put16(frame + 12, 0x0806);   /* ARP */
  cr_assert_eq(gso_tcp_init(&gso, frame, l.len, 1000, 1500), 0);

  l = build(1, 0, 3000, F_ACK, 1, 1);
  frame[l.l3 + 6] = 0;   /* hop-by-hop options header */
  cr_assert_eq(gso_tcp_init(&gso, frame, l.len, 1000, 1500), 0);

  l = build(0, 0, 3000, F_ACK, 1, 1);
  cr_assert_eq(gso_tcp_init(&gso, frame, l.len - 1, 1000, 1500), 0, "IP length beyond the frame");
  cr_assert_eq(gso_tcp_init(&gso, frame, l.l4 + 10, 1000, 1500), 0, "truncated TCP header");
  cr_assert_eq(gso_tcp_init(&gso, frame, 13, 1000, 1500), 0, "truncated Ethernet header");

  l = build(0, 0, 0, F_ACK, 1, 1);
  cr_assert_eq(gso_tcp_init(&gso, frame, l.len, 1000, 1500), 0, "no payload");

  l = build(0, 0, 3000, F_ACK, 1, 1);
  cr_assert_eq(gso_tcp_init(&gso, frame, l.len, 0, 40), 0, "MTU too small for the headers");
}

Test(gso, segment_buffer_too_small)
{
  gso_tcp_t gso;
  layout_t  l = build(0, 0, 3000, F_ACK, 1, 1);

  cr_assert_eq(gso_tcp_init(&gso, frame, l.len, 1000, 1500), 1);
  cr_assert_eq(gso_tcp_next(&gso, seg, l.l4 + TCP_HLEN + 999), -1);
  cr_assert_eq(gso_tcp_next(&gso, seg, sizeof(seg)), (ssize_t)(l.l4 + TCP_HLEN + 1000));
}

Test(gso, partial_checksum_completed)
{
  layout_t l = build(0, 0, 777, F_ACK | F_PSH, 1, 1);
  unsigned full;

  /* the valid checksum */
  put16(frame + l.l4 + 16, 0);
  full = ~fold(sum16(pseudo_sum(frame, &l, l.len), frame + l.l4, l.len - l.l4)) & 0xffff;

  /* CHECKSUM_PARTIAL leaves the pseudo-header sum in the field */
  put16(frame + l.l4 + 16, fold(pseudo_sum(frame, &l, l.len)));
  cr_assert_eq(gso_csum_complete(frame, l.len, l.l4, 16), 0);
  cr_assert_eq(get16(frame + l.l4 + 16), full);
  cr_assert(tcp_csum_ok(frame, l.len, &l));

  cr_assert_eq(gso_csum_complete(frame, l.len, l.len - 1, 0), -1);
  cr_assert_eq(gso_csum_complete(frame, l.len, l.len + 1, 0), -1);
}
