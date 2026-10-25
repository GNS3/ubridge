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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/virtio_net.h>

#include "ubridge.h"
#include "nio_linux_raw.h"
#include "gso.h"

/* One frame as the socket delivers it: up to 64 KB of IP packet once GRO,
 * LRO or TSO have merged segments, plus its link-layer header and a VLAN
 * tag put back from PACKET_AUXDATA */
#define RAW_FRAME_MAXLEN    (65536 + 64)

struct nio_linux_raw_rx {
   gso_tcp_t gso;
   int gso_pending;
   unsigned char frame[RAW_FRAME_MAXLEN];
};

/* Get interface index of specified device */
static int nio_linux_raw_dev_id(char *device)
{
   struct ifreq if_req;
   int fd;

   if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      fprintf(stderr, "nio_linux_raw_dev_id: socket: %s\n", strerror(errno));
      return(-1);
   }

   memset((void *)&if_req,0,sizeof(if_req));
   strcpy(if_req.ifr_name, device);

   if (ioctl(fd,SIOCGIFINDEX,&if_req) < 0) {
      fprintf(stderr, "nio_linux_raw_dev_id: SIOCGIFINDEX: %s\n", strerror(errno));
      close(fd);
      return (-1);
   }

   close(fd);
   return (if_req.ifr_ifindex);
}

/* Get the MTU of specified device: no frame off its wire was longer */
static int nio_linux_raw_dev_mtu(char *device)
{
   struct ifreq if_req;
   int fd;

   if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      fprintf(stderr, "nio_linux_raw_dev_mtu: socket: %s\n", strerror(errno));
      return (0);
   }

   memset((void *)&if_req,0,sizeof(if_req));
   strcpy(if_req.ifr_name, device);

   if (ioctl(fd,SIOCGIFMTU,&if_req) < 0) {
      fprintf(stderr, "nio_linux_raw_dev_mtu: SIOCGIFMTU: %s\n", strerror(errno));
      close(fd);
      return (0);
   }

   close(fd);
   return (if_req.ifr_mtu);
}

/* Open a new RAW socket */
static int nio_linux_raw_open_socket(char *device)
{
   struct sockaddr_ll sa;
   struct packet_mreq mreq;
   int sck;

   if ((sck = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) == -1) {
      fprintf(stderr, "nio_linux_raw_open_socket: socket: %s\n",strerror(errno));
      return (-1);
   }

   memset(&sa,0,sizeof(struct sockaddr_ll));
   sa.sll_family = AF_PACKET;
   sa.sll_protocol = htons(ETH_P_ALL);
   sa.sll_hatype = ARPHRD_ETHER;
   sa.sll_halen = ETH_ALEN;
   sa.sll_ifindex = nio_linux_raw_dev_id(device);

   memset(&mreq,0,sizeof(mreq));
   mreq.mr_ifindex = sa.sll_ifindex;
   mreq.mr_type = PACKET_MR_PROMISC;

   if (bind(sck,(struct sockaddr *)&sa,sizeof(struct sockaddr_ll)) == -1) {
      fprintf(stderr, "nio_linux_raw_open_socket: bind: %s\n", strerror(errno));
      return (-1);
   }

   if (setsockopt(sck, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,sizeof(mreq)) == -1) {
      fprintf(stderr, "nio_linux_raw_open_socket: setsockopt (PACKET_ADD_MEMBERSHIP): %s\n", strerror(errno));
      return (-1);
   }

#ifdef PACKET_AUXDATA
   int val = 1;
   if (setsockopt(sck, SOL_PACKET, PACKET_AUXDATA, &val, sizeof val) == -1) {
      fprintf(stderr, "nio_linux_raw_open_socket: setsockopt (PACKET_AUXDATA): %s\n", strerror(errno));
      return (-1);
   }
#endif

   return (sck);
}

static void nio_linux_raw_free(nio_linux_raw_t *nio_linux_raw)
{
   if (nio_linux_raw->fd != -1)
      close(nio_linux_raw->fd);
   free(nio_linux_raw->rx);
}

static ssize_t nio_linux_raw_send(nio_linux_raw_t *nio_linux_raw, void *pkt, size_t pkt_len)
{
   struct sockaddr_ll sa;
   struct virtio_net_hdr vnet;
   struct iovec iov[2];
   struct msghdr msg;
   ssize_t sent;

   memset(&sa,0,sizeof(struct sockaddr_ll));
   sa.sll_family = AF_PACKET;
   sa.sll_protocol = htons(ETH_P_ALL);
   sa.sll_hatype = ARPHRD_ETHER;
   sa.sll_halen = ETH_ALEN;
   sa.sll_ifindex = nio_linux_raw->dev_id;

   if (!nio_linux_raw->vnet_hdr)
      return (sendto(nio_linux_raw->fd, pkt, pkt_len, 0,(struct sockaddr *)&sa, sizeof(sa)));

   /* a plain frame: no GSO, checksums complete */
   memset(&vnet, 0, sizeof(vnet));
   iov[0].iov_base = &vnet;
   iov[0].iov_len = sizeof(vnet);
   iov[1].iov_base = pkt;
   iov[1].iov_len = pkt_len;
   memset(&msg, 0, sizeof(msg));
   msg.msg_name = &sa;
   msg.msg_namelen = sizeof(sa);
   msg.msg_iov = iov;
   msg.msg_iovlen = 2;

   sent = sendmsg(nio_linux_raw->fd, &msg, 0);
   if (sent > 0)
      sent -= sizeof(vnet);
   return (sent);
}

/* Read one frame, put back the VLAN tag the NIC stripped and get the GSO
 * and checksum state of the frame in vnet (all zero without PACKET_VNET_HDR) */
static ssize_t nio_linux_raw_read(nio_linux_raw_t *nio_linux_raw, struct virtio_net_hdr *vnet, void *pkt, size_t max_len)
{
   memset(vnet, 0, sizeof(*vnet));

#ifdef PACKET_AUXDATA

#ifdef TP_STATUS_VLAN_TPID_VALID
# define VLAN_TPID(hdr, hv)     (((hv)->tp_vlan_tpid || ((hdr)->tp_status & TP_STATUS_VLAN_TPID_VALID)) ? (hv)->tp_vlan_tpid : ETH_P_8021Q)
#else
# define VLAN_TPID(hdr, hv)     ETH_P_8021Q
#endif

    ssize_t received;
    struct iovec iov[2];
    struct cmsghdr *cmsg;
    struct msghdr msg;
    /* The kernel fills msg_name with a whole struct sockaddr_ll (20 bytes)
     * regardless of msg_namelen — packet_recvmsg() copies
     * sll_halen + offsetof(sll_addr) and zero-pads up to sizeof(sockaddr_ll).
     * A generic 16-byte struct sockaddr overflows the stack by 4 bytes on
     * every received frame (ASan: stack-buffer-overflow, WRITE of size 20). */
    struct sockaddr_ll from;
    union {
      struct cmsghdr  cmsg;
      char    buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;


    memset(&msg, 0, sizeof(msg));
    memset(&cmsg_buf, 0, sizeof(cmsg_buf));

    /* with PACKET_VNET_HDR the kernel puts a struct virtio_net_hdr in front */
    iov[0].iov_base = vnet;
    iov[0].iov_len = sizeof(*vnet);
    iov[1].iov_base = pkt;
    iov[1].iov_len = max_len - VLAN_HEADER_LEN;

    msg.msg_name = &from;
    msg.msg_namelen  = sizeof(from);
    msg.msg_iov = nio_linux_raw->vnet_hdr ? iov : &iov[1];
    msg.msg_iovlen = nio_linux_raw->vnet_hdr ? 2 : 1;
    msg.msg_control = &cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    msg.msg_flags = 0;

    received = recvmsg(nio_linux_raw->fd, &msg, MSG_TRUNC);
    if (received > 0 && nio_linux_raw->vnet_hdr)
       received -= sizeof(*vnet);
    /* MSG_TRUNC: the real length of a frame that did not fit, which leaves
     * no room to put a VLAN tag back. The caller drops it */
    if (received > (ssize_t)(max_len - VLAN_HEADER_LEN))
       return (received);
    if (received > 0) {

       /* Code mostly copied from libpcap to reconstruct VLAN header */
       for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
           struct tpacket_auxdata *aux;
           vlan_tag_t *tag;

           if (cmsg->cmsg_len >= CMSG_LEN(sizeof(struct tpacket_auxdata)) && cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_AUXDATA) {
                aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);
#if defined(TP_STATUS_VLAN_VALID)
                if ((aux->tp_vlan_tci == 0) && !(aux->tp_status & TP_STATUS_VLAN_VALID))
#else
                /* this is ambigious but without the TP_STATUS_VLAN_VALID flag,
                   there is nothing that we can do */
                if (aux->tp_vlan_tci == 0)
#endif
                   continue;

                /* VLAN tag found. Shift MAC addresses down and insert VLAN tag */
                memmove((unsigned char *)pkt + ETH_ALEN * 2 + VLAN_HEADER_LEN,
                        (unsigned char *)pkt + ETH_ALEN * 2,
                        received - ETH_ALEN * 2);
                received += VLAN_HEADER_LEN;
                tag = (vlan_tag_t *)((unsigned char *)pkt + ETH_ALEN * 2);
                tag->vlan_tp_id = htons(VLAN_TPID(aux,aux));
                tag->vlan_tci = htons(aux->tp_vlan_tci);
                /* the checksummed part moved along */
                if (vnet->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
                   vnet->csum_start += VLAN_HEADER_LEN;
            }
       }
    }
    return (received);
#else
    return (recv(nio_linux_raw->fd, pkt, max_len, 0));
#endif
}

/*
 * GRO, LRO (hv_netvsc RSC, for one) and TSO hand the socket TCP frames of
 * up to 64 KB, and GRO and TSO frames carry a partial checksum. The kernel
 * splits such frames itself before it forwards them; a relay that passed
 * them on byte for byte would feed the node frames longer than its MTU, all
 * dropped (a cloud on a host NIC crawled at a few hundred kbit/s). Cut them
 * back into wire-sized segments, one per call, and complete the checksums.
 */
static ssize_t nio_linux_raw_recv(nio_linux_raw_t *nio_linux_raw, void *pkt, size_t max_len)
{
   struct nio_linux_raw_rx *rx = nio_linux_raw->rx;
   struct virtio_net_hdr vnet;
   size_t gso_size = 0;
   ssize_t len, seg;

   /* the rest of the frame being segmented */
   if (rx->gso_pending) {
      if ((seg = gso_tcp_next(&rx->gso, pkt, max_len)) > 0)
         return (seg);
      rx->gso_pending = FALSE;
   }

   /* EINVAL: the frame had a GSO type that a virtio_net_hdr cannot
    * describe and the kernel dropped it. Read the next one */
   do {
      len = nio_linux_raw_read(nio_linux_raw, &vnet, rx->frame, sizeof(rx->frame));
   } while (len < 0 && errno == EINVAL && nio_linux_raw->vnet_hdr);
   /* a truncated frame (MSG_TRUNC length) is longer than the caller takes */
   if (len <= 0 || len > (ssize_t)sizeof(rx->frame))
      return (len);

   switch (vnet.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
   case VIRTIO_NET_HDR_GSO_TCPV4:
   case VIRTIO_NET_HDR_GSO_TCPV6:
      gso_size = vnet.gso_size;
      break;
   }
   if (gso_tcp_init(&rx->gso, rx->frame, len, gso_size, nio_linux_raw->mtu) &&
       (seg = gso_tcp_next(&rx->gso, pkt, max_len)) > 0) {
      rx->gso_pending = TRUE;
      return (seg);
   }

   if (vnet.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
      gso_csum_complete(rx->frame, len, vnet.csum_start, vnet.csum_offset);
   /* too long for the caller, which drops it */
   if (len > (ssize_t)max_len)
      return (len);
   memcpy(pkt, rx->frame, len);
   return (len);
}

/* Create a new NIO Linux RAW */
nio_t *create_nio_linux_raw(char *dev_name)
{
   nio_linux_raw_t *nio_linux_raw;
   nio_t *nio;

   if (!(nio = create_nio()))
      return NULL;

   nio_linux_raw = &nio->u.nio_linux_raw;

   if (strlen(dev_name) >= NIO_DEV_MAXLEN) {
      fprintf(stderr, "create_nio_linux_raw: bad Ethernet device string specified.\n");
      free_nio(nio);
      return NULL;
   }

   nio_linux_raw->fd = nio_linux_raw_open_socket(dev_name);
   nio_linux_raw->dev_id = nio_linux_raw_dev_id(dev_name);

   if (nio_linux_raw->fd < 0) {
      free_nio(nio);
      return NULL;
   }

   if (!(nio_linux_raw->rx = calloc(1, sizeof(*nio_linux_raw->rx)))) {
      fprintf(stderr, "create_nio_linux_raw: out of memory\n");
      close(nio_linux_raw->fd);
      free_nio(nio);
      return NULL;
   }

   /* the MTU bounds the segments of merged frames */
   nio_linux_raw->mtu = nio_linux_raw_dev_mtu(dev_name);

#if defined(PACKET_AUXDATA) && defined(PACKET_VNET_HDR)
   /* the GSO size and checksum state of every frame. Without them, frames
    * over the MTU are still cut to it, but partial checksums stay partial */
   {
      int on = 1;

      if (setsockopt(nio_linux_raw->fd, SOL_PACKET, PACKET_VNET_HDR, &on, sizeof(on)) == 0)
         nio_linux_raw->vnet_hdr = TRUE;
      else
         fprintf(stderr, "create_nio_linux_raw: setsockopt (PACKET_VNET_HDR): %s\n", strerror(errno));
   }
#endif

   nio->type = NIO_TYPE_LINUX_RAW;
   nio->send = (void *)nio_linux_raw_send;
   nio->recv = (void *)nio_linux_raw_recv;
   nio->free = (void *)nio_linux_raw_free;
   nio->dptr = &nio->u.nio_linux_raw;

   return nio;
}
