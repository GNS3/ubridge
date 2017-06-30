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

#include "ubridge.h"
#include "nio_linux_raw.h"

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
}

static ssize_t nio_linux_raw_send(nio_linux_raw_t *nio_linux_raw, void *pkt, size_t pkt_len)
{
   struct sockaddr_ll sa;

   memset(&sa,0,sizeof(struct sockaddr_ll));
   sa.sll_family = AF_PACKET;
   sa.sll_protocol = htons(ETH_P_ALL);
   sa.sll_hatype = ARPHRD_ETHER;
   sa.sll_halen = ETH_ALEN;
   sa.sll_ifindex = nio_linux_raw->dev_id;

   return (sendto(nio_linux_raw->fd, pkt, pkt_len, 0,(struct sockaddr *)&sa, sizeof(sa)));
}

static ssize_t nio_linux_raw_recv(nio_linux_raw_t *nio_linux_raw, void *pkt, size_t max_len)
{
#ifdef PACKET_AUXDATA

#ifdef TP_STATUS_VLAN_TPID_VALID
# define VLAN_TPID(hdr, hv)     (((hv)->tp_vlan_tpid || ((hdr)->tp_status & TP_STATUS_VLAN_TPID_VALID)) ? (hv)->tp_vlan_tpid : ETH_P_8021Q)
#else
# define VLAN_TPID(hdr, hv)     ETH_P_8021Q
#endif

    ssize_t received;
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct msghdr msg;
    struct sockaddr from;
    union {
      struct cmsghdr  cmsg;
      char    buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;


    memset(&msg, 0, sizeof(msg));
    memset(&cmsg_buf, 0, sizeof(cmsg_buf));

    msg.msg_name = &from;
    msg.msg_namelen  = sizeof(from);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    msg.msg_flags = 0;
    iov.iov_len = max_len - VLAN_HEADER_LEN;
    iov.iov_base = pkt;

    received = recvmsg(nio_linux_raw->fd, &msg, MSG_TRUNC);
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
            }
       }
    }
    return (received);
#else
    return (recv(nio_linux_raw->fd, pkt, max_len, 0));
#endif
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

   nio->type = NIO_TYPE_LINUX_RAW;
   nio->send = (void *)nio_linux_raw_send;
   nio->recv = (void *)nio_linux_raw_recv;
   nio->free = (void *)nio_linux_raw_free;
   nio->dptr = &nio->u.nio_linux_raw;

   return nio;
}
