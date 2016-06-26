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
      return(-1);
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
      fprintf(stderr, "nio_linux_raw_open_socket: bind: %s\n",strerror(errno));
      return(-1);
   }

   if (setsockopt(sck,SOL_PACKET,PACKET_ADD_MEMBERSHIP,
                  &mreq,sizeof(mreq)) == -1)
   {
      fprintf(stderr, "nio_linux_raw_open_socket: setsockopt: %s\n",strerror(errno));
      return(-1);
   }

   return(sck);
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
   return (recv(nio_linux_raw->fd, pkt, max_len, 0));
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