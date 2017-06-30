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
#include <arpa/inet.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>

#include "ubridge.h"
#include "nio_udp.h"


static int udp_connect(int local_port, char *remote_host, int remote_port)
{
   struct addrinfo hints, *res, *res0;
   struct sockaddr_storage st;
   int error, sck = -1, yes = 1;
   char port_str[20];
   char hostname[HOST_NAME_MAX];
   void *ptr;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = PF_UNSPEC;
   hints.ai_socktype = SOCK_DGRAM;

   snprintf(port_str, sizeof(port_str), "%d", remote_port);

   if ((error = getaddrinfo(remote_host, port_str, &hints, &res0)) != 0) {
     fprintf(stderr,"%s\n", gai_strerror(error));
     return(-1);
   }

   for(res = res0; res; res = res->ai_next) {
     /* We want only IPv4 or IPv6 */
     if ((res->ai_family != PF_INET) && (res->ai_family != PF_INET6))
        continue;

     /* create new socket */
     if ((sck = socket(res->ai_family, SOCK_DGRAM, res->ai_protocol)) < 0) {
        perror("udp_connect: socket");
        continue;
     }

     /* bind to the local port */
     memset(&st, 0, sizeof(st));

     switch(res->ai_family) {
       case PF_INET: {
         struct sockaddr_in *sin = (struct sockaddr_in *)&st;
         sin->sin_family = PF_INET;
         sin->sin_port = htons(local_port);
         ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
         break;
       }

       case PF_INET6: {
         struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&st;
#ifdef SIN6_LEN
         sin6->sin6_len = res->ai_addrlen;
#endif
         sin6->sin6_family = PF_INET6;
         sin6->sin6_port = htons(local_port);
         ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
         break;
       }

       default:
         /* shouldn't happen */
         close(sck);
         sck = -1;
         continue;
     }

      setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
      inet_ntop(res->ai_family, ptr, hostname, HOST_NAME_MAX);
      printf("UDP tunnel connecting from local port %d to IPv%d addresss %s on port %d\n",
      local_port, res->ai_family == PF_INET6 ? 6 : 4, hostname, remote_port);

      /* try to connect to remote host */
      if (!bind(sck, (struct sockaddr *)&st, res->ai_addrlen) && !connect(sck, res->ai_addr, res->ai_addrlen))
        break;

      close(sck);
      sck = -1;
   }

   freeaddrinfo(res0);
   return (sck);
}

static void nio_udp_free(nio_udp_t *nio_udp)
{
   if (nio_udp->remote_host) {
     free(nio_udp->remote_host);
     nio_udp->remote_host = NULL;
   }

   if (nio_udp->fd != -1)
     close(nio_udp->fd);
}

static ssize_t nio_udp_send(nio_udp_t *nio_udp, void *pkt, size_t pkt_len)
{
   return (send(nio_udp->fd, pkt, pkt_len, 0));
}

static ssize_t nio_udp_recv(nio_udp_t *nio_udp, void *pkt, size_t max_len)
{
   return (recvfrom(nio_udp->fd, pkt, max_len, 0, NULL, NULL));
}

/* Create a new NIO UDP */
nio_t *create_nio_udp(int local_port, char *remote_host, int remote_port)
{
   nio_udp_t *nio_udp;
   nio_t *nio;

   if (!(nio = create_nio()))
      return NULL;

   nio_udp = &nio->u.nio_udp;
   nio_udp->local_port  = local_port;
   nio_udp->remote_port = remote_port;

   if (!(nio_udp->remote_host = strdup(remote_host))) {
     fprintf(stderr, "create_nio_udp: insufficient memory\n");
     free_nio(nio);
     return NULL;
   }

   if ((nio_udp->fd = udp_connect(local_port, remote_host, remote_port)) < 0) {
     fprintf(stderr, "create_nio_udp: unable to connect to %s:%d\n", remote_host, remote_port);
     free_nio(nio);
     return NULL;
   }

   nio->type = NIO_TYPE_UDP;
   nio->send = (void *)nio_udp_send;
   nio->recv = (void *)nio_udp_recv;
   nio->free = (void *)nio_udp_free;
   nio->dptr = &nio->u.nio_udp;
   return nio;
}
