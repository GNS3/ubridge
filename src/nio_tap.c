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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netdb.h>

#ifdef __linux__
#include <net/if.h>
#include <linux/if_tun.h>
#endif

#include "ubridge.h"
#include "nio_tap.h"


/* Open a TAP device */
static int nio_tap_open(char *tap_devname)
{
#ifdef __linux__
   struct ifreq ifr;
   int err, fd;
   if (*tap_devname == '/') {
      if ((fd = open(tap_devname, O_RDWR)) < 0)
         return(-1);

      if ((err = ioctl(fd, TUNGETIFF, &ifr)) < 0) {
         close(fd);
         return err;
      }
      if (ifr.ifr_flags | IFF_VNET_HDR) {
         ifr.ifr_flags &= ~IFF_VNET_HDR;
         if ((err = ioctl(fd, TUNSETIFF, &ifr)) < 0) {
            fprintf(stderr, "nio_tap_open: cannot clean IFF_VNET_HDR bit.\n");
            close(fd);
            return err;
         }
      }
      if (ifr.ifr_flags != (IFF_TAP | IFF_NO_PI)) {
         fprintf(stderr, "nio_tap_open: bad TAP device specified (%d).\n",
                 ifr.ifr_flags);
         close(fd);
         return(-1);
      }
   } else {
      if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
         return(-1);

      memset(&ifr,0,sizeof(ifr));
      ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
      if (*tap_devname)
         strncpy(ifr.ifr_name, tap_devname, IFNAMSIZ);

      if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
         close(fd);
         return err;
      }

      strcpy(tap_devname, ifr.ifr_name);
   }
   return(fd);
#else
   int i, fd = -1;
   char tap_fullname[NIO_DEV_MAXLEN];

   if (*tap_devname) {
      snprintf(tap_fullname, NIO_DEV_MAXLEN, "/dev/%s", tap_devname);
      fd = open(tap_fullname, O_RDWR);
   } else {
      for(i = 0; i < 16; i++) {
         snprintf(tap_devname, NIO_DEV_MAXLEN, "/dev/tap%d", i);

         if ((fd = open(tap_devname, O_RDWR)) >= 0)
            break;
      }
   }

   return (fd);
#endif
}

static void nio_tap_free(nio_tap_t *nio_tap)
{
   if (nio_tap->fd != -1)
     close(nio_tap->fd);
}

static ssize_t nio_tap_send(nio_tap_t *nio_tap, void *pkt, size_t pkt_len)
{
   return (write(nio_tap->fd, pkt, pkt_len));
}

static ssize_t nio_tap_recv(nio_tap_t *nio_tap, void *pkt, size_t max_len)
{
#ifdef __APPLE__
  /* wait for an active IP interface and incoming data */
  fd_set tap_fd_set;
  FD_ZERO(&tap_fd_set);
  FD_SET(nio_tap->fd, &tap_fd_set);
  if (select(nio_tap->fd + 1, &tap_fd_set, NULL, NULL, NULL) < 0)
     return (-1);
#endif
   return (read(nio_tap->fd, pkt, max_len));
}

/* Create a new NIO TAP */
nio_t *create_nio_tap(char *tap_name)
{
   nio_tap_t *nio_tap;
   nio_t *nio;

   if (!(nio = create_nio()))
      return NULL;

   nio_tap = &nio->u.nio_tap;

   if (strlen(tap_name) >= NIO_DEV_MAXLEN) {
      fprintf(stderr, "create_nio_tap: bad TAP device string specified.\n");
      free_nio(nio);
      return NULL;
   }

   memset(nio_tap, 0, sizeof(*nio_tap));
   nio_tap->fd = nio_tap_open(tap_name);

   if (nio_tap->fd == -1) {
      fprintf(stderr,"create_nio_tap: unable to open TAP device %s (%s)\n", tap_name, strerror(errno));
      free_nio(nio);
      return NULL;
   }

   nio->type = NIO_TYPE_TAP;
   nio->send = (void *)nio_tap_send;
   nio->recv = (void *)nio_tap_recv;
   nio->free = (void *)nio_tap_free;
   nio->dptr = &nio->u.nio_tap;
   return nio;
}
