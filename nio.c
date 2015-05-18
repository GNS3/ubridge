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

#include "ubridge.h"
#include "nio.h"


nio_t *create_nio(void)
{
   nio_t *nio;

   if (!(nio = malloc(sizeof(*nio))))
     return NULL;
   memset(nio, 0, sizeof(*nio));

   return nio;
}

int free_nio(void *data)
{
   nio_t *nio = data;

   if (nio) {
     if (nio->free != NULL)
       nio->free(nio->dptr);
     free(nio);
   }

   return (TRUE);
}

ssize_t nio_send(nio_t *nio, void *pkt, size_t len)
{
   if (!nio)
     return (-1);

   return (nio->send(nio->dptr, pkt, len));
}

ssize_t nio_recv(nio_t *nio, void *pkt, size_t max_len)
{
   ssize_t len;

   if (!nio)
     return (-1);

   /* Receive the packet */
   if ((len = nio->recv(nio->dptr, pkt, max_len)) <= 0)
      return (-1);

   return(len);
}
