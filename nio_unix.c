/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2016 GNS3 Technologies Inc.
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
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "ubridge.h"
#include "nio_unix.h"


static int create_unix_socket(char *local_filename)
{
    int fd;
    struct sockaddr_un local_sock;

    if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
       perror("create_unix_socket: socket");
       return (-1);
    }

    memset(&local_sock, 0, sizeof(local_sock));
    local_sock.sun_family = AF_UNIX;
    strcpy(local_sock.sun_path, local_filename);
    unlink(local_sock.sun_path);

    if (bind(fd, (struct sockaddr *)&local_sock, sizeof(local_sock)) == -1) {
       perror("create_unix_socket: bind");
       return (-1);
    }

   return (fd);
}

static void nio_unix_free(nio_unix_t *nio_unix)
{
   if (nio_unix->local_filename) {
      unlink(nio_unix->local_filename);
      free(nio_unix->local_filename);
   }

   if (nio_unix->fd != -1)
      close(nio_unix->fd);
}

static ssize_t nio_unix_send(nio_unix_t *nio_unix, void *pkt, size_t pkt_len)
{
   return(sendto(nio_unix->fd, pkt, pkt_len, 0, (struct sockaddr *)&nio_unix->remote_sock, sizeof(nio_unix->remote_sock)));
}

static ssize_t nio_unix_recv(nio_unix_t *nio_unix, void *pkt, size_t max_len)
{
   return (recvfrom(nio_unix->fd, pkt, max_len, 0, NULL, NULL));
}

/* Create a new NIO UNIX */
nio_t *create_nio_unix(char *local, char *remote)
{
   nio_unix_t *nio_unix;
   nio_t *nio;

   if (!(nio = create_nio()))
      return NULL;

   nio_unix = &nio->u.nio_unix;

   if ((strlen(local) >= sizeof(nio_unix->remote_sock.sun_path)) || (strlen(remote) >= sizeof(nio_unix->remote_sock.sun_path))) {
     fprintf(stderr, "create_nio_unix: invalid file path size\n");
     free_nio(nio);
     return NULL;
   }

   if (!(nio_unix->local_filename = strdup(local))) {
     fprintf(stderr, "create_nio_unix: insufficient memory\n");
     free_nio(nio);
     return NULL;
   }

   if ((nio_unix->fd = create_unix_socket(nio_unix->local_filename)) < 0) {
     fprintf(stderr, "create_nio_unix: unable to create UNIX domain socket with %s\n", nio_unix->local_filename);
     free_nio(nio);
     return NULL;
   }

   nio_unix->remote_sock.sun_family = AF_UNIX;
   strcpy(nio_unix->remote_sock.sun_path, remote);

   nio->type = NIO_TYPE_UNIX;
   nio->send = (void *)nio_unix_send;
   nio->recv = (void *)nio_unix_recv;
   nio->free = (void *)nio_unix_free;
   nio->dptr = &nio->u.nio_unix;
   return nio;
}
