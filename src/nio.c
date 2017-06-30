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
#include "pcap_capture.h"
#include "packet_filter.h"


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
     if (nio->desc != NULL)
       free(nio->desc);
     if (nio->free != NULL)
       nio->free(nio->dptr);
     free(nio);
   }

   return (TRUE);
}

void add_nio_desc(nio_t *nio, const char *fmt, ...)
{
	int len;
	va_list argptr;

	va_start(argptr, fmt);
	len = vsnprintf(NULL, 0, fmt, argptr);

    if ((nio->desc = malloc((len + 1) * sizeof(char)))) {
       va_start(argptr, fmt);
       vsnprintf(nio->desc, len + 1, fmt, argptr);
       va_end(argptr);
    }
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

void dump_packet(FILE *f_output, u_char *pkt, u_int len)
{
   u_int x, i = 0, tmp;

   while (i < len)
   {
      if ((len - i) > 16)
         x = 16;
      else x = len - i;

      fprintf(f_output, "%4.4x: ", i);

      for (tmp = 0; tmp < x; tmp++)
         fprintf(f_output, "%2.2x ",pkt[i + tmp]);
      for (tmp = x;tmp < 16; tmp++) fprintf(f_output,"   ");

      for (tmp = 0; tmp < x; tmp++) {
         char c = pkt[i + tmp];

         if (((c >= 'A') && (c <= 'Z')) ||
             ((c >= 'a') && (c <= 'z')) ||
             ((c >= '0') && (c <= '9')))
            fprintf(f_output, "%c", c);
         else
            fputs(".", f_output);
      }

      i += x;
      fprintf(f_output, "\n");
   }

   fprintf(f_output, "\n");
   fflush(f_output);
}
