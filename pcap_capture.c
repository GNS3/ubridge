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
#include "pcap_capture.h"

void free_pcap_capture(pcap_capture_t *capture)
{
   if (capture != NULL) {

      if (capture->dumper)
         pcap_dump_close(capture->dumper);

      if (capture->fd)
         pcap_close(capture->fd);

      pthread_mutex_destroy(&capture->lock);
      free(capture);
   }
}

/* Create a new PCAP capture */
pcap_capture_t *create_pcap_capture(const char *filename, const char *pcap_linktype)
{
   int link_type;
   pcap_capture_t *capture;

   if (!(capture = malloc(sizeof(*capture)))) {
      fprintf(stderr,"not enough memory to setup pcap capture\n");
      return (NULL);
   }

   if (pthread_mutex_init(&capture->lock, NULL)) {
      fprintf(stderr,"pthread_mutex_init failure (file %s)\n", filename);
      return (NULL);
   }

   if (!pcap_linktype || (link_type = pcap_datalink_name_to_val(pcap_linktype)) == -1) {
      fprintf(stderr,"unknown link type %s, assuming Ethernet.\n", pcap_linktype);
      link_type = DLT_EN10MB;
   }

   /* Open a dead pcap descriptor */
   if (!(capture->fd = pcap_open_dead(link_type, 65535))) {
      fprintf(stderr, "pcap_open_dead failure\n");
      goto pcap_open_err;
   }

   /* Open the output file */
   if (!(capture->dumper = pcap_dump_open(capture->fd, filename))) {
      fprintf(stderr,"pcap_dump_open failure (file %s)\n", filename);
      goto pcap_dump_err;
   }

   printf("Capturing to file '%s'\n", filename);
   return (capture);

   pcap_dump_err:
      pcap_close(capture->fd);
   pcap_open_err:
      pthread_mutex_destroy(&capture->lock);
   return (NULL);
}

/* Packet handler: write packets to a file in CAP format */
void pcap_capture_packet(pcap_capture_t *capture, void *pkt, size_t len)
{
   struct pcap_pkthdr pkt_hdr;

   if (capture != NULL) {
      gettimeofday(&pkt_hdr.ts,0);
      pkt_hdr.caplen = m_min(len, (u_int)pcap_snapshot(capture->fd));
      pkt_hdr.len = len;

      /* thread safe dump */
      pthread_mutex_lock(&capture->lock);
      pcap_dump((u_char *)capture->dumper, &pkt_hdr, pkt);
      pcap_dump_flush(capture->dumper);
      pthread_mutex_unlock(&capture->lock);
   }
}
