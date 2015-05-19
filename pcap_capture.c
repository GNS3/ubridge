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


void free_pcap_capture(nio_t *nio)
{
   if (nio->pcap_capture_fd != NULL) {
      printf("NIO %s: ending packet capture.\n",nio->name);

      /* Close dumper */
      if (nio->dumper)
         pcap_dump_close(nio->dumper);

      /* Close PCAP descriptor */
      if (nio->pcap_capture_fd)
         pcap_close(nio->pcap_capture_fd);

      //pthread_mutex_destroy(&c->lock);
   }
}

/* Setup filter resources */
int setup_pcap_capture(nio_t *nio, const char *filename, const char *pcap_linktype)
{
    int link_type;
   /* Free resources if something has already been done */
   //pf_capture_free(nio,opt);

//   if (pthread_mutex_init(&c->lock,NULL)) {
//      fprintf(stderr,"NIO %s: pthread_mutex_init failure (file %s)\n",
//              nio->name,argv[0]);
//      goto pcap_lock_err;
//   }
//
//   if ((link_type = pcap_datalink_name_to_val(pcap_linktype)) == -1) {
//      fprintf(stderr,"unknown link type %s, assuming Ethernet.\n", pcap_linktype);
//      link_type = DLT_EN10MB;
//   }

   link_type = DLT_EN10MB;

   /* Open a dead pcap descriptor */
   if (!(nio->pcap_capture_fd = pcap_open_dead(link_type, 65535))) {
      fprintf(stderr, "pcap_open_dead failure\n");
      goto pcap_open_err;
   }

   /* Open the output file */
   if (!(nio->dumper = pcap_dump_open(nio->pcap_capture_fd, filename))) {
      fprintf(stderr,"pcap_dump_open failure (file %s)\n", filename);
      goto pcap_dump_err;
   }

   printf("capturing to file '%s'\n", filename);
   return(0);

 pcap_dump_err:
   pcap_close(nio->pcap_capture_fd);
 pcap_open_err:
   //pthread_mutex_destroy(&c->lock);
 pcap_lock_err:
   //free(c);
   return(-1);
}

/* Packet handler: write packets to a file in CAP format */
int pcap_capture_packet(nio_t *nio, void *pkt, size_t len)
{
   struct pcap_pkthdr pkt_hdr;

   if (nio->pcap_capture_fd != NULL) {
      gettimeofday(&pkt_hdr.ts,0);
      pkt_hdr.caplen = m_min(len, (u_int)pcap_snapshot(nio->pcap_capture_fd));
      pkt_hdr.len = len;

      /* thread safe dump */
      //pthread_mutex_lock(&c->lock);
      pcap_dump((u_char *)nio->dumper, &pkt_hdr, pkt);
      pcap_dump_flush(nio->dumper);
      //pthread_mutex_unlock(&c->lock);
   }
    return 1;
   //return(NETIO_FILTER_ACTION_PASS);
}
