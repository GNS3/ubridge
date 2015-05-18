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
#include "nio_ethernet.h"

#define m_min(a,b) (((a) < (b)) ? (a) : (b))

#ifdef CYGWIN
/* Needed for pcap_open() flags */
#define HAVE_REMOTE
#endif

/* Initialize a generic ethernet driver */
static pcap_t *nio_ethernet_open(char *device)
{
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *p;

#ifndef CYGWIN
   if (!(p = pcap_open_live(device, 65535, TRUE, 10, pcap_errbuf)))
      goto pcap_error;

   pcap_setdirection(p, PCAP_D_INOUT);
#ifdef BIOCFEEDBACK
   {
     int on = 1;
     ioctl(pcap_fileno(p), BIOCFEEDBACK, &on);
   }
#endif
#else
   p = pcap_open(device, 65535,
       PCAP_OPENFLAG_PROMISCUOUS |
       PCAP_OPENFLAG_NOCAPTURE_LOCAL |
	   PCAP_OPENFLAG_MAX_RESPONSIVENESS |
	   PCAP_OPENFLAG_NOCAPTURE_RPCAP,
	   10, NULL, pcap_errbuf);

   if (!p)
      goto pcap_error;
#endif

   return p;

 pcap_error:
   fprintf(stderr, "nio_ethernet_open: unable to open device '%s' ""with PCAP (%s)\n", device, pcap_errbuf);
   return NULL;
}

/* Free a NIO Ethernet descriptor */
static void nio_ethernet_free(nio_ethernet_t *nio_ethernet)
{
   pcap_close(nio_ethernet->pcap_dev);
}

/* Send a packet to an Ethernet device */
static ssize_t nio_ethernet_send(nio_ethernet_t *nio_ethernet, void *pkt, size_t pkt_len)
{
   return (pcap_sendpacket(nio_ethernet->pcap_dev, (u_char *)pkt, pkt_len));
}

/* Receive a packet from an Ethernet device */
static ssize_t nio_ethernet_recv(nio_ethernet_t *nio_ethernet, void *pkt, size_t max_len)
{
   struct pcap_pkthdr pkt_info;
   u_char *pkt_ptr;
   ssize_t rlen;

   if (!(pkt_ptr = (u_char *)pcap_next(nio_ethernet->pcap_dev, &pkt_info)))
      return (-1);

   rlen = m_min(max_len, pkt_info.caplen);
   memcpy(pkt, pkt_ptr, rlen);
   return (rlen);
}

/* Create a new NIO descriptor with the Ethernet method */
nio_t *create_nio_ethernet(char *dev_name)
{
   nio_ethernet_t *nio_ethernet;
   nio_t *nio;

   if (!(nio = create_nio()))
      return NULL;

   nio_ethernet = &nio->u.nio_ethernet;

   if (!(nio_ethernet->pcap_dev = nio_ethernet_open(dev_name))) {
      free_nio(nio);
      return NULL;
   }

   nio->type = NIO_TYPE_ETHERNET;
   nio->send = (void *)nio_ethernet_send;
   nio->recv = (void *)nio_ethernet_recv;
   nio->free = (void *)nio_ethernet_free;
   nio->dptr = &nio->u.nio_ethernet;
   return nio;
}
