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
#include "pcap_filter.h"

int set_pcap_filter(nio_ethernet_t *nio_ethernet, const char *filter)
{
     struct bpf_program fp;

	 if (pcap_compile(nio_ethernet->pcap_dev, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
	    fprintf(stderr, "Cannot compile filter '%s': %s\n", filter, pcap_geterr(nio_ethernet->pcap_dev));
		return (-1);
	 }

	 if (pcap_setfilter(nio_ethernet->pcap_dev, &fp) < 0) {
		fprintf(stderr, "Cannot install filter '%s': %s\n", filter, pcap_geterr(nio_ethernet->pcap_dev));
		return (-1);
	 }

	 pcap_freecode(&fp);
	 return (0);
}
