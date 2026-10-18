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

#ifndef PCAP_CAPTURE_H_
#define PCAP_CAPTURE_H_

#include <sys/time.h>

#include "nio.h"

pcap_capture_t *create_pcap_capture(const char *filename, const char *pcap_linktype);
void free_pcap_capture(pcap_capture_t *pcap_capture);

/* Write a packet stamped with the given receive time. `ts` is the packet's
 * actual receive timestamp when the caller has one (e.g. the kernel stamp
 * pulled off the socket); NULL stamps "now", at write time. */
void pcap_capture_packet_ts(pcap_capture_t *capture, void *pkt, size_t len,
                            const struct timeval *ts);
void pcap_capture_packet(pcap_capture_t *capture, void *pkt, size_t len);

#endif /* !PCAP_CAPTURE_H_ */
