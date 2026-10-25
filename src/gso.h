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

#ifndef GSO_H_
#define GSO_H_

#include <stddef.h>
#include <sys/types.h>

/*
 * Software TCP segmentation for frames read off an AF_PACKET socket.
 *
 * A packet socket sees frames as the kernel holds them, not as they were on
 * the wire. GRO (or a NIC's LRO, such as hv_netvsc RSC) has merged
 * consecutive TCP segments into one frame of up to 64 KB, and the host's own
 * outgoing frames have not been split by TSO yet. GRO and TSO frames also
 * carry only the pseudo-header part of their TCP checksum. When the kernel
 * forwards such a frame it cuts it back into wire-sized segments (GSO on the
 * egress device). A relay that hands it to a node has to do the same, or the
 * node drops every frame that is longer than its MTU.
 */

typedef struct {
   const unsigned char *frame;  /* merged frame, owned by the caller */
   size_t l3_off;               /* IP header */
   size_t l4_off;               /* TCP header */
   size_t hdr_len;              /* headers repeated in front of every segment */
   size_t end;                  /* end of the TCP payload, from the IP length */
   size_t mss;                  /* payload bytes per segment */
   size_t pos;                  /* offset of the next segment's payload */
   int ipv6;
} gso_tcp_t;

/* Prepare to segment a TCP/IPv4 or TCP/IPv6 Ethernet frame (up to two
 * 802.1Q/802.1ad tags). gso_size is the segment size the kernel reported for
 * a GRO or TSO frame, or 0. mtu is the L3 MTU of the device that the frame
 * came from, or 0 if unknown. Segments are cut to gso_size. A frame that
 * exceeds the MTU without a gso_size (LRO) is cut to the MTU. No segment
 * exceeds the MTU.
 * Returns 1 if the frame must be segmented, or 0 to forward it as is. */
int gso_tcp_init(gso_tcp_t *gso, const unsigned char *frame, size_t len, size_t gso_size, size_t mtu);

/* Write the next segment into seg. Its IP length, IPv4 ID and header
 * checksum, TCP sequence number, flags and checksum are fixed up.
 * Returns its length, 0 when there are no segments left, or -1 if seg is too
 * small. */
ssize_t gso_tcp_next(gso_tcp_t *gso, unsigned char *seg, size_t max_len);

/* Complete a partial (CHECKSUM_PARTIAL) checksum. The 16-bit field at
 * csum_start + csum_offset holds the pseudo-header sum, and the checksum
 * covers csum_start to the end of the frame.
 * Returns 0, or -1 if the field is out of bounds. */
int gso_csum_complete(unsigned char *frame, size_t len, size_t csum_start, size_t csum_offset);

#endif /* !GSO_H_ */
