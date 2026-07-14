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
 *
 * marker — push packet-filter match signals to a UDP sink (the controller).
 *
 * When a `mark` packet filter (see packet_filter.c) matches a packet, it calls
 * marker_emit(), which formats a one-line signal and sends a single UDP
 * datagram to a configured sink (typically gns3server) — fire-and-forget, no
 * listener, no thread. The sink address is set via the `marker sink` command
 * or the UBRIDGE_MARKER_SINK env var at startup.
 */

#ifndef MARKER_H_
#define MARKER_H_

#include <stddef.h>

/* Emit a marker signal for a matched filter. No-op when no sink is configured.
 * Safe to call from the bridge relay (listener) threads.
 * `tag` and `link` are opaque ids echoed verbatim (NULL → "-" in the signal):
 * `tag` for caller-side correlation, `link` for topology link attribution. */
void marker_emit(const char *filter_name, const char *tag, const char *link, size_t len);

/* Configure / clear the UDP sink (consumer = gns3server). 0 or -errno. */
int  marker_set_sink(const char *host, int port);
int  marker_clear_sink(void);
void marker_set_node(const char *node_id);

typedef struct {
    int  enabled;            /* sink configured? */
    char sink[72];           /* "host:port" for display, "" if unset */
    char node[64];           /* node id echoed in signals, "" if unset */
    unsigned long emitted;   /* signals sent since start */
} marker_status_t;
int  marker_status(marker_status_t *out);

/* Hypervisor module registration (commands: sink/node/off/status). */
int  hypervisor_marker_init(void);

#endif /* !MARKER_H_ */
