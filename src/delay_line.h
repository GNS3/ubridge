/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2017 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   ubridge is distributed in the hope that it will be useful, but
 *   WITHOUT ANY EVEN THE IMPLIED WARRANTY OF MERCHANTABILITY or
 *   FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DELAY_LINE_H_
#define DELAY_LINE_H_

#include <sys/types.h>
#include <stddef.h>
#include <time.h>

/*
 * A bounded-latency delay line.
 *
 * Each enqueued packet is held for (base_latency_ms +/- jitter_ms) and then
 * handed to send_fn. Enqueueing never blocks the caller: a dedicated release
 * thread owns the wait + send, so the receive loop that feeds the delay line
 * stays drained and per-packet latency stays bounded regardless of offered
 * load (see GNS3/ubridge#114 — the old delay filter slept inline in the
 * bridge thread, serializing each direction to ~1000/latency pps).
 *
 * The queue is also depth-bounded (default 1000 packets, matching the kernel
 * netem limit): once full, new packets are tail-dropped so memory stays
 * bounded and excess load is shed rather than buffered. Every delivered packet
 * transits this queue, so delivery is capped at the limit under overload.
 *
 * One delay_line belongs to one direction of one bridge (it is created and
 * destroyed inside a single bridge_nios() call), so it is single-producer
 * (the recv thread) / single-consumer (the release thread).
 */

typedef struct delay_line delay_line_t;

/* Invoked by the release thread when a packet becomes due. ctx is the opaque
 * pointer passed to delay_line_create() (the transmitting NIO). Returns
 * whatever the underlying send returns. */
typedef ssize_t (*delay_send_fn)(void *ctx, const void *pkt, size_t len);

/* Create a delay line and start its release thread. Returns NULL on failure. */
delay_line_t *delay_line_create(int base_latency_ms, int jitter_ms,
                                delay_send_fn send_fn, void *send_ctx);

/* Enqueue one packet for delayed release. The packet is copied, so the caller
 * may reuse/free it immediately. Returns 0 on success, -1 on allocation
 * failure (the caller should treat the packet as dropped). */
int delay_line_enqueue(delay_line_t *dl, const void *pkt, size_t len);

/* Stop the release thread, join it, and free the delay line and any packets
 * still queued (they are dropped, not sent). Cancel-safe: may run from a
 * pthread cleanup handler. */
void delay_line_destroy(delay_line_t *dl);

#endif /* !DELAY_LINE_H_ */
