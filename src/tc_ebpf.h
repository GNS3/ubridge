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

/*
 * eBPF impairment loader (kernel-impairment spec B): raw-syscall BPF
 * plumbing for the tc_impair program. Lives in its own translation unit
 * because <linux/bpf.h> and libpcap both define struct bpf_insn; callers
 * (hypervisor_tc.c) only handle fds and netlink, never bpf.h types.
 *
 * All functions return 0 on success or a negative errno. EPERM (the BPF
 * capability gate) and EACCES (the verifier refusing a program this
 * process may not run — kernel !root restrictions) both mean "stateful
 * filters unavailable": callers report the spec's exact 210 string.
 */

#ifndef TC_EBPF_H
#define TC_EBPF_H

#include "tc_impair.h"

/* Cached capability probe: load (and discard) the real program. 1/0. */
int tc_ebpf_supported(void);

/*
 * Create the CFG/CNT ARRAY maps (CNT seeded: counters zero, draw key from
 * the monotonic clock), patch the two map-fd loads in the embedded
 * instruction array and BPF_PROG_LOAD it as SCHED_CLS. Fills the three fd
 * out-params. 0 or -errno.
 */
int tc_ebpf_load(int *prog_fd, int *cfg_fd, int *cnt_fd);

/* BPF_MAP_UPDATE_ELEM of *value at key 0. 0 or -errno.  The single map
 * write a mode command performs: the cfg carries the reset_seq/reset_mask
 * handshake, and the program applies the counter resets itself (userspace
 * never writes CNT after the load-time seed). */
int tc_ebpf_map_update(int map_fd, const void *value);

#endif /* TC_EBPF_H */
