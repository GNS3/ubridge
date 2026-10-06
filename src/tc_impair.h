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
 * Shared ABI between the eBPF impairment program (src/tc_impair.bpf.c,
 * compiled for the BPF target) and the uBridge loader (src/hypervisor_tc.c,
 * compiled natively). Field order and types are the frozen contract
 * (kernel-impairment spec B.1); both compilers lay these structs out
 * identically because the members that need it (and the structs
 * themselves) carry explicit 8-byte alignment.
 *
 * One SCHED_CLS program is loaded per interface and attached once at clsact
 * egress prio 1; all modes are configured through the single CFG map entry,
 * no program reload on parameter changes. Evaluation order is fixed:
 * nth -> quota -> window -> flow; the first rule that decides a drop wins
 * (TC_ACT_SHOT); every non-drop path returns TC_ACT_UNSPEC so the prio
 * chain continues (bpf_drop filters at prio 10..99 still run — TC_ACT_OK
 * would end the chain in direct-action mode).
 */

#ifndef TC_IMPAIR_H
#define TC_IMPAIR_H

/* flow_mask bits (spec B.2): which header fields feed the flow hash */
#define TC_IMPAIR_FLOW_SRC_MAC		0x1	/* Ethernet source MAC */
#define TC_IMPAIR_FLOW_DST_MAC		0x2	/* Ethernet destination MAC */
#define TC_IMPAIR_FLOW_SPORT		0x4	/* L4 source port (TCP/UDP over IPv4) */
#define TC_IMPAIR_FLOW_DPORT		0x8	/* L4 destination port */
#define TC_IMPAIR_FLOW_PROTO		0x10	/* IPv4 protocol byte */

struct tc_impair_cfg {
    unsigned int nth;              /* 0 = off, else drop every Nth packet */
    /* The u64s that follow u32 fields are explicitly 8-byte aligned, and the
     * struct itself pins 8: on a 32-bit host (i386: alignof(unsigned long
     * long) == 4) the natural layout would drift from the BPF target's and
     * the map ABI would silently break.  Offsets are asserted next to the
     * loader (tc_ebpf.c). */
    unsigned long long quota_bytes __attribute__((aligned(8))); /* 0 = off */
    unsigned int quota_pct;        /* random drop % after quota reached */
    unsigned long long win_start_ns __attribute__((aligned(8))); /* phase anchor, (re)set by window_drop */
    unsigned long long win_len_ns; /* outage length; 0 = mode off */
    unsigned long long win_period_ns; /* 0 = single window; else cycle length */
    unsigned long long win_jitter_ns; /* 0 = deterministic; else uniform ± per cycle */
    unsigned int win_pct;          /* random drop % inside the window */
    unsigned int flow_mask;        /* TC_IMPAIR_FLOW_* bitmask */
    unsigned int flow_target;      /* required hash remainder, 0 = off */
    /* Lazy-reset handshake — see the CNT comment below.  Userspace bumps
     * reset_seq and sets reset_mask atomically with every command's single
     * cfg write; the program applies the requested reset on the next
     * packet. */
    unsigned int reset_seq;        /* ++ on every state-resetting command */
    unsigned int reset_mask;       /* TC_IMPAIR_RESET_* */
} __attribute__((aligned(8)));

/* reset_mask bits */
#define TC_IMPAIR_RESET_NTH    0x1
#define TC_IMPAIR_RESET_QUOTA  0x2
#define TC_IMPAIR_RESET_WINDOW 0x4

/*
 * CNT: counters + runtime state, written by the PROGRAM after the load-time
 * seed — userspace never touches it again (its old read-modify-write
 * replayed a stale snapshot over counters the program was advancing).  The
 * first three fields are the frozen counters (spec B.1).
 *
 * - win_outage_cur_ns / win_period_cur_ns hold the current cycle's drawn
 *   lengths (equal to the nominals while jitter is 0).
 * - win_start_cur_ns is the advancing cycle start: runtime state, so a cfg
 *   rewrite by an unrelated mode command cannot rewind an active window's
 *   phase; window_drop (re)sets it via TC_IMPAIR_RESET_WINDOW.
 * - prng_seed is the userspace draw key; draw_seq hands out one atomic
 *   ticket per draw (splitmix64 of seed and ticket) — two CPUs can never
 *   share a draw, and a fixed sequence of draw points replays exactly.
 * - seen_seq is the last cfg reset_seq the program applied.
 */
struct tc_impair_cnt {
    unsigned long long packets;    /* quota machinery (packets past nth) */
    unsigned long long bytes;      /* quota machinery */
    unsigned long long nth_state;  /* packets seen since nth (re)armed */
    unsigned long long win_outage_cur_ns; /* current cycle's outage length */
    unsigned long long win_period_cur_ns; /* current cycle's period length */
    unsigned long long win_start_cur_ns;  /* current cycle's start (advanced by the program) */
    unsigned long long prng_seed;  /* draw key, userspace-seeded */
    unsigned long long draw_seq;   /* atomic draw-ticket counter */
    unsigned int seen_seq;         /* last cfg reset_seq applied */
} __attribute__((aligned(8)));

#endif /* TC_IMPAIR_H */
