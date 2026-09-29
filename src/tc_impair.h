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
 * (kernel-impairment spec B.1); both compilers lay out these structs
 * identically (same natural-alignment rules for these scalar types).
 *
 * One SCHED_CLS program is loaded per interface and attached once at clsact
 * egress prio 1; all modes are configured through the single CFG map entry,
 * no program reload on parameter changes. Evaluation order is fixed:
 * nth -> quota -> window -> flow; the first rule that decides a drop wins
 * (TC_ACT_SHOT), otherwise TC_ACT_OK.
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
    unsigned long long quota_bytes;/* 0 = off */
    unsigned int quota_pct;        /* random drop % after quota reached */
    unsigned long long win_start_ns; /* current window's start (monotonic) */
    unsigned long long win_len_ns; /* outage length; 0 = mode off */
    unsigned long long win_period_ns; /* 0 = single window; else cycle length */
    unsigned long long win_jitter_ns; /* 0 = deterministic; else uniform ± per cycle */
    unsigned int win_pct;          /* random drop % inside the window */
    unsigned int flow_mask;        /* TC_IMPAIR_FLOW_* bitmask */
    unsigned int flow_target;      /* required hash remainder, 0 = off */
};

/*
 * CNT: the first three fields are the frozen counters (spec B.1). The two
 * win_*_cur_ns fields hold the current cycle's drawn window lengths (equal
 * to the nominals while jitter is 0); userspace re-seeds them on every
 * window_drop set. prng_state carries the "prandom seeded via map"
 * requirement: userspace seeds it (| 1 — the generator must never see zero)
 * and the program advances it atomically, so percentage drops are
 * reproducible for a given seed.
 */
struct tc_impair_cnt {
    unsigned long long packets;    /* quota machinery (packets past nth) */
    unsigned long long bytes;      /* quota machinery */
    unsigned long long nth_state;  /* packets seen since nth (re)armed */
    unsigned long long win_outage_cur_ns; /* current cycle's outage length */
    unsigned long long win_period_cur_ns; /* current cycle's period length */
    unsigned long long prng_state; /* xorshift64* state, userspace-seeded */
};

#endif /* TC_IMPAIR_H */
