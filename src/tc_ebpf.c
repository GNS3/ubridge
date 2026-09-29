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
 * Raw-syscall loader for the tc_impair eBPF program (spec B.1). No libbpf:
 * two BPF_MAP_CREATEs, patching the two BPF_PSEUDO_MAP_FD loads the
 * generator located in the committed instruction array, one BPF_PROG_LOAD
 * of type SCHED_CLS. Attaching (clsact egress, prio 1, direct-action) is
 * netlink and stays in hypervisor_tc.c.
 *
 * BPF_PROG_LOAD needs CAP_BPF (or CAP_SYS_ADMIN) on kernels >= 5.8 —
 * callers turn EPERM into the spec's exact 210 reply.
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

#include "tc_ebpf.h"
#include "tc_ebpf_insns.h"

/* verifier log for BPF_PROG_LOAD failures (only printed on error) */
static char bpf_log[65536];

/* The freestanding program reads ctx->data / ctx->data_end through a
 * hand-written minimal __sk_buff; prove its offsets match the uapi. */
_Static_assert(offsetof(struct __sk_buff, data) == 76, "min_skb data offset");
_Static_assert(offsetof(struct __sk_buff, data_end) == 80, "min_skb data_end offset");
_Static_assert(sizeof(struct bpf_insn) == 8, "bpf_insn size");

#ifndef __NR_bpf
#define __NR_bpf 321            /* x86_64 */
#endif

static int bpf_call(int cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int bpf_map_create_array(unsigned int value_size)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(unsigned int);
    attr.value_size = value_size;
    attr.max_entries = 1;
    return bpf_call(BPF_MAP_CREATE, &attr);   /* fd or -1/errno */
}

/*
 * Create both maps, seed CNT (counters zero; prng seeded from the
 * monotonic clock and forced non-zero — xorshift64* must never see 0),
 * patch the map fds into a private copy of the instructions and load it.
 */
int tc_ebpf_load(int *prog_fd, int *cfg_fd, int *cnt_fd)
{
    struct bpf_insn insns[TC_IMPAIR_INSNS];
    struct tc_impair_cnt cnt;
    struct timespec ts;
    union bpf_attr attr;
    int cfd, nfd, pfd, ret;

    cfd = bpf_map_create_array(sizeof(struct tc_impair_cfg));
    if (cfd < 0) {
        fprintf(stderr, "tc_ebpf: BPF_MAP_CREATE(cfg) failed: %s\n", strerror(errno));
        return -errno;
    }
    nfd = bpf_map_create_array(sizeof(struct tc_impair_cnt));
    if (nfd < 0) {
        fprintf(stderr, "tc_ebpf: BPF_MAP_CREATE(cnt) failed: %s\n", strerror(errno));
        ret = -errno;
        close(cfd);
        return ret;
    }

    memset(&cnt, 0, sizeof(cnt));
    clock_gettime(CLOCK_MONOTONIC, &ts);
    cnt.prng_state = ((unsigned long long)ts.tv_sec << 20) ^ (unsigned long long)ts.tv_nsec
                     ^ (unsigned long long)getpid();
    cnt.prng_state |= 1;                    /* xorshift state must be non-zero */

    {
        const unsigned int key = 0;
        memset(&attr, 0, sizeof(attr));
        attr.map_fd = nfd;
        attr.key = (unsigned long)&key;
        attr.value = (unsigned long)&cnt;
        if (bpf_call(BPF_MAP_UPDATE_ELEM, &attr) < 0) {
            fprintf(stderr, "tc_ebpf: BPF_MAP_UPDATE_ELEM(cnt seed) failed: %s\n", strerror(errno));
            ret = -errno;
            close(cfd);
            close(nfd);
            return ret;
        }
    }

    memcpy(insns, tc_impair_insns, sizeof(insns));
    insns[TC_IMPAIR_CFG_LD_IDX].src_reg = BPF_PSEUDO_MAP_FD;
    insns[TC_IMPAIR_CFG_LD_IDX].imm = cfd;
    insns[TC_IMPAIR_CNT_LD_IDX].src_reg = BPF_PSEUDO_MAP_FD;
    insns[TC_IMPAIR_CNT_LD_IDX].imm = nfd;

    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    attr.insns = (unsigned long)insns;
    attr.insn_cnt = TC_IMPAIR_INSNS;
    attr.license = (unsigned long)"GPL";
    attr.log_buf = (unsigned long)bpf_log;
    attr.log_size = sizeof(bpf_log);
    attr.log_level = 1;
    bpf_log[0] = '\0';
    pfd = bpf_call(BPF_PROG_LOAD, &attr);
    if (pfd < 0) {
        size_t n = strlen(bpf_log);

        fprintf(stderr, "tc_ebpf: BPF_PROG_LOAD failed: %s\n", strerror(errno));
        if (n > 0)
            fprintf(stderr, "tc_ebpf: verifier log (tail): %s\n",
                    n > 700 ? bpf_log + n - 700 : bpf_log);
        ret = -errno;
        close(cfd);
        close(nfd);
        return ret;
    }

    *prog_fd = pfd;
    *cfg_fd = cfd;
    *cnt_fd = nfd;
    return 0;
}

int tc_ebpf_map_update(int map_fd, const void *value)
{
    const unsigned int key = 0;
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = (unsigned long)&key;
    attr.value = (unsigned long)value;
    if (bpf_call(BPF_MAP_UPDATE_ELEM, &attr) < 0)
        return -errno;
    return 0;
}

int tc_ebpf_cnt_reset(int cnt_fd, int reset_nth, int reset_quota)
{
    struct tc_impair_cnt cnt;
    const unsigned int key = 0;
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = cnt_fd;
    attr.key = (unsigned long)&key;
    attr.value = (unsigned long)&cnt;
    if (bpf_call(BPF_MAP_LOOKUP_ELEM, &attr) < 0)
        return -errno;
    if (reset_nth)
        cnt.nth_state = 0;
    if (reset_quota) {
        cnt.packets = 0;
        cnt.bytes = 0;
    }
    return tc_ebpf_map_update(cnt_fd, &cnt);
}

/*
 * (Re)seed the current-cycle window lengths in CNT with the nominals —
 * called on every window_drop set so a schedule (jittered or not) starts
 * from the configured values, never from stale draws of a previous run.
 */
int tc_ebpf_cnt_set_window(int cnt_fd, unsigned long long outage_ns,
                           unsigned long long period_ns)
{
    struct tc_impair_cnt cnt;
    const unsigned int key = 0;
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = cnt_fd;
    attr.key = (unsigned long)&key;
    attr.value = (unsigned long)&cnt;
    if (bpf_call(BPF_MAP_LOOKUP_ELEM, &attr) < 0)
        return -errno;
    cnt.win_outage_cur_ns = outage_ns;
    cnt.win_period_cur_ns = period_ns;
    return tc_ebpf_map_update(cnt_fd, &cnt);
}

/*
 * Capability probe: load the REAL program (maps + verifier acceptance on
 * this kernel) and throw it away. Result cached; any failure — EPERM for
 * a missing CAP_BPF, EINVAL/EOVERFLOW for a kernel the program does not
 * verify on — means ebpf=0 and the controller stays on the relay path.
 */
int tc_ebpf_supported(void)
{
    static int supported = -1;
    int pfd, cfd, nfd;

    if (supported >= 0)
        return supported;
    supported = 0;
    if (tc_ebpf_load(&pfd, &cfd, &nfd) == 0) {
        close(pfd);
        close(cfd);
        close(nfd);
        supported = 1;
    }
    return supported;
}
