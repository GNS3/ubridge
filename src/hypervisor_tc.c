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
 * tc — kernel traffic-control (netem) impairment via netlink.
 *
 * Attaches/replaces a netem qdisc at the root of an interface, and removes
 * it. This provides the kernel-side link impairment (delay/jitter/loss/dup/
 * corrupt, plus rate/reorder/gemodel/distribution/seed/limit extensions)
 * that the kernel data plane needs: once frames flow TAP -> kernel bridge ->
 * TAP (not through ubridge's user-space NIO relay), the bridge module's
 * user-space packet filters no longer see the traffic, so the impairment
 * has to live in the kernel qdisc.
 *
 * netem ABI (mirrors what the iproute2 `tc` CLI puts on the wire, verified
 * against net/sched/sch_netem.c netem_change()): TCA_OPTIONS is a nested
 * attribute whose payload begins with a raw struct tc_netem_qopt (mandatory;
 * carries limit, loss, gap and duplicate), followed by nested TCA_NETEM_*
 * attributes, emitted in the iproute2 order: LATENCY64, JITTER64, CORR,
 * REORDER, CORRUPT, LOSS (gemodel nest), RATE64+RATE, PRNG_SEED,
 * DELAY_DIST. delay/jitter are s64 nanoseconds; rates are BYTES per second
 * on the wire (tc's internal unit: "10mbit" => 1250000); the gemodel third
 * parameter is 1-h and is stored complemented (h = ~pct); reorder needs a
 * delay and defaults gap to 1, like the tc CLI.
 *
 * bpf_drop (the GNS3 "bpf" filter, kernel-side): a pcap-compiled classic
 * BPF program attached as a cls_bpf filter on the clsact qdisc's egress
 * side, with a gact TC_ACT_SHOT action — match means drop, non-match falls
 * through. Wire ABI (verified against net/sched/cls_bpf.c cls_bpf_change()
 * and iproute2 tc/f_bpf.c): clsact is created at parent TC_H_CLSACT with
 * handle TC_H_MAKE(TC_H_CLSACT, 0); filters sit at parent
 * TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS) with tcm_info = (prio << 16) |
 * htons(ETH_P_ALL), and carry TCA_OPTIONS { TCA_BPF_ACT (nested gact with
 * action TC_ACT_SHOT), TCA_BPF_OPS_LEN (u16), TCA_BPF_OPS (sock_filter
 * array) }. The kernel migrates classic bytecode to eBPF internally
 * (bpf_prog_create) — no CAP_BPF needed, only the netlink CAP_NET_ADMIN
 * this module already requires. Egress cls_bpf filters see the full
 * Ethernet frame (the ingress side would need a mac_len push), which is
 * exactly what a DLT_EN10MB pcap program expects.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/tc_act/tc_gact.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <pcap.h>

#include "netlink/nl.h"
#include "hypervisor.h"
#include "hypervisor_tc.h"
#include "tc_netem_dist.h"
#include "tc_impair.h"
#include "tc_ebpf.h"

/* Default netem fifo limit (packets). */
#define NETEM_LIMIT_DEFAULT 1000

/* Highest accepted rate: 100gbit (in bits/s). */
#define NETEM_RATE_MAX_BPS 100000000000ULL

/* bpf_drop filter priorities the controller may use (spec part C/D: egress
 * classifiers run by ascending prio, eBPF impairment owns prio 1). */
#define BPF_DROP_PRIO_MIN 10
#define BPF_DROP_PRIO_MAX 99

/* One "tc netem set" command, as gathered by the parser. */
struct netem_params {
    int has_delay;
    double delay_ms;
    int has_jitter;
    double jitter_ms;
    int has_loss;                 /* plain random loss */
    unsigned int loss_pct;
    int has_loss_correl;
    unsigned int loss_correl_pct;
    int has_dup;
    unsigned int dup_pct;
    int has_dup_correl;
    unsigned int dup_correl_pct;
    int has_corrupt;
    unsigned int corrupt_pct;
    int has_reorder;
    unsigned int reorder_pct;
    int has_reorder_correl;
    unsigned int reorder_correl_pct;
    int has_gap;                  /* reorder suffix; defaults to 1 */
    unsigned int gap;
    int has_gemodel;              /* mutually exclusive with plain loss */
    unsigned int gem_p, gem_r, gem_one_minus_h;
    int has_rate;
    unsigned long long rate_bytes;   /* bytes/s, tc wire unit */
    int dist;                     /* -1 = none/uniform, else table index */
    int has_seed;
    unsigned long long seed;
    int has_limit;
    unsigned int limit;
};

/* --------------------------------------------------------------------------
 * bpf_drop filter registry — the prios we installed, per interface.
 *
 * Kernel state is the source of truth; this list only remembers WHICH prios
 * of an interface belong to us, so `bpf_drop flush` and `tc reset` remove
 * exactly our filters and never a foreign classifier. Only touched from
 * command handlers, which the dispatcher serialises under global_lock.
 * --------------------------------------------------------------------------
 */

struct bpf_drop_prio {
    struct bpf_drop_prio *next;
    unsigned int ifindex;
    unsigned int prio;
};

static struct bpf_drop_prio *bpf_drop_prios;

static void bpf_drop_track(unsigned int ifindex, unsigned int prio)
{
    struct bpf_drop_prio *e;

    for (e = bpf_drop_prios; e != NULL; e = e->next)
        if (e->ifindex == ifindex && e->prio == prio)
            return;

    e = malloc(sizeof(*e));
    if (e != NULL) {
        e->ifindex = ifindex;
        e->prio = prio;
        e->next = bpf_drop_prios;
        bpf_drop_prios = e;
    }
}

/* --------------------------------------------------------------------------
 * netlink helpers — return 0 on success or a negative errno.
 * -------------------------------------------------------------------------- */

/*
 * Convert a percentage (0..100) to netem's u32 probability encoding
 * (p * 2^32). 0 => none, ~0 => all; see netem loss_event()/netem_enqueue().
 */
static unsigned int netem_percent(unsigned int percent)
{
    if (percent == 0)
        return 0;
    if (percent >= 100)
        return 0xFFFFFFFFu;
    return (unsigned int)(((unsigned long long)percent << 32) / 100);
}

/*
 * Parse a rate value: integer + unit, decimal multiples. bit family is
 * bits/s (bit, kbit, mbit, gbit); bps family is bytes/s (bps, kbps, mbps).
 * Returns bits/s, or -1 on a malformed value / value above 100gbit.
 */
static int parse_rate_bps(const char *val, unsigned long long *bits_out)
{
    static const struct { const char *suffix; unsigned long long scale; } units[] = {
        { "bit",  1ULL },
        { "kbit", 1000ULL },
        { "mbit", 1000000ULL },
        { "gbit", 1000000000ULL },
        { "bps",  8ULL },          /* bytes/s */
        { "kbps", 8000ULL },
        { "mbps", 8000000ULL },
    };
    unsigned long long v;
    char *end;
    size_t i;

    if (!isdigit((unsigned char)val[0]))
        return -1;
    v = strtoull(val, &end, 10);
    if (end == val || *end == '\0')
        return -1;                 /* bare number: unit required */
    for (i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
        if (strcasecmp(end, units[i].suffix) == 0) {
            if (v > NETEM_RATE_MAX_BPS / units[i].scale)
                return -1;
            v *= units[i].scale;
            if (v > NETEM_RATE_MAX_BPS)
                return -1;
            *bits_out = v;
            return 0;
        }
    }
    return -1;
}

/* Attach/replace a netem qdisc at the root of <ifname>. Returns 0 or -errno. */
static int tc_netem_replace(const char *ifname, const struct netem_params *p)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct tcmsg *tcm;
    struct rtattr *opts;
    struct tc_netem_qopt qopt;
    long long v64;
    int ifindex, ret;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
        return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0)
        return ret;

    /* big enough for an 8 KiB distribution table on top of the options */
    msg = nlmsg_alloc(16384);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        ret = -ENOMEM;
        goto out;
    }

    tcm = (struct tcmsg *)nlmsg_data(msg);
    memset(tcm, 0, sizeof(*tcm));
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = ifindex;
    tcm->tcm_parent = TC_H_ROOT;   /* root qdisc */

    msg->nlmsghdr.nlmsg_type = RTM_NEWQDISC;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    nla_put_string(msg, TCA_KIND, "netem");

    /* TCA_OPTIONS = raw struct tc_netem_qopt (mandatory prefix) + nested attrs */
    opts = nla_begin_nested(msg, TCA_OPTIONS);
    opts->rta_type |= NLA_F_NESTED;

    /* qopt carries limit/loss/gap/duplicate; latency/jitter stay 0,
     * overridden unambiguously (ns) by LATENCY64/JITTER64 below. */
    memset(&qopt, 0, sizeof(qopt));
    qopt.limit = p->has_limit ? p->limit : NETEM_LIMIT_DEFAULT;
    qopt.loss = p->has_loss ? netem_percent(p->loss_pct) : 0;
    qopt.gap = p->has_reorder ? (p->has_gap ? p->gap : 1) : 0;
    qopt.duplicate = p->has_dup ? netem_percent(p->dup_pct) : 0;
    memcpy(NLMSG_TAIL(&msg->nlmsghdr), &qopt, sizeof(qopt));
    msg->nlmsghdr.nlmsg_len += sizeof(qopt);

    if (p->has_delay) {
        v64 = (long long)(p->delay_ms * 1000000.0);   /* ms -> ns */
        nla_put_buffer(msg, TCA_NETEM_LATENCY64, &v64, sizeof(v64));
    }
    if (p->has_jitter) {
        v64 = (long long)(p->jitter_ms * 1000000.0);  /* ms -> ns */
        nla_put_buffer(msg, TCA_NETEM_JITTER64, &v64, sizeof(v64));
    }
    if (p->has_loss_correl || p->has_dup_correl || p->has_reorder_correl) {
        /* reorder correlation rides in TCA_NETEM_REORDER, but the tc CLI
         * still emits the (zeroed) CORR attr in that case — mirror it.
         * Unlike the tc CLI, dup correl alone is not silently dropped. */
        struct tc_netem_corr corr;
        memset(&corr, 0, sizeof(corr));
        corr.delay_corr = 0;
        corr.loss_corr = p->has_loss_correl ? netem_percent(p->loss_correl_pct) : 0;
        corr.dup_corr = p->has_dup_correl ? netem_percent(p->dup_correl_pct) : 0;
        nla_put_buffer(msg, TCA_NETEM_CORR, &corr, sizeof(corr));
    }
    if (p->has_reorder) {
        struct tc_netem_reorder reorder;
        memset(&reorder, 0, sizeof(reorder));
        reorder.probability = netem_percent(p->reorder_pct);
        reorder.correlation = p->has_reorder_correl ? netem_percent(p->reorder_correl_pct) : 0;
        nla_put_buffer(msg, TCA_NETEM_REORDER, &reorder, sizeof(reorder));
    }
    if (p->has_corrupt) {
        /* TCA_NETEM_CORRUPT: fixed-size struct {probability, correlation},
         * probability encoded like loss/dup (p * 2^32); correlation 0. */
        struct tc_netem_corrupt c;
        memset(&c, 0, sizeof(c));
        c.probability = netem_percent(p->corrupt_pct);
        nla_put_buffer(msg, TCA_NETEM_CORRUPT, &c, sizeof(c));
    }
    if (p->has_gemodel) {
        /* TCA_NETEM_LOSS nest, kind NETEM_LOSS_GE. The third parameter is
         * 1-h on the wire syntax; the kernel wants h, stored complemented
         * (like iproute2: gemodel.h = ~percent). k1 stays 0. */
        struct rtattr *loss;
        struct tc_netem_gemodel gem;
        memset(&gem, 0, sizeof(gem));
        gem.p = netem_percent(p->gem_p);
        gem.r = netem_percent(p->gem_r);
        gem.h = 0xFFFFFFFFu - netem_percent(p->gem_one_minus_h);
        loss = nla_begin_nested(msg, TCA_NETEM_LOSS);
        loss->rta_type |= NLA_F_NESTED;
        nla_put_buffer(msg, NETEM_LOSS_GE, &gem, sizeof(gem));
        nla_end_nested(msg, loss);
    }
    if (p->has_rate) {
        struct tc_netem_rate rate;
        memset(&rate, 0, sizeof(rate));
        if (p->rate_bytes >= (1ULL << 32)) {
            /* too big for the legacy u32 field: exact u64 attr, legacy
             * field saturated (kernel takes the max of the two) */
            unsigned long long r64 = p->rate_bytes;
            nla_put_buffer(msg, TCA_NETEM_RATE64, &r64, sizeof(r64));
            rate.rate = ~0U;
        } else {
            rate.rate = (unsigned int)p->rate_bytes;
        }
        nla_put_buffer(msg, TCA_NETEM_RATE, &rate, sizeof(rate));
    }
    if (p->has_seed) {
        unsigned long long seed = p->seed;
        nla_put_buffer(msg, TCA_NETEM_PRNG_SEED, &seed, sizeof(seed));
    }
    if (p->dist >= 0) {
        /* distribution table, verbatim (uniform = no table at all) */
        const short *tbl;
        switch (p->dist) {
            case 0:  tbl = netem_dist_normal; break;
            case 1:  tbl = netem_dist_pareto; break;
            default: tbl = netem_dist_paretonormal; break;
        }
        nla_put_buffer(msg, TCA_NETEM_DELAY_DIST, tbl, NETEM_DIST_SIZE * sizeof(short));
    }
    nla_end_nested(msg, opts);

    ret = netlink_transaction(&nlh, msg, reply);

out:
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/* --------------------------------------------------------------------------
 * clsact / classifier-filter netlink ops (bpf_drop). All take an open
 * netlink handler and return 0 or a negative errno.
 * --------------------------------------------------------------------------
 */

/*
 * Create the clsact qdisc on <ifindex>. It coexists with the root netem
 * qdisc — clsact never replaces the root. EEXIST (already attached) is
 * success for the caller's "ensure" intent.
 */
static int tc_clsact_create(struct nl_handler *nlh, int ifindex)
{
    struct nlmsg *msg, *reply;
    struct tcmsg *tcm;
    int ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        return -ENOMEM;
    }

    tcm = (struct tcmsg *)nlmsg_data(msg);
    memset(tcm, 0, sizeof(*tcm));
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = ifindex;
    tcm->tcm_parent = TC_H_CLSACT;
    tcm->tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);

    msg->nlmsghdr.nlmsg_type = RTM_NEWQDISC;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    nla_put_string(msg, TCA_KIND, "clsact");

    ret = netlink_transaction(nlh, msg, reply);
    if (ret == -EEXIST)
        ret = 0;
    nlmsg_free(msg);
    nlmsg_free(reply);
    return ret;
}

/*
 * Delete the clsact qdisc of <ifindex>. Requesting handle 0 (rather than
 * TC_H_MAKE(TC_H_CLSACT, 0)) makes an absent clsact uniformly ENOENT: the
 * kernel finds the ingress queue's noop qdisc and refuses to delete
 * handle 0, instead of comparing against a handle and returning EINVAL
 * (what `tc qdisc del ... clsact` twice prints as "Invalid handle").
 */
static int tc_clsact_delete(struct nl_handler *nlh, int ifindex)
{
    struct nlmsg *msg, *reply;
    struct tcmsg *tcm;
    int ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        return -ENOMEM;
    }

    tcm = (struct tcmsg *)nlmsg_data(msg);
    memset(tcm, 0, sizeof(*tcm));
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = ifindex;
    tcm->tcm_parent = TC_H_CLSACT;

    msg->nlmsghdr.nlmsg_type = RTM_DELQDISC;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    ret = netlink_transaction(nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    return ret;
}

/*
 * Delete the whole prio node <prio> (all filters at that priority) from the
 * clsact egress side. ENOENT = nothing at that prio, fine for callers.
 */
static int tc_filter_del_prio(struct nl_handler *nlh, int ifindex, unsigned int prio)
{
    struct nlmsg *msg, *reply;
    struct tcmsg *tcm;
    int ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        return -ENOMEM;
    }

    tcm = (struct tcmsg *)nlmsg_data(msg);
    memset(tcm, 0, sizeof(*tcm));
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = ifindex;
    tcm->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    tcm->tcm_info = (prio << 16) | htons(ETH_P_ALL);

    msg->nlmsghdr.nlmsg_type = RTM_DELTFILTER;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    ret = netlink_transaction(nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    return ret;
}

/*
 * Attach a classic-BPF drop filter: cls_bpf on clsact egress at <prio>,
 * protocol ETH_P_ALL, one gact action with TC_ACT_SHOT. The kernel assigns
 * the filter handle. Attribute order mirrors the tc CLI (ACT, then
 * OPS_LEN/OPS; the kernel is order-agnostic).
 */
static int tc_bpf_filter_add(struct nl_handler *nlh, int ifindex,
                             unsigned int prio,
                             const struct sock_filter *ops, unsigned int ops_len)
{
    struct nlmsg *msg, *reply;
    struct rtattr *opts, *act, *slot, *actopts;
    struct tc_gact gact;
    struct tcmsg *tcm;
    int ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        return -ENOMEM;
    }

    tcm = (struct tcmsg *)nlmsg_data(msg);
    memset(tcm, 0, sizeof(*tcm));
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = ifindex;
    tcm->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    tcm->tcm_info = (prio << 16) | htons(ETH_P_ALL);

    msg->nlmsghdr.nlmsg_type = RTM_NEWTFILTER;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    nla_put_string(msg, TCA_KIND, "bpf");

    opts = nla_begin_nested(msg, TCA_OPTIONS);
    opts->rta_type |= NLA_F_NESTED;

    /* TCA_BPF_ACT -> action slot 1 -> gact with action = TC_ACT_SHOT */
    act = nla_begin_nested(msg, TCA_BPF_ACT);
    act->rta_type |= NLA_F_NESTED;
    slot = nla_begin_nested(msg, 1);
    slot->rta_type |= NLA_F_NESTED;
    nla_put_string(msg, TCA_ACT_KIND, "gact");
    actopts = nla_begin_nested(msg, TCA_ACT_OPTIONS);
    actopts->rta_type |= NLA_F_NESTED;
    memset(&gact, 0, sizeof(gact));
    gact.action = TC_ACT_SHOT;
    nla_put_buffer(msg, TCA_GACT_PARMS, &gact, sizeof(gact));
    nla_end_nested(msg, actopts);
    nla_end_nested(msg, slot);
    nla_end_nested(msg, act);

    /* the classic bytecode itself (struct bpf_insn == struct sock_filter) */
    nla_put_u16(msg, TCA_BPF_OPS_LEN, ops_len);
    nla_put_buffer(msg, TCA_BPF_OPS, ops, ops_len * sizeof(*ops));

    nla_end_nested(msg, opts);

    ret = netlink_transaction(nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    return ret;
}

/*
 * Delete every tracked prio node of <ifindex> from the kernel and untrack
 * it. ENOENT per filter is tolerated (already gone). With stop_on_error
 * (flush), the first real failure aborts and the remaining entries stay
 * tracked; reset passes 0 — clsact is torn down right after, so untracking
 * everything is correct regardless. Returns 0 or the first non-ENOENT
 * negative errno.
 */
static int bpf_drop_flush_tracked(struct nl_handler *nlh, unsigned int ifindex,
                                  int stop_on_error)
{
    struct bpf_drop_prio **pp = &bpf_drop_prios, *e;
    int ret = 0, err;

    while ((e = *pp) != NULL) {
        if (e->ifindex != ifindex) {
            pp = &e->next;
            continue;
        }
        err = tc_filter_del_prio(nlh, ifindex, e->prio);
        if (err < 0 && err != -ENOENT) {
            if (ret == 0)
                ret = err;
            if (stop_on_error)
                break;
        }
        *pp = e->next;
        free(e);
    }
    return ret;
}

/* RTM_NEWLINK a throwaway dummy (IFLA_INFO_KIND "dummy"). */
static int nl_link_create_dummy(struct nl_handler *nlh, const char *name)
{
    struct nlmsg *msg, *reply;
    struct ifinfomsg *ifi;
    struct rtattr *linkinfo;
    int ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        return -ENOMEM;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;

    msg->nlmsghdr.nlmsg_type = RTM_NEWLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    nla_put_string(msg, IFLA_IFNAME, name);
    linkinfo = nla_begin_nested(msg, IFLA_LINKINFO);
    nla_put_string(msg, IFLA_INFO_KIND, "dummy");
    nla_end_nested(msg, linkinfo);

    ret = netlink_transaction(nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    return ret;
}

/* RTM_DELLINK by ifindex. */
static int nl_link_delete(struct nl_handler *nlh, int ifindex)
{
    struct nlmsg *msg, *reply;
    struct ifinfomsg *ifi;
    int ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        return -ENOMEM;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_DELLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    ret = netlink_transaction(nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    return ret;
}

/* defined with the eBPF section below; used by tc_reset */
static void ebpf_if_release(struct nl_handler *nlh, unsigned int ifindex);

/*
 * Full restore of <ifname> (spec part D): 1. remove every bpf_drop filter we
 * added (clsact egress side), 2. delete clsact, 3. delete the root qdisc.
 * ENOENT at any step is the target state already (idempotent reset).
 * Returns 0 or a negative errno.
 */
static int tc_reset(const char *ifname)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct tcmsg *tcm;
    int ifindex, ret;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
        return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0)
        return ret;

    /* 0. the eBPF impairment filter (prio 1) and its program/maps */
    ebpf_if_release(&nlh, ifindex);

    /* 1. our classifier filters (ENOENT tolerated; untrack all regardless —
     * clsact goes away next, taking any survivor with it) */
    ret = bpf_drop_flush_tracked(&nlh, ifindex, 0);
    if (ret < 0)
        goto out;

    /* 2. clsact (coexisted with the root netem; absent = fine) */
    ret = tc_clsact_delete(&nlh, ifindex);
    if (ret == -ENOENT)
        ret = 0;
    if (ret < 0)
        goto out;

    /* 3. the root qdisc */
    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        ret = -ENOMEM;
        goto out;
    }

    tcm = (struct tcmsg *)nlmsg_data(msg);
    memset(tcm, 0, sizeof(*tcm));
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = ifindex;
    tcm->tcm_parent = TC_H_ROOT;

    msg->nlmsghdr.nlmsg_type = RTM_DELQDISC;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    ret = netlink_transaction(&nlh, msg, reply);

out:
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/* --------------------------------------------------------------------------
 * Command handlers
 * -------------------------------------------------------------------------- */

/* Parse a 0..100 percentage into *out. Returns 0 or -1. */
static int parse_pct(const char *val, unsigned int *out)
{
    char *end;
    long v = strtol(val, &end, 10);

    if (end == val || *end != '\0' || v < 0 || v > 100)
        return -1;
    *out = (unsigned int)v;
    return 0;
}

/*
 * tc netem set <if> [delay <ms>] [jitter <ms>]
 *    [loss <pct> [correl <pct>] | loss gemodel <p> [<r> [<1-h>]]]
 *    [dup <pct> [correl <pct>]] [corrupt <pct>]
 *    [reorder <pct> [correl <pct>] [gap <n>]]    (reorder requires delay)
 *    [rate <bw>] [limit <pkts>]
 *    [distribution uniform|normal|pareto|paretonormal] [seed <u32>]
 */
static int cmd_netem(hypervisor_conn_t *conn, int argc, char *argv[])
{
    const char *ifname;
    struct netem_params p;
    int i, err;

    if (strcmp(argv[0], "set") != 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "unknown netem action '%s' (expected 'set')", argv[0]);
        return -1;
    }

    ifname = argv[1];
    memset(&p, 0, sizeof(p));
    p.dist = -1;   /* no distribution table by default (uniform) */

    i = 2;
    while (i < argc) {
        const char *kw = argv[i];

        if (!strcmp(kw, "delay") || !strcmp(kw, "jitter")) {
            char *end;
            double ms;
            if (i + 1 >= argc) {
                hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "option '%s' missing its value", kw);
                return -1;
            }
            ms = strtod(argv[i + 1], &end);
            if (end == argv[i + 1] || *end != '\0' || ms < 0) {
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid %s value '%s'", kw, argv[i + 1]);
                return -1;
            }
            if (kw[0] == 'd') { p.has_delay = 1; p.delay_ms = ms; }
            else { p.has_jitter = 1; p.jitter_ms = ms; }
            i += 2;
        } else if (!strcmp(kw, "loss")) {
            if (p.has_loss || p.has_gemodel) {
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "duplicate loss argument");
                return -1;
            }
            if (i + 1 >= argc) {
                hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "option '%s' missing its value", kw);
                return -1;
            }
            if (!strcmp(argv[i + 1], "gemodel")) {
                /* loss gemodel <p> [<r> [<1-h>]] — defaults r=0, 1-h=0 */
                i += 2;
                if (i >= argc || !isdigit((unsigned char)argv[i][0])) {
                    hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "option 'loss gemodel' missing its value");
                    return -1;
                }
                if (parse_pct(argv[i], &p.gem_p) < 0) {
                    hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid gemodel value '%s' (0-100)", argv[i]);
                    return -1;
                }
                i++;
                if (i < argc && isdigit((unsigned char)argv[i][0])) {
                    if (parse_pct(argv[i], &p.gem_r) < 0) {
                        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid gemodel value '%s' (0-100)", argv[i]);
                        return -1;
                    }
                    i++;
                    if (i < argc && isdigit((unsigned char)argv[i][0])) {
                        if (parse_pct(argv[i], &p.gem_one_minus_h) < 0) {
                            hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid gemodel value '%s' (0-100)", argv[i]);
                            return -1;
                        }
                        i++;
                    }
                }
                p.has_gemodel = 1;
            } else {
                if (parse_pct(argv[i + 1], &p.loss_pct) < 0) {
                    hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid loss percent '%s' (0-100)", argv[i + 1]);
                    return -1;
                }
                p.has_loss = 1;
                i += 2;
                /* correl binds to the loss it follows */
                if (i + 1 < argc && !strcmp(argv[i], "correl")) {
                    if (parse_pct(argv[i + 1], &p.loss_correl_pct) < 0) {
                        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid correl percent '%s' (0-100)", argv[i + 1]);
                        return -1;
                    }
                    p.has_loss_correl = 1;
                    i += 2;
                }
            }
        } else if (!strcmp(kw, "dup")) {
            if (i + 1 >= argc) {
                hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "option '%s' missing its value", kw);
                return -1;
            }
            if (parse_pct(argv[i + 1], &p.dup_pct) < 0) {
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid dup percent '%s' (0-100)", argv[i + 1]);
                return -1;
            }
            p.has_dup = 1;
            i += 2;
            if (i + 1 < argc && !strcmp(argv[i], "correl")) {
                if (parse_pct(argv[i + 1], &p.dup_correl_pct) < 0) {
                    hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid correl percent '%s' (0-100)", argv[i + 1]);
                    return -1;
                }
                p.has_dup_correl = 1;
                i += 2;
            }
        } else if (!strcmp(kw, "corrupt")) {
            if (i + 1 >= argc) {
                hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "option '%s' missing its value", kw);
                return -1;
            }
            if (parse_pct(argv[i + 1], &p.corrupt_pct) < 0) {
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid corrupt percent '%s' (0-100)", argv[i + 1]);
                return -1;
            }
            p.has_corrupt = 1;
            i += 2;
        } else if (!strcmp(kw, "reorder")) {
            if (i + 1 >= argc) {
                hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "option '%s' missing its value", kw);
                return -1;
            }
            if (parse_pct(argv[i + 1], &p.reorder_pct) < 0) {
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid reorder percent '%s' (0-100)", argv[i + 1]);
                return -1;
            }
            p.has_reorder = 1;
            i += 2;
            /* correl / gap bind to the reorder they follow (any order) */
            for (;;) {
                if (i + 1 < argc && !strcmp(argv[i], "correl") && !p.has_reorder_correl) {
                    if (parse_pct(argv[i + 1], &p.reorder_correl_pct) < 0) {
                        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid correl percent '%s' (0-100)", argv[i + 1]);
                        return -1;
                    }
                    p.has_reorder_correl = 1;
                    i += 2;
                } else if (i + 1 < argc && !strcmp(argv[i], "gap") && !p.has_gap) {
                    char *end;
                    long v = strtol(argv[i + 1], &end, 10);
                    if (end == argv[i + 1] || *end != '\0' || v < 1 || v > 1000) {
                        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid gap value '%s' (1-1000)", argv[i + 1]);
                        return -1;
                    }
                    p.gap = (unsigned int)v;
                    p.has_gap = 1;
                    i += 2;
                } else {
                    break;
                }
            }
        } else if (!strcmp(kw, "rate")) {
            unsigned long long bits;
            if (i + 1 >= argc) {
                hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "option '%s' missing its value", kw);
                return -1;
            }
            if (parse_rate_bps(argv[i + 1], &bits) < 0) {
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid rate value '%s'", argv[i + 1]);
                return -1;
            }
            p.has_rate = 1;
            p.rate_bytes = bits / 8;   /* tc wire unit is bytes/s */
            i += 2;
        } else if (!strcmp(kw, "limit")) {
            char *end;
            long v;
            if (i + 1 >= argc) {
                hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "option '%s' missing its value", kw);
                return -1;
            }
            v = strtol(argv[i + 1], &end, 10);
            if (end == argv[i + 1] || *end != '\0' || v < 1 || v > 1000000) {
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid limit value '%s' (1-1000000)", argv[i + 1]);
                return -1;
            }
            p.has_limit = 1;
            p.limit = (unsigned int)v;
            i += 2;
        } else if (!strcmp(kw, "seed")) {
            char *end;
            unsigned long long v;
            if (i + 1 >= argc) {
                hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "option '%s' missing its value", kw);
                return -1;
            }
            v = strtoull(argv[i + 1], &end, 10);
            if (end == argv[i + 1] || *end != '\0' || v > 0xFFFFFFFFULL) {
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid seed value '%s'", argv[i + 1]);
                return -1;
            }
            p.has_seed = 1;
            p.seed = v;
            i += 2;
        } else if (!strcmp(kw, "distribution")) {
            if (i + 1 >= argc) {
                hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "option '%s' missing its value", kw);
                return -1;
            }
            if (!strcmp(argv[i + 1], "uniform")) {
                p.dist = -1;           /* kernel default: no table */
            } else if (!strcmp(argv[i + 1], "normal")) {
                p.dist = 0;
            } else if (!strcmp(argv[i + 1], "pareto")) {
                p.dist = 1;
            } else if (!strcmp(argv[i + 1], "paretonormal")) {
                p.dist = 2;
            } else {
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "unknown distribution '%s'", argv[i + 1]);
                return -1;
            }
            i += 2;
        } else {
            hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "unknown netem option '%s'", kw);
            return -1;
        }
    }

    if (p.has_reorder && !p.has_delay) {
        /* mirror the tc CLI check (reordering is invisible without delay);
         * the server keys on this exact string */
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "reorder requires delay");
        return -1;
    }

    err = tc_netem_replace(ifname, &p);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "Could not set netem on %s: %s", ifname, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "netem set on %s", ifname);
    return 0;
}

/* tc reset <if> */
static int cmd_reset(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *ifname = argv[0];
    int err = tc_reset(ifname);

    if (err < 0) {
        if (err == -ENOENT) {
            /* No root qdisc = already the target state ("ensure no netem").
             * Idempotent OK, like marker delete_kernel / capture stop_kernel. */
            hypervisor_send_reply(conn, HSC_INFO_OK, 1, "no qdisc on %s", ifname);
            return 0;
        }
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "Could not reset qdisc on %s: %s", ifname, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "qdisc reset on %s", ifname);
    return 0;
}

/* --------------------------------------------------------------------------
 * eBPF stateful impairment (spec B): one program per interface, attached
 * once at clsact egress prio 1; the four modes are pure map state.
 * -------------------------------------------------------------------------- */

/* prio 1 is reserved for this filter (bpf_drop owns 10..99) */
#define EBPF_FILTER_PRIO 1

/* the exact 210 reply the controller keys on (spec B.3 / E) */
#define EBPF_NO_CAP_MSG \
    "uBridge lacks CAP_BPF (setcap cap_bpf,cap_net_admin,cap_net_raw=ep) " \
    "and the kernel requires it for stateful filters"

struct ebpf_if {
    struct ebpf_if *next;
    unsigned int ifindex;
    int prog_fd, cfg_fd, cnt_fd;
    struct tc_impair_cfg cfg;
};

/* like the bpf_drop prio registry: only touched from command handlers
 * (dispatcher serialises them under global_lock) */
static struct ebpf_if *ebpf_interfaces;

static struct ebpf_if *ebpf_if_find(unsigned int ifindex)
{
    struct ebpf_if *e;

    for (e = ebpf_interfaces; e != NULL; e = e->next)
        if (e->ifindex == ifindex)
            return e;
    return NULL;
}

/* Attach the loaded program at clsact egress prio 1, direct-action (the
 * program's TC_ACT_* return IS the verdict). 0 or -errno. */
static int ebpf_attach(struct nl_handler *nlh, int ifindex, int prog_fd)
{
    struct nlmsg *msg, *reply;
    struct rtattr *opts;
    struct tcmsg *tcm;
    int ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        return -ENOMEM;
    }

    tcm = (struct tcmsg *)nlmsg_data(msg);
    memset(tcm, 0, sizeof(*tcm));
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = ifindex;
    tcm->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    tcm->tcm_info = (EBPF_FILTER_PRIO << 16) | htons(ETH_P_ALL);

    msg->nlmsghdr.nlmsg_type = RTM_NEWTFILTER;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    nla_put_string(msg, TCA_KIND, "bpf");

    opts = nla_begin_nested(msg, TCA_OPTIONS);
    opts->rta_type |= NLA_F_NESTED;
    nla_put_u32(msg, TCA_BPF_FD, prog_fd);
    nla_put_string(msg, TCA_BPF_NAME, "tc_impair");
    /* direct-action: no gact needed, the program returns TC_ACT_SHOT/OK */
    nla_put_u32(msg, TCA_BPF_FLAGS, 1 /* TCA_BPF_FLAG_ACT_DIRECT */);
    nla_end_nested(msg, opts);

    ret = netlink_transaction(nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    return ret;
}

/*
 * First enable on an interface: ensure clsact, create maps + load the
 * program, attach at prio 1. *out is registered on success. Returns 0,
 * -errno, or -1 with *errmsg set to the static no-CAP_BPF message.
 */
static int ebpf_if_enable(struct nl_handler *nlh, unsigned int ifindex,
                          struct ebpf_if **out, const char **errmsg)
{
    struct ebpf_if *e;
    int ret;

    ret = tc_clsact_create(nlh, ifindex);
    if (ret < 0)
        return ret;

    e = malloc(sizeof(*e));
    if (e == NULL)
        return -ENOMEM;
    memset(e, 0, sizeof(*e));
    e->ifindex = ifindex;

    ret = tc_ebpf_load(&e->prog_fd, &e->cfg_fd, &e->cnt_fd);
    if (ret < 0) {
        free(e);
        /* EPERM = the BPF capability gate; EACCES = the verifier refusing a
         * program this process may not run (kernel !root restrictions).
         * Both mean "stateful filters unavailable here" — the spec's 210. */
        if (ret == -EPERM || ret == -EACCES) {
            *errmsg = EBPF_NO_CAP_MSG;
            return -1;
        }
        return ret;
    }

    ret = ebpf_attach(nlh, ifindex, e->prog_fd);
    if (ret < 0) {
        close(e->prog_fd);
        close(e->cfg_fd);
        close(e->cnt_fd);
        free(e);
        return ret;
    }

    e->next = ebpf_interfaces;
    ebpf_interfaces = e;
    *out = e;
    return 0;
}

/* Detach the prio-1 filter, close the fds, drop the registry entry. */
static void ebpf_if_release(struct nl_handler *nlh, unsigned int ifindex)
{
    struct ebpf_if **pp = &ebpf_interfaces, *e;

    while ((e = *pp) != NULL) {
        if (e->ifindex != ifindex) {
            pp = &e->next;
            continue;
        }
        tc_filter_del_prio(nlh, ifindex, EBPF_FILTER_PRIO);   /* ENOENT fine */
        close(e->prog_fd);
        close(e->cfg_fd);
        close(e->cnt_fd);
        *pp = e->next;
        free(e);
    }
}

/* true when no mode is active anymore — the filter can go away */
static int ebpf_cfg_all_off(const struct tc_impair_cfg *c)
{
    return c->nth == 0 && c->quota_bytes == 0 && c->win_len_ns == 0
           && (c->flow_mask == 0 || c->flow_target == 0);
}

/* what a mode command wants reset/reseeded in CNT before the cfg update */
struct ebpf_resets {
    int nth;      /* zero nth_state */
    int quota;    /* zero packets/bytes */
    int window;   /* reseed the current-cycle window lengths from cfg */
};

/* Common tail of every mode command: apply cfg, reset that mode's
 * counters, tear the whole thing down when the last mode went off. */
static int ebpf_apply(hypervisor_conn_t *conn, struct nl_handler *nlh,
                      struct ebpf_if *e, const char *mode, const char *ifname,
                      const struct ebpf_resets *res, int was_loaded)
{
    int ret;

    if (ebpf_cfg_all_off(&e->cfg)) {
        /* last mode off: filter and program go away */
        if (was_loaded)
            ebpf_if_release(nlh, e->ifindex);
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s off on %s", mode, ifname);
        return 0;
    }

    if (res->nth || res->quota)
        tc_ebpf_cnt_reset(e->cnt_fd, res->nth, res->quota);     /* best effort */
    if (res->window)
        tc_ebpf_cnt_set_window(e->cnt_fd, e->cfg.win_len_ns,
                               e->cfg.win_period_ns);           /* best effort */
    ret = tc_ebpf_map_update(e->cfg_fd, &e->cfg);
    if (ret < 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                              "Could not set %s on %s: %s", mode, ifname, strerror(-ret));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s set on %s", mode, ifname);
    return 0;
}

/*
 * Shared dispatch for the four mode commands. argv after the command:
 *   <if> <mode-specific values...> | <if> off
 * set_fn fills cfg (validation, 204 on bad values) and the reset/reseed
 * flags; argc lets a mode take optional trailing arguments.
 */
static int cmd_ebpf_mode(hypervisor_conn_t *conn, int argc, char *argv[],
                         const char *mode,
                         int (*set_fn)(hypervisor_conn_t *conn, int argc,
                                       char **argv, struct tc_impair_cfg *cfg,
                                       struct ebpf_resets *res))
{
    struct nl_handler nlh;
    struct ebpf_if *e;
    const char *ifname = argv[0];
    const char *errmsg = NULL;
    struct ebpf_resets res = { 0, 0, 0 };
    int ifindex, was_loaded, ret;

    if (strcmp(argv[1], "off") == 0) {
        if (argc != 2) {
            hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1,
                                  "Bad number of parameters (%d with min/max=2/2)", argc);
            return -1;
        }
        ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                                  "Could not set %s on %s: %s", mode, ifname, strerror(ENODEV));
            return -1;
        }
        e = ebpf_if_find(ifindex);
        if (e == NULL) {
            /* nothing loaded: the mode is trivially off (idempotent) */
            hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s off on %s", mode, ifname);
            return 0;
        }
        /* clear this mode's cfg fields; counters reset below (or the whole
         * state is torn down when this was the last active mode) */
        if (strcmp(mode, "nth_drop") == 0) {
            e->cfg.nth = 0;
            res.nth = 1;
        } else if (strcmp(mode, "quota_drop") == 0) {
            e->cfg.quota_bytes = 0;
            e->cfg.quota_pct = 0;
            res.quota = 1;
        } else if (strcmp(mode, "window_drop") == 0) {
            e->cfg.win_len_ns = 0;
            e->cfg.win_period_ns = 0;
            e->cfg.win_jitter_ns = 0;
            e->cfg.win_pct = 0;
        } else {
            e->cfg.flow_mask = 0;
            e->cfg.flow_target = 0;
        }
        ret = netlink_open(&nlh, NETLINK_ROUTE);
        if (ret < 0) {
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                                  "Could not set %s on %s: %s", mode, ifname, strerror(-ret));
            return -1;
        }
        ebpf_apply(conn, &nlh, e, mode, ifname, &res, 1);
        netlink_close(&nlh);
        return 0;
    }

    /* set path: validate FIRST — a bad value must 204 without touching the
     * kernel (and without a pointless program load). The scratch cfg is
     * seeded from the current state so the other modes stay configured. */
    {
        struct tc_impair_cfg scratch;

        ifindex = if_nametoindex(ifname);
        e = (ifindex != 0) ? ebpf_if_find(ifindex) : NULL;
        if (e != NULL)
            scratch = e->cfg;
        else
            memset(&scratch, 0, sizeof(scratch));

        if (set_fn(conn, argc, argv, &scratch, &res) < 0)
            return -1;                        /* set_fn already replied 204 */

        if (ifindex == 0) {
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                                  "Could not set %s on %s: %s", mode, ifname, strerror(ENODEV));
            return -1;
        }

        ret = netlink_open(&nlh, NETLINK_ROUTE);
        if (ret < 0) {
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                                  "Could not set %s on %s: %s", mode, ifname, strerror(-ret));
            return -1;
        }

        was_loaded = (e != NULL);
        if (e == NULL) {
            ret = ebpf_if_enable(&nlh, ifindex, &e, &errmsg);
            if (ret < 0) {
                netlink_close(&nlh);
                if (errmsg != NULL) {
                    hypervisor_send_reply(conn, HSC_ERR_STOP, 1, "%s", errmsg);
                    return -1;
                }
                hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                                      "Could not set %s on %s: %s", mode, ifname, strerror(-ret));
                return -1;
            }
        }

        e->cfg = scratch;
        ebpf_apply(conn, &nlh, e, mode, ifname, &res, was_loaded);
        netlink_close(&nlh);
        return 0;
    }
}

/* tc nth_drop <if> <n | off> */
static int nth_set(hypervisor_conn_t *conn, int argc, char **argv,
                   struct tc_impair_cfg *cfg, struct ebpf_resets *res)
{
    char *end;
    long v;

    (void)argc;
    v = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || v < 1 || v > 1000000) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "invalid nth value '%s' (1-1000000)", argv[1]);
        return -1;
    }
    cfg->nth = (unsigned int)v;
    res->nth = 1;
    return 0;
}

/* tc quota_drop <if> <bytes> <pct> | off */
static int quota_set(hypervisor_conn_t *conn, int argc, char **argv,
                     struct tc_impair_cfg *cfg, struct ebpf_resets *res)
{
    char *end;
    unsigned long long bytes;

    (void)argc;
    if (!isdigit((unsigned char)argv[1][0]))
        goto bad_bytes;
    bytes = strtoull(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || bytes == 0)
        goto bad_bytes;
    if (parse_pct(argv[2], &cfg->quota_pct) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "invalid quota percent '%s' (0-100)", argv[2]);
        return -1;
    }
    cfg->quota_bytes = bytes;
    res->quota = 1;
    return 0;

bad_bytes:
    hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                          "invalid quota bytes '%s'", argv[1]);
    return -1;
}

/*
 * tc window_drop <if> <start_ms> <outage_ms> <pct> [<period_ms> [<jitter_ms>]] | off
 *
 * period omitted: a single [start, start+outage) window — packets pass
 * before AND after it. With period: outages recur every cycle; jitter
 * re-draws each cycle's outage/period uniformly in nominal ± jitter
 * (0 = the fixed schedule). jitter is capped at 1e9 ms so the program's
 * multiply-shift draw cannot overflow on the ms grid.
 */
static int window_set(hypervisor_conn_t *conn, int argc, char **argv,
                      struct tc_impair_cfg *cfg, struct ebpf_resets *res)
{
    char *end;
    unsigned long long start_ms, len_ms, period_ms = 0, jitter_ms = 0;
    struct timespec ts;

    if (!isdigit((unsigned char)argv[1][0])) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "invalid window start '%s'", argv[1]);
        return -1;
    }
    start_ms = strtoull(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || start_ms > 1000000000000ULL) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "invalid window start '%s'", argv[1]);
        return -1;
    }
    if (!isdigit((unsigned char)argv[2][0]))
        goto bad_len;
    len_ms = strtoull(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || len_ms == 0 || len_ms > 1000000000000ULL)
        goto bad_len;
    if (parse_pct(argv[3], &cfg->win_pct) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "invalid window percent '%s' (0-100)", argv[3]);
        return -1;
    }
    if (argc >= 5) {
        if (!isdigit((unsigned char)argv[4][0]))
            goto bad_period;
        period_ms = strtoull(argv[4], &end, 10);
        if (end == argv[4] || *end != '\0' || period_ms == 0
            || period_ms > 1000000000000ULL || period_ms < len_ms)
            goto bad_period;
        if (argc == 6) {
            if (!isdigit((unsigned char)argv[5][0]))
                goto bad_jitter;
            jitter_ms = strtoull(argv[5], &end, 10);
            if (end == argv[5] || *end != '\0' || jitter_ms > 1000000000ULL)
                goto bad_jitter;
        }
    }

    /* first window starts start_ms from now; the program then advances
     * start by one (drawn) period per cycle (monotonic clock, same base
     * as bpf_ktime_get_ns) */
    clock_gettime(CLOCK_MONOTONIC, &ts);
    cfg->win_start_ns = ((unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec)
                        + start_ms * 1000000ULL;
    cfg->win_len_ns = len_ms * 1000000ULL;
    cfg->win_period_ns = period_ms * 1000000ULL;
    cfg->win_jitter_ns = jitter_ms * 1000000ULL;
    res->window = 1;
    return 0;

bad_len:
    hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                          "invalid window length '%s'", argv[2]);
    return -1;
bad_period:
    hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                          "invalid window period '%s' (>= outage length)", argv[4]);
    return -1;
bad_jitter:
    hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                          "invalid window jitter '%s' (0-1000000000)", argv[5]);
    return -1;
}

/* tc flow_drop <if> <mask> <target> | off */
static int flow_set(hypervisor_conn_t *conn, int argc, char **argv,
                    struct tc_impair_cfg *cfg, struct ebpf_resets *res)
{
    char *end;
    long mask, target;

    (void)argc;
    (void)res;
    mask = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || mask < 1 || mask > 0x1F) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "invalid flow mask '%s' (1-31: 1=src 2=dst 4=sport 8=dport 16=proto)",
                              argv[1]);
        return -1;
    }
    target = strtol(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || target < 1 || target > 0xFFFFFFFFL) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "invalid flow target '%s' (>=1)", argv[2]);
        return -1;
    }
    cfg->flow_mask = (unsigned int)mask;
    cfg->flow_target = (unsigned int)target;
    return 0;
}

/* thin command handlers keeping the per-mode expected-argc in one place */
static int cmd_nth_drop(hypervisor_conn_t *conn, int argc, char *argv[])
{
    if (argc != 2) {
        hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1,
                              "Bad number of parameters (%d with min/max=2/2)", argc);
        return -1;
    }
    return cmd_ebpf_mode(conn, argc, argv, "nth_drop", nth_set);
}

static int cmd_quota_drop(hypervisor_conn_t *conn, int argc, char *argv[])
{
    if (argc != 3 && strcmp(argv[1], "off") != 0) {
        hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1,
                              "Bad number of parameters (%d with min/max=3/3)", argc);
        return -1;
    }
    if (argc != 2 && strcmp(argv[1], "off") == 0) {
        hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1,
                              "Bad number of parameters (%d with min/max=2/2)", argc);
        return -1;
    }
    return cmd_ebpf_mode(conn, argc, argv, "quota_drop", quota_set);
}

static int cmd_window_drop(hypervisor_conn_t *conn, int argc, char *argv[])
{
    if (strcmp(argv[1], "off") != 0 && (argc < 4 || argc > 6)) {
        hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1,
                              "Bad number of parameters (%d with min/max=4/6)", argc);
        return -1;
    }
    if (strcmp(argv[1], "off") == 0 && argc != 2) {
        hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1,
                              "Bad number of parameters (%d with min/max=2/2)", argc);
        return -1;
    }
    return cmd_ebpf_mode(conn, argc, argv, "window_drop", window_set);
}

static int cmd_flow_drop(hypervisor_conn_t *conn, int argc, char *argv[])
{
    if (argc != 3 && strcmp(argv[1], "off") != 0) {
        hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1,
                              "Bad number of parameters (%d with min/max=3/3)", argc);
        return -1;
    }
    if (argc != 2 && strcmp(argv[1], "off") == 0) {
        hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1,
                              "Bad number of parameters (%d with min/max=2/2)", argc);
        return -1;
    }
    return cmd_ebpf_mode(conn, argc, argv, "flow_drop", flow_set);
}

/* --------------------------------------------------------------------------
 * bpf_drop commands
 * --------------------------------------------------------------------------
 */

/*
 * Compile a pcap expression against Ethernet (same shape as the relay's
 * "bpf" filter, so one expression serves both datapaths). On failure the
 * caller replies 209 with this exact prefix — the controller keys on it.
 * Newlines in pcap's error are folded to spaces to keep the reply
 * single-line. Returns 0 or -1 with <err> filled.
 */
static int bpf_drop_compile(const char *expr, struct bpf_program *fp,
                            char *err, size_t errlen)
{
    pcap_t *pd;
    char *p;

    pd = pcap_open_dead(DLT_EN10MB, 65535);
    if (pd == NULL) {
        snprintf(err, errlen, "pcap_open_dead failed");
        return -1;
    }
    if (pcap_compile(pd, fp, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        snprintf(err, errlen, "%s", pcap_geterr(pd));
        for (p = err; *p != '\0'; p++)
            if (*p == '\n' || *p == '\r')
                *p = ' ';
        pcap_close(pd);
        return -1;
    }
    pcap_close(pd);
    return 0;
}

/*
 * tc bpf_drop add <if> <prio> "<expression>"
 * tc bpf_drop flush <if>
 */
static int cmd_bpf_drop(hypervisor_conn_t *conn, int argc, char *argv[])
{
    struct nl_handler nlh;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *ifname;
    unsigned int prio;
    char *end;
    long v;
    int ifindex, ret;

    if (strcmp(argv[0], "add") == 0) {
        if (argc != 4) {
            hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1,
                                  "Bad number of parameters (%d with min/max=4/4)", argc);
            return -1;
        }
        ifname = argv[1];
        v = strtol(argv[2], &end, 10);
        if (end == argv[2] || *end != '\0' || v < BPF_DROP_PRIO_MIN || v > BPF_DROP_PRIO_MAX) {
            hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                                  "invalid prio value '%s' (%d-%d)", argv[2],
                                  BPF_DROP_PRIO_MIN, BPF_DROP_PRIO_MAX);
            return -1;
        }
        prio = (unsigned int)v;

        if (bpf_drop_compile(argv[3], &fp, errbuf, sizeof(errbuf)) < 0) {
            hypervisor_send_reply(conn, HSC_ERR_START, 1,
                                  "Cannot compile filter '%s': %s", argv[3], errbuf);
            return -1;
        }

        ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            pcap_freecode(&fp);
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                                  "Could not add bpf_drop filter on %s: %s", ifname, strerror(ENODEV));
            return -1;
        }

        ret = netlink_open(&nlh, NETLINK_ROUTE);
        if (ret < 0) {
            pcap_freecode(&fp);
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                                  "Could not add bpf_drop filter on %s: %s", ifname, strerror(-ret));
            return -1;
        }

        /* clsact (EEXIST tolerated), then replace-whole-prio semantics:
         * drop any filter already sitting at this prio so re-adding an
         * expression cannot stack duplicates. The controller normally
         * flushes first; this covers a ubridge restart. */
        ret = tc_clsact_create(&nlh, ifindex);
        if (ret == 0) {
            tc_filter_del_prio(&nlh, ifindex, prio);   /* best effort */
            ret = tc_bpf_filter_add(&nlh, ifindex, prio,
                                    (const struct sock_filter *)fp.bf_insns, fp.bf_len);
        }
        netlink_close(&nlh);
        pcap_freecode(&fp);

        if (ret < 0) {
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                                  "Could not add bpf_drop filter on %s: %s", ifname, strerror(-ret));
            return -1;
        }
        bpf_drop_track(ifindex, prio);
        hypervisor_send_reply(conn, HSC_INFO_OK, 1,
                              "bpf_drop filter added on %s (prio %u)", ifname, prio);
        return 0;
    }

    if (strcmp(argv[0], "flush") == 0) {
        if (argc != 2) {
            hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1,
                                  "Bad number of parameters (%d with min/max=2/2)", argc);
            return -1;
        }
        ifname = argv[1];

        ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                                  "Could not flush bpf_drop on %s: %s", ifname, strerror(ENODEV));
            return -1;
        }

        ret = netlink_open(&nlh, NETLINK_ROUTE);
        if (ret < 0) {
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                                  "Could not flush bpf_drop on %s: %s", ifname, strerror(-ret));
            return -1;
        }
        /* only OUR filters: clsact itself, any eBPF impairment filter and
         * the netem root qdisc stay untouched */
        ret = bpf_drop_flush_tracked(&nlh, ifindex, 1);
        netlink_close(&nlh);

        if (ret < 0) {
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                                  "Could not flush bpf_drop on %s: %s", ifname, strerror(-ret));
            return -1;
        }
        hypervisor_send_reply(conn, HSC_INFO_OK, 1,
                              "bpf_drop filters flushed on %s", ifname);
        return 0;
    }

    hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                          "unknown bpf_drop action '%s' (expected 'add' or 'flush')", argv[0]);
    return -1;
}

/*
 * cbpf capability probe: can this kernel (and our caps) install a
 * classic-BPF cls_bpf filter at all? Creates a throwaway dummy, attaches
 * clsact plus a one-instruction never-matching program, then deletes the
 * dummy again (deleting the link tears the qdisc with it). Result cached;
 * failure of any step means cbpf=0 and the controller stays on the relay
 * datapath for "bpf" filters.
 */
static int tc_cbpf_capable(void)
{
    static int capable = -1;
    struct nl_handler nlh;
    /* ret #0 — never matches, so even a leak could not drop traffic */
    static const struct sock_filter never[1] = { { .code = BPF_RET | BPF_K, .k = 0 } };
    char name[IF_NAMESIZE];
    unsigned int salt;
    int attempt, ifindex, ok = 0;

    if (capable >= 0)
        return capable;
    capable = 0;

    if (netlink_open(&nlh, NETLINK_ROUTE) < 0)
        return capable;

    for (attempt = 0; attempt < 3 && !ok; attempt++) {
        salt = (unsigned int)(getpid() + attempt * 7919) % 100000;
        snprintf(name, sizeof(name), "ubcap%05u", salt);
        if (nl_link_create_dummy(&nlh, name) < 0)
            continue;
        ifindex = if_nametoindex(name);
        if (ifindex == 0)
            continue;
        if (tc_clsact_create(&nlh, ifindex) == 0)
            ok = (tc_bpf_filter_add(&nlh, ifindex, BPF_DROP_PRIO_MAX, never, 1) == 0);
        nl_link_delete(&nlh, ifindex);   /* qdisc and filters go with it */
    }
    netlink_close(&nlh);

    capable = ok;
    return capable;
}

/*
 * tc capabilities — what this build supports, so the controller can hide
 * filter types the local kernel/ubridge cannot run (and fall back to the
 * relay datapath). ebpf = the real program loads+verifies here (CAP_BPF,
 * kernel new enough); cbpf = a classic cls_bpf filter installs. An old
 * ubridge without this command at all keeps the controller on the relay
 * datapath.
 *
 * ebpf_modes is a BUILD fact, deliberately orthogonal to those runtime
 * probes: the same binary flips ebpf between users/kernels, while the mode
 * set changes only with the binary (an ebpf=1 build with pre-correction
 * window semantics is indistinguishable from a correct one without it).
 * A mode is usable iff ebpf=1 AND its token is listed; a build that does
 * not emit the field at all predates it and gets legacy treatment. An
 * incompatible mode revision renames its token (window -> window2) rather
 * than versioning it in place.
 */
static int cmd_capabilities(hypervisor_conn_t *conn, int argc, char *argv[])
{
    hypervisor_send_reply(conn, HSC_INFO_OK, 1,
                          "netem=delay,jitter,loss,dup,corrupt,rate,reorder,gemodel,dist,seed,limit;"
                          "ebpf=%d;cbpf=%d;ebpf_modes=nth,quota,window,flow",
                          tc_ebpf_supported(), tc_cbpf_capable());
    return 0;
}

/* --------------------------------------------------------------------------
 * Command table + module registration
 * -------------------------------------------------------------------------- */

static hypervisor_cmd_t tc_cmd_array[] = {
   /* netem set <if> [delay <ms>] [jitter <ms>] [loss <pct> [correl <pct>]]
    *              [loss gemodel <p> [<r> [<1-h>]]] [dup <pct> [correl <pct>]]
    *              [corrupt <pct>] [reorder <pct> [correl <pct>] [gap <n>]]
    *              [rate <bw>] [limit <pkts>]
    *              [distribution uniform|normal|pareto|paretonormal] [seed <u32>] */
   { "netem", 4, 32, cmd_netem, NULL },
   /* bpf_drop add <if> <prio> "<expr>" (prio 10-99) / bpf_drop flush <if> */
   { "bpf_drop", 2, 4, cmd_bpf_drop, NULL },
   /* eBPF stateful impairment, one shared program at clsact prio 1 */
   { "nth_drop", 2, 2, cmd_nth_drop, NULL },
   { "quota_drop", 2, 3, cmd_quota_drop, NULL },
   /* window: <if> <start_ms> <outage_ms> <pct> [<period_ms> [<jitter_ms>]]
    * (4-6 args) or <if> off (2) */
   { "window_drop", 2, 6, cmd_window_drop, NULL },
   { "flow_drop", 2, 3, cmd_flow_drop, NULL },
   { "reset", 1, 1, cmd_reset, NULL },
   { "capabilities", 0, 0, cmd_capabilities, NULL },
   { NULL, -1, -1, NULL, NULL },
};

/* Hypervisor tc initialization */
int hypervisor_tc_init(void)
{
   hypervisor_module_t *module;

   module = hypervisor_register_module("tc", NULL);
   assert(module != NULL);

   hypervisor_register_cmd_array(module, tc_cmd_array);
   return(0);
}
