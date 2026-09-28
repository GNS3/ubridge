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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>

#include "netlink/nl.h"
#include "hypervisor.h"
#include "hypervisor_tc.h"
#include "tc_netem_dist.h"

/* Default netem fifo limit (packets). */
#define NETEM_LIMIT_DEFAULT 1000

/* Highest accepted rate: 100gbit (in bits/s). */
#define NETEM_RATE_MAX_BPS 100000000000ULL

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

/* Remove the root qdisc of <ifname>. Returns 0 or -errno. */
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

/*
 * tc capabilities — what this build supports, so the controller can hide
 * filter types the local kernel/ubridge cannot run (and fall back to the
 * relay datapath). ebpf/cbpf flip to 1 when the clsact classifier commands
 * (spec parts B/C) land; an old ubridge without this command at all keeps
 * the controller on the relay datapath.
 */
static int cmd_capabilities(hypervisor_conn_t *conn, int argc, char *argv[])
{
    hypervisor_send_reply(conn, HSC_INFO_OK, 1,
                          "netem=delay,jitter,loss,dup,corrupt,rate,reorder,gemodel,dist,seed,limit;ebpf=0;cbpf=0");
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
