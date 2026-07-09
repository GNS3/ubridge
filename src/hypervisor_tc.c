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
 * it. This provides the kernel-side link impairment (delay/jitter/loss/dup)
 * that the kernel data plane needs: once frames flow TAP -> kernel bridge ->
 * TAP (not through ubridge's user-space NIO relay), the bridge module's
 * user-space packet filters no longer see the traffic, so the impairment has
 * to live in the kernel qdisc.
 *
 * netem ABI (per net/sched/sch_netem.c netem_change): TCA_OPTIONS is a nested
 * attribute whose payload begins with a raw struct tc_netem_qopt (mandatory),
 * optionally followed by nested TCA_NETEM_* attributes. delay/jitter are sent
 * as TCA_NETEM_LATENCY64/JITTER64 (s64 nanoseconds), which override the
 * legacy u32 struct fields and avoid the PSCHED_TICKS unit ambiguity; loss and
 * duplicate go in the struct fields as a probability scaled by 2^32.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>

#include "netlink/nl.h"
#include "hypervisor.h"
#include "hypervisor_tc.h"

/* Default netem fifo limit (packets). */
#define NETEM_LIMIT_DEFAULT 1000

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

/* Attach/replace a netem qdisc at the root of <ifname>. Returns 0 or -errno. */
static int tc_netem_replace(const char *ifname,
                            int has_delay, double delay_ms,
                            int has_jitter, double jitter_ms,
                            int has_loss, unsigned int loss_pct,
                            int has_dup, unsigned int dup_pct,
                            int has_corrupt, unsigned int corrupt_pct)
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
    tcm->tcm_parent = TC_H_ROOT;   /* root qdisc */

    msg->nlmsghdr.nlmsg_type = RTM_NEWQDISC;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    nla_put_string(msg, TCA_KIND, "netem");

    /* TCA_OPTIONS = raw struct tc_netem_qopt (mandatory prefix) + nested attrs */
    opts = nla_begin_nested(msg, TCA_OPTIONS);
    opts->rta_type |= NLA_F_NESTED;

    memset(&qopt, 0, sizeof(qopt));
    qopt.limit = NETEM_LIMIT_DEFAULT;
    qopt.loss = has_loss ? netem_percent(loss_pct) : 0;
    qopt.duplicate = has_dup ? netem_percent(dup_pct) : 0;
    /* latency/jitter left 0; overridden unambiguously (ns) by *64 below */
    memcpy(NLMSG_TAIL(&msg->nlmsghdr), &qopt, sizeof(qopt));
    msg->nlmsghdr.nlmsg_len += sizeof(qopt);

    if (has_delay) {
        v64 = (long long)(delay_ms * 1000000.0);   /* ms -> ns */
        nla_put_buffer(msg, TCA_NETEM_LATENCY64, &v64, sizeof(v64));
    }
    if (has_jitter) {
        v64 = (long long)(jitter_ms * 1000000.0);  /* ms -> ns */
        nla_put_buffer(msg, TCA_NETEM_JITTER64, &v64, sizeof(v64));
    }
    if (has_corrupt) {
        /* TCA_NETEM_CORRUPT: fixed-size struct {probability, correlation},
         * probability encoded like loss/dup (p * 2^32); correlation 0. */
        struct tc_netem_corrupt c;
        memset(&c, 0, sizeof(c));
        c.probability = netem_percent(corrupt_pct);
        nla_put_buffer(msg, TCA_NETEM_CORRUPT, &c, sizeof(c));
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

/* tc netem set <if> [delay <ms>] [jitter <ms>] [loss <%>] [dup <%>] [corrupt <%>] */
static int cmd_netem(hypervisor_conn_t *conn, int argc, char *argv[])
{
    const char *ifname;
    int has_delay = 0, has_jitter = 0, has_loss = 0, has_dup = 0, has_corrupt = 0, any = 0;
    double delay_ms = 0.0, jitter_ms = 0.0;
    unsigned int loss_pct = 0, dup_pct = 0, corrupt_pct = 0;
    int i, err;

    if (strcmp(argv[0], "set") != 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "unknown netem action '%s' (expected 'set')", argv[0]);
        return -1;
    }

    ifname = argv[1];

    /* keyword/value pairs from argv[2] on */
    for (i = 2; i + 1 < argc; i += 2) {
        char *kw = argv[i], *val = argv[i + 1], *end;

        if (!strcmp(kw, "delay") || !strcmp(kw, "jitter")) {
            double ms = strtod(val, &end);
            if (end == val || *end != '\0' || ms < 0) {
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid %s value '%s'", kw, val);
                return -1;
            }
            if (kw[0] == 'd') { delay_ms = ms; has_delay = 1; }
            else { jitter_ms = ms; has_jitter = 1; }
            any = 1;
        } else if (!strcmp(kw, "loss") || !strcmp(kw, "dup") || !strcmp(kw, "corrupt")) {
            long p = strtol(val, &end, 10);
            if (end == val || *end != '\0' || p < 0 || p > 100) {
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid %s percent '%s' (0-100)", kw, val);
                return -1;
            }
            if (!strcmp(kw, "loss")) { loss_pct = (unsigned int)p; has_loss = 1; }
            else if (!strcmp(kw, "dup")) { dup_pct = (unsigned int)p; has_dup = 1; }
            else { corrupt_pct = (unsigned int)p; has_corrupt = 1; }
            any = 1;
        } else {
            hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "unknown netem option '%s'", kw);
            return -1;
        }
    }

    if (i < argc) {
        hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "option '%s' missing its value", argv[i]);
        return -1;
    }

    if (!any) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "no impairment specified (use delay/jitter/loss/dup/corrupt)");
        return -1;
    }

    err = tc_netem_replace(ifname, has_delay, delay_ms, has_jitter, jitter_ms,
                           has_loss, loss_pct, has_dup, dup_pct,
                           has_corrupt, corrupt_pct);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set netem on %s: %s", ifname, strerror(-err));
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
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "Could not reset qdisc on %s: %s", ifname, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "qdisc reset on %s", ifname);
    return 0;
}

/* --------------------------------------------------------------------------
 * Command table + module registration
 * -------------------------------------------------------------------------- */

static hypervisor_cmd_t tc_cmd_array[] = {
   /* netem set <if> [delay <ms>] [jitter <ms>] [loss <%>] [dup <%>] [corrupt <%>] */
   { "netem", 4, 12, cmd_netem, NULL },
   { "reset", 1, 1, cmd_reset, NULL },
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
