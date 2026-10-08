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
 * vxlan module — kernel VXLAN device management via rtnetlink.
 *
 * The vxlan netdev is the kernel's own encapsulation endpoint: once it
 * exists, the dataplane needs nothing from us (AF_PACKET on the device via
 * bridge add_nio_linux_raw, or enslave it as a bridge port with brctl
 * addif). This module owns only the device lifecycle, mirroring how brctl
 * owns bridges: create / delete / show, all through RTM_*LINK messages
 * with IFLA_INFO_KIND "vxlan" — no ioctls, no fork+exec of iproute2.
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include "netlink/nl.h"
#include "hypervisor.h"
#include "hypervisor_vxlan.h"
#include "hypervisor_link.h"

/* 24-bit VNI; 0 is reserved (means "unspecified" in the header) */
#define VXLAN_VNI_MAX 0xFFFFFFu

/* -EPROTO marks "device exists but is not a vxlan" back to cmd_show, which
 * words it as a kind mismatch rather than a netlink failure. */
#define VXLAN_ERR_WRONG_KIND (-EPROTO)

/*
 * Parsed view of one vxlan device: what `create` may set, and what `show`
 * reports. Addresses are kept in network order as inet_pton produced them.
 */
struct vxlan_params {
    unsigned int vni;
    int has_vni;

    /* remote (unicast) or group (multicast): both ride IFLA_VXLAN_GROUP in
     * the kernel; the address class decides the mode. Mutual exclusion is
     * enforced at parse time, not left to the kernel. */
    int has_remote, remote_is6;
    struct in_addr remote4;
    struct in6_addr remote6;
    int has_group, group_is6;
    struct in_addr group4;
    struct in6_addr group6;

    char dev[IFNAMSIZ];      /* underlying device, "" if none */
    int has_dev;

    unsigned int dstport;    /* host order */
    int has_dstport;

    unsigned int ttl;        /* 0 = auto (kernel default) */
    int has_ttl;

    int learning;            /* on=1/off=0 */
    int has_learning;
};

/*
 * Parse an IPv4 or IPv6 literal. Sets *is6 and the corresponding address.
 * Returns 0 on success, -1 if the string is neither.
 */
static int parse_addr(const char *s, int *is6, struct in_addr *a4, struct in6_addr *a6)
{
    if (inet_pton(AF_INET, s, a4) == 1) {
        *is6 = 0;
        return 0;
    }
    if (inet_pton(AF_INET6, s, a6) == 1) {
        *is6 = 1;
        return 0;
    }
    return -1;
}

/* Multicast test for either family (no libc helper covers both). */
static int addr_is_mcast(int is6, const struct in_addr *a4, const struct in6_addr *a6)
{
    if (is6)
        return a6->s6_addr[0] == 0xff;
    return IN_MULTICAST(ntohl(a4->s_addr));
}

/*
 * Parse one "key=value" argument into params.
 * Returns 0 on success, -1 on an unknown key or a bad value.
 */
static int vxlan_parse_kv(struct vxlan_params *p, const char *kv)
{
    char buf[128];
    char *eq, *key, *val;
    char *end;
    unsigned long v;

    if (strlen(kv) >= sizeof(buf))
        return -1;
    strcpy(buf, kv);

    eq = strchr(buf, '=');
    if (eq == NULL || eq == buf || eq[1] == '\0')
        return -1;
    *eq = '\0';
    key = buf;
    val = eq + 1;

    if (!strcmp(key, "remote")) {
        if (parse_addr(val, &p->remote_is6, &p->remote4, &p->remote6) < 0)
            return -1;
        if (addr_is_mcast(p->remote_is6, &p->remote4, &p->remote6))
            return -1;  /* a multicast address is group=, not remote= */
        p->has_remote = 1;
        return 0;
    }
    if (!strcmp(key, "group")) {
        if (parse_addr(val, &p->group_is6, &p->group4, &p->group6) < 0)
            return -1;
        if (!addr_is_mcast(p->group_is6, &p->group4, &p->group6))
            return -1;  /* a unicast address is remote=, not group= */
        p->has_group = 1;
        return 0;
    }
    if (!strcmp(key, "dev")) {
        if (strlen(val) >= IFNAMSIZ || val[0] == '\0')
            return -1;
        strcpy(p->dev, val);
        p->has_dev = 1;
        return 0;
    }
    if (!strcmp(key, "dstport")) {
        v = strtoul(val, &end, 10);
        if (*end != '\0' || end == val || v < 1 || v > 65535)
            return -1;
        p->dstport = (unsigned int)v;
        p->has_dstport = 1;
        return 0;
    }
    if (!strcmp(key, "ttl")) {
        v = strtoul(val, &end, 10);
        if (*end != '\0' || end == val || v > 255)
            return -1;
        p->ttl = (unsigned int)v;
        p->has_ttl = 1;
        return 0;
    }
    if (!strcmp(key, "learning")) {
        if (!strcasecmp(val, "on"))
            p->learning = 1;
        else if (!strcasecmp(val, "off"))
            p->learning = 0;
        else
            return -1;
        p->has_learning = 1;
        return 0;
    }
    return -1;
}

/*
 * Create a kernel vxlan device (RTM_NEWLINK + IFLA_INFO_KIND "vxlan").
 * NLM_F_EXCL makes a duplicate name fail with -EEXIST, same contract as
 * brctl create. Returns 0 on success or a negative errno on failure
 * (NOT -1).
 */
static int vxlan_add(const char *name, const struct vxlan_params *p)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *linkinfo, *infodata;
    int ret, dev_ifindex = 0;

    if (p->has_dev) {
        dev_ifindex = if_nametoindex(p->dev);
        if (dev_ifindex == 0)
            return -ENODEV;
    }

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0)
        return ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg) {
        netlink_close(&nlh);
        return -ENOMEM;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;

    msg->nlmsghdr.nlmsg_type = RTM_NEWLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    nla_put_string(msg, IFLA_IFNAME, name);
    linkinfo = nla_begin_nested(msg, IFLA_LINKINFO);
    nla_put_string(msg, IFLA_INFO_KIND, "vxlan");
    infodata = nla_begin_nested(msg, IFLA_INFO_DATA);

    nla_put_u32(msg, IFLA_VXLAN_ID, (int)p->vni);

    /* remote=/group= both land in IFLA_VXLAN(_6) GROUP: the kernel picks
     * unicast vs multicast mode from the address class, and there is no
     * separate REMOTE attribute (cf. linux/if_link.h: "group or remote
     * address"). */
    if (p->has_remote) {
        if (p->remote_is6)
            nla_put_buffer(msg, IFLA_VXLAN_GROUP6, &p->remote6, sizeof(p->remote6));
        else
            nla_put_buffer(msg, IFLA_VXLAN_GROUP, &p->remote4, sizeof(p->remote4));
    }
    if (p->has_group) {
        if (p->group_is6)
            nla_put_buffer(msg, IFLA_VXLAN_GROUP6, &p->group6, sizeof(p->group6));
        else
            nla_put_buffer(msg, IFLA_VXLAN_GROUP, &p->group4, sizeof(p->group4));
    }

    if (p->has_dev)
        nla_put_u32(msg, IFLA_VXLAN_LINK, dev_ifindex);

    /* The kernel reads this attribute as a __be16 (like iproute2 writes
     * it), hence the htons. Left unset it defaults to 8472 — the kernel's
     * pre-IANA value, NOT 4789; see doc/vxlan.md. */
    if (p->has_dstport)
        nla_put_u16(msg, IFLA_VXLAN_PORT, (unsigned short)htons((unsigned short)p->dstport));

    if (p->has_ttl)
        nla_put_u32(msg, IFLA_VXLAN_TTL, (int)p->ttl);

    if (p->has_learning)
        nla_put_u8(msg, IFLA_VXLAN_LEARNING, (unsigned char)p->learning);

    nla_end_nested(msg, infodata);
    nla_end_nested(msg, linkinfo);

    ret = nl_xact(&nlh, msg);
    netlink_close(&nlh);
    return ret;
}

/*
 * Delete a vxlan device (RTM_DELLINK by ifindex).
 *
 * Unlike brctl delete there is no in-use refusal: a vxlan endpoint is not
 * shared state. If it is currently a bridge port the kernel detaches it on
 * unregister (the port disappears from the bridge cleanly); the tunnel
 * going away is the point of the command.
 * Returns 0 on success or a negative errno on failure (NOT -1).
 */
static int vxlan_del(const char *name)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL;
    struct ifinfomsg *ifi;
    int ret, ifindex;

    ifindex = if_nametoindex(name);
    if (ifindex == 0)
        return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0)
        return ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg) {
        netlink_close(&nlh);
        return -ENOMEM;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_DELLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    ret = nl_xact(&nlh, msg);
    netlink_close(&nlh);
    return ret;
}

/*
 * Walk IFLA_LINKINFO of an RTM_GETLINK reply; when the device is a vxlan,
 * fill params (show defaults applied for absent attributes) and flags.
 * Returns 0 on success, -ENODEV if the device does not exist,
 * VXLAN_ERR_WRONG_KIND if it is not a vxlan, or a negative errno from the
 * netlink exchange.
 */
static int vxlan_get_info(const char *name, struct vxlan_params *p, unsigned int *flags)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    int ret, ifindex, attrlen, found_vxlan = 0;

    ifindex = if_nametoindex(name);
    if (ifindex == 0)
        return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0)
        return ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        return -ENOMEM;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_GETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    ret = netlink_transaction(&nlh, msg, reply);
    if (ret < 0) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        return ret;
    }

    memset(p, 0, sizeof(*p));
    ifi = (struct ifinfomsg *)nlmsg_data(reply);
    *flags = ifi->ifi_flags;

    attrlen = reply->nlmsghdr.nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
    struct rtattr *rta = IFLA_RTA(ifi);
    while (RTA_OK(rta, attrlen)) {
        if (rta->rta_type == IFLA_LINKINFO) {
            int inner_len = RTA_PAYLOAD(rta);
            struct rtattr *sub = (struct rtattr *)RTA_DATA(rta);
            while (RTA_OK(sub, inner_len)) {
                if (sub->rta_type == IFLA_INFO_KIND) {
                    if (!strncmp((char *)RTA_DATA(sub), "vxlan", RTA_PAYLOAD(sub)))
                        found_vxlan = 1;
                } else if (sub->rta_type == IFLA_INFO_DATA && found_vxlan) {
                    int data_len = RTA_PAYLOAD(sub);
                    struct rtattr *va = (struct rtattr *)RTA_DATA(sub);
                    while (RTA_OK(va, data_len)) {
                        switch (va->rta_type) {
                        case IFLA_VXLAN_ID: {
                            unsigned int id;
                            memcpy(&id, RTA_DATA(va), sizeof(id));
                            p->vni = id;
                            p->has_vni = 1;
                            break;
                        }
                        case IFLA_VXLAN_GROUP:
                            memcpy(&p->group4, RTA_DATA(va), sizeof(p->group4));
                            p->group_is6 = 0;
                            if (addr_is_mcast(0, &p->group4, &p->remote6)) {
                                p->has_group = 1;
                            } else {
                                /* kernel packs a unicast remote into the
                                 * same attribute; relabel for display */
                                p->remote4 = p->group4;
                                p->remote_is6 = 0;
                                p->has_remote = 1;
                            }
                            break;
                        case IFLA_VXLAN_GROUP6:
                            memcpy(&p->group6, RTA_DATA(va), sizeof(p->group6));
                            p->group_is6 = 1;
                            if (addr_is_mcast(1, &p->group4, &p->group6)) {
                                p->has_group = 1;
                            } else {
                                p->remote6 = p->group6;
                                p->remote_is6 = 1;
                                p->has_remote = 1;
                            }
                            break;
                        case IFLA_VXLAN_PORT: {
                            unsigned short port_n;
                            memcpy(&port_n, RTA_DATA(va), sizeof(port_n));
                            p->dstport = ntohs(port_n);
                            p->has_dstport = 1;
                            break;
                        }
                        case IFLA_VXLAN_LINK: {
                            unsigned int dev_index;
                            memcpy(&dev_index, RTA_DATA(va), sizeof(dev_index));
                            if (dev_index && if_indextoname(dev_index, p->dev))
                                p->has_dev = 1;
                            break;
                        }
                        case IFLA_VXLAN_TTL: {
                            unsigned int ttl;
                            memcpy(&ttl, RTA_DATA(va), sizeof(ttl));
                            p->ttl = ttl;
                            p->has_ttl = 1;
                            break;
                        }
                        case IFLA_VXLAN_LEARNING: {
                            unsigned char learning;
                            memcpy(&learning, RTA_DATA(va), 1);
                            p->learning = learning ? 1 : 0;
                            p->has_learning = 1;
                            break;
                        }
                        }
                        va = RTA_NEXT(va, data_len);
                    }
                }
                sub = RTA_NEXT(sub, inner_len);
            }
        }
        rta = RTA_NEXT(rta, attrlen);
    }

    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);

    return found_vxlan ? 0 : VXLAN_ERR_WRONG_KIND;
}

/* Append "key value"-shaped fields to a show line; tracks the cursor so the
 * caller stays a single snprintf-mistake away from truncation, not a bug. */
static char *appendf(char *cur, char *end, const char *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(cur, end - cur, fmt, ap);
    va_end(ap);
    if (n < 0 || n >= end - cur)
        return cur;  /* truncated or errored: keep what fits, stop growing */
    return cur + n;
}

/* vxlan create <name> <vni> [key=value ...] */
static int cmd_create(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *name = argv[0];
    char *end;
    unsigned long vni;
    struct vxlan_params p;
    int i, err;

    vni = strtoul(argv[1], &end, 10);
    if (*end != '\0' || end == argv[1] || vni < 1 || vni > VXLAN_VNI_MAX) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "Invalid VNI %s (expected 1-%u)", argv[1], VXLAN_VNI_MAX);
        return -1;
    }

    /* The name goes straight into the RTM_NEWLINK message; the kernel
     * accepts at most IFNAMSIZ-1 chars, and anything past the fixed message
     * buffer used to overflow it (ASan: heap-buffer-overflow in nla_put). */
    if (strlen(name) >= IFNAMSIZ) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not create vxlan %s: %s", name,
                              strerror(ENAMETOOLONG));
        return -1;
    }

    memset(&p, 0, sizeof(p));
    p.vni = (unsigned int)vni;
    p.has_vni = 1;

    for (i = 2; i < argc; i++) {
        if (vxlan_parse_kv(&p, argv[i]) < 0) {
            hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                                  "Invalid vxlan parameter %s", argv[i]);
            return -1;
        }
    }

    if (p.has_remote && p.has_group) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "remote= and group= are mutually exclusive");
        return -1;
    }

    /* The kernel refuses a multicast group with no underlying device (the
     * IGMP join needs a link to ride on); iproute2 enforces the same rule
     * client-side. Word it here rather than surfacing the kernel's opaque
     * "Attribute failed policy validation". */
    if (p.has_group && !p.has_dev) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "group= requires dev= to be specified");
        return -1;
    }

    /* Fail with the dev named before touching netlink: the kernel's own
     * -ENODEV would render as a bare "No such device" with no hint which
     * of the two devices (the vxlan or dev=) was missing. */
    if (p.has_dev && if_nametoindex(p.dev) == 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "dev %s does not exist", p.dev);
        return -1;
    }

    err = vxlan_add(name, &p);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not create vxlan %s: %s", name, strerror(-err));
        return -1;
    }

    /* A vxlan device is a host-side data-plane anchor (doc/vxlan.md's own
     * example enslaves it to a fabric bridge), so it gets the l2-only
     * hardening every other creator applies — best-effort: a failure logs
     * and never fails the creation. */
    if ((err = link_harden_l2only(name)) < 0)
        fprintf(stderr, "vxlan create: %s: L2-only hardening failed (%s)\n",
                name, strerror(-err));

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "VXLAN %s created (VNI %lu)", name, vni);
    return 0;
}

/* vxlan delete <name> */
static int cmd_delete(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *name = argv[0];
    int err = vxlan_del(name);

    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                              "Could not delete vxlan %s: %s", name, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "VXLAN %s deleted", name);
    return 0;
}

/* vxlan show <name> */
static int cmd_show(hypervisor_conn_t *conn, int argc, char *argv[])
{
    const char *name = argv[0];
    struct vxlan_params p;
    unsigned int flags;
    char line[256], *cur = line, *end = line + sizeof(line);
    char addr[INET6_ADDRSTRLEN];
    int err;

    err = vxlan_get_info(name, &p, &flags);
    if (err == -ENODEV) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "VXLAN %s does not exist", name);
        return -1;
    }
    if (err == VXLAN_ERR_WRONG_KIND) {
        hypervisor_send_reply(conn, HSC_ERR_BAD_OBJ, 1, "%s is not a vxlan device", name);
        return -1;
    }
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not query vxlan %s: %s", name, strerror(-err));
        return -1;
    }

    cur = appendf(cur, end, "%s", name);
    if (p.has_vni)
        cur = appendf(cur, end, " vni %u", p.vni);
    if (p.has_remote) {
        inet_ntop(p.remote_is6 ? AF_INET6 : AF_INET,
                  p.remote_is6 ? (void *)&p.remote6 : (void *)&p.remote4,
                  addr, sizeof(addr));
        cur = appendf(cur, end, " remote %s", addr);
    }
    if (p.has_group) {
        inet_ntop(p.group_is6 ? AF_INET6 : AF_INET,
                  p.group_is6 ? (void *)&p.group6 : (void *)&p.group4,
                  addr, sizeof(addr));
        cur = appendf(cur, end, " group %s", addr);
    }
    if (p.has_dev)
        cur = appendf(cur, end, " dev %s", p.dev);
    if (p.has_dstport)
        cur = appendf(cur, end, " dstport %u", p.dstport);
    /* ttl 0 is the kernel's "auto" (inherit from the inner packet) */
    if (p.has_ttl && p.ttl > 0)
        cur = appendf(cur, end, " ttl %u", p.ttl);
    else
        cur = appendf(cur, end, " ttl auto");
    cur = appendf(cur, end, " learning %s", (p.has_learning && !p.learning) ? "off" : "on");
    if (flags & IFF_UP)
        cur = appendf(cur, end, " UP");
    if (flags & IFF_RUNNING)
        cur = appendf(cur, end, " RUNNING");

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s", line);
    return 0;
}

/* Command table */
static hypervisor_cmd_t vxlan_cmd_array[] = {
    { "create", 2, 10, cmd_create, NULL },
    { "delete", 1, 1,  cmd_delete, NULL },
    { "show",   1, 1,  cmd_show,   NULL },
    { NULL, -1, -1, NULL, NULL },
};

/* Hypervisor vxlan initialization */
int hypervisor_vxlan_init(void)
{
    hypervisor_module_t *module;

    module = hypervisor_register_module("vxlan", NULL);
    assert(module != NULL);

    hypervisor_register_cmd_array(module, vxlan_cmd_array);
    return(0);
}
