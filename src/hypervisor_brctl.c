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

#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include "netlink/nl.h"
#include "ubridge.h"
#include "hypervisor.h"
#include "hypervisor_brctl.h"


/*
 * Create a Linux bridge device (RTM_NEWLINK + IFLA_INFO_KIND "bridge").
 * Returns 0 on success or a negative errno on failure (NOT -1).
 */
static int br_addbr(const char *bridge)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *linkinfo;
    int ret;

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

    msg->nlmsghdr.nlmsg_type = RTM_NEWLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    nla_put_string(msg, IFLA_IFNAME, bridge);
    linkinfo = nla_begin_nested(msg, IFLA_LINKINFO);
    nla_put_string(msg, IFLA_INFO_KIND, "bridge");
    nla_end_nested(msg, linkinfo);

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/*
 * Delete a Linux bridge device (RTM_DELLINK via if_nametoindex).
 * Returns 0 on success or a negative errno on failure (NOT -1).
 */
static int br_delbr(const char *bridge)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    int ret, ifindex;

    ifindex = if_nametoindex(bridge);
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

    msg->nlmsghdr.nlmsg_type = RTM_DELLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/*
 * Enslave a port interface to a bridge (RTM_SETLINK + IFLA_MASTER) and
 * bring the port up (RTM_SETLINK + IFF_UP), matching the legacy ioctl
 * implementation which set SIOCSIFFLAGS|IFF_UP after adding the port.
 * Returns 0 on success or a negative errno on failure (NOT -1).
 */
static int br_enslave_if(const char *bridge, const char *port)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    int ret, br_ifindex, port_ifindex;

    br_ifindex = if_nametoindex(bridge);
    port_ifindex = if_nametoindex(port);
    if (br_ifindex == 0 || port_ifindex == 0)
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

    /* Step 1 – enslave the port to the bridge */
    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = port_ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_SETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    nla_put_u32(msg, IFLA_MASTER, br_ifindex);

    ret = netlink_transaction(&nlh, msg, reply);
    if (ret < 0) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        return ret;
    }

    /* Step 2 – bring the port up (backward compat with the ioctl path) */
    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = port_ifindex;
    ifi->ifi_change |= IFF_UP;
    ifi->ifi_flags |= IFF_UP;

    msg->nlmsghdr.nlmsg_type = RTM_SETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/*
 * Release a port from its bridge (RTM_SETLINK + IFLA_MASTER = 0).
 * Returns 0 on success or a negative errno on failure (NOT -1).
 */
static int br_release_if(const char *port)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    int ret, port_ifindex;

    port_ifindex = if_nametoindex(port);
    if (port_ifindex == 0)
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
    ifi->ifi_index = port_ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_SETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    nla_put_u32(msg, IFLA_MASTER, 0);

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/*
 * Parse a "ip/prefixlen" string (e.g. "172.31.1.1/24") into an address and
 * the corresponding netmask. The input string is left untouched.
 * Returns 0 on success, -1 on error (with errno = EINVAL).
 */
static int parse_cidr(const char *cidr, struct in_addr *ip, struct in_addr *mask)
{
    char buf[64];
    char *slash, *end;
    long prefix;

    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    slash = strchr(buf, '/');
    if (slash == NULL) {
        errno = EINVAL;
        return -1;
    }
    *slash = '\0';

    prefix = strtol(slash + 1, &end, 10);
    if (*end != '\0' || prefix < 0 || prefix > 32) {
        errno = EINVAL;
        return -1;
    }

    if (inet_pton(AF_INET, buf, ip) != 1) {
        errno = EINVAL;
        return -1;
    }

    /* Convert the prefix length into a network-order netmask */
    mask->s_addr = prefix ? htonl(~((1U << (32 - prefix)) - 1)) : 0;
    return 0;
}

/*
 * Set an IPv4 address on an interface and bring it up (RTM_NEWADDR +
 * RTM_SETLINK IFF_UP).
 * Returns 0 on success or a negative errno on failure (NOT -1).
 */
static int br_set_address(const char *bridge, struct in_addr ip, struct in_addr mask)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL, *msg2 = NULL;
    struct ifaddrmsg *ifa;
    struct ifinfomsg *ifi;
    int ret, ifindex;

    /* Convert netmask back to prefix length */
    unsigned int m = ntohl(mask.s_addr);
    int prefix = 0;
    while (m & 0x80000000) { prefix++; m <<= 1; }

    ifindex = if_nametoindex(bridge);
    if (ifindex == 0)
        return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0)
        return ret;

    /* Step 1 – add/replace IPv4 address (RTM_NEWADDR) */
    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        return -ENOMEM;
    }

    ifa = (struct ifaddrmsg *)nlmsg_data(msg);
    memset(ifa, 0, sizeof(*ifa));
    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = prefix;
    ifa->ifa_index = ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_NEWADDR;
    msg->nlmsghdr.nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE | NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

    nla_put_buffer(msg, IFA_LOCAL, &ip, sizeof(ip));
    nla_put_buffer(msg, IFA_ADDRESS, &ip, sizeof(ip));

    ret = netlink_transaction(&nlh, msg, reply);
    if (ret < 0) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        return ret;
    }

    /* Step 2 – bring the interface up (RTM_SETLINK IFF_UP) */
    msg2 = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg2) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        return -ENOMEM;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg2);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;
    ifi->ifi_change |= IFF_UP;
    ifi->ifi_flags |= IFF_UP;

    msg2->nlmsghdr.nlmsg_type = RTM_SETLINK;
    msg2->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg2->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    ret = netlink_transaction(&nlh, msg2, reply);
    nlmsg_free(msg2);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/*
 * Generic runtime setter for a u32 bridge attribute (RTM_SETLINK +
 * IFLA_LINKINFO{IFLA_INFO_KIND="bridge", IFLA_INFO_DATA{attr}}).
 * Returns 0 on success or a negative errno on failure (NOT -1).
 */
static int br_set_bridge_attr(const char *bridge, int attr, unsigned int val)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *linkinfo, *infodata;
    int ret, ifindex;

    ifindex = if_nametoindex(bridge);
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

    msg->nlmsghdr.nlmsg_type = RTM_NEWLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    linkinfo = nla_begin_nested(msg, IFLA_LINKINFO);
    nla_put_string(msg, IFLA_INFO_KIND, "bridge");
    infodata = nla_begin_nested(msg, IFLA_INFO_DATA);
    nla_put_u32(msg, attr, val);
    nla_end_nested(msg, infodata);
    nla_end_nested(msg, linkinfo);

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/*
 * Generic runtime setter for a u16 bridge attribute (same as above but u16).
 * Returns 0 on success or a negative errno on failure (NOT -1).
 */
static int br_set_bridge_attr_u16(const char *bridge, int attr, unsigned short val)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *linkinfo, *infodata;
    int ret, ifindex;

    ifindex = if_nametoindex(bridge);
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

    msg->nlmsghdr.nlmsg_type = RTM_NEWLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    linkinfo = nla_begin_nested(msg, IFLA_LINKINFO);
    nla_put_string(msg, IFLA_INFO_KIND, "bridge");
    infodata = nla_begin_nested(msg, IFLA_INFO_DATA);
    nla_put_u16(msg, attr, val);
    nla_end_nested(msg, infodata);
    nla_end_nested(msg, linkinfo);

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/*
 * Set a time-valued bridge attribute. The kernel stores these in clock_t
 * (USER_HZ units, i.e. centiseconds on x86); the caller passes seconds.
 * Returns 0 on success or a negative errno on failure (NOT -1).
 */
static int br_set_bridge_attr_secs(const char *bridge, int attr, long secs)
{
    long hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0)
        hz = 100;
    return br_set_bridge_attr(bridge, attr, (unsigned int)(secs * hz));
}

/*
 * Generic runtime setter for a u32 bridge PORT attribute (RTM_SETLINK +
 * IFLA_PROTINFO{attr}). Returns 0 on success or a negative errno (NOT -1).
 */
static int br_set_port_attr(const char *port, int attr, unsigned int val)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *protinfo;
    int ret, ifindex;

    ifindex = if_nametoindex(port);
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
    ifi->ifi_family = AF_BRIDGE;
    ifi->ifi_index = ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_SETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    protinfo = nla_begin_nested(msg, IFLA_PROTINFO);
    protinfo->rta_type |= NLA_F_NESTED;
    nla_put_u32(msg, attr, val);
    nla_end_nested(msg, protinfo);

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/* Parse a long integer in [min,max]; returns 0 on success, -1 with errno=EINVAL. */
static int parse_long(const char *s, long min, long max, long *out)
{
    char *end;
    long v = strtol(s, &end, 0);
    if (*end != '\0' || v < min || v > max) {
        errno = EINVAL;
        return -1;
    }
    *out = v;
    return 0;
}

/* Parse an on/off token: 1/0, on/off, yes/no, true/false. Returns 1, 0, or -1. */
static int parse_onoff(const char *s)
{
    if (!strcasecmp(s, "on") || !strcasecmp(s, "yes") || !strcasecmp(s, "true") || !strcmp(s, "1"))
        return 1;
    if (!strcasecmp(s, "off") || !strcasecmp(s, "no") || !strcasecmp(s, "false") || !strcmp(s, "0"))
        return 0;
    return -1;
}

/* brctl create <bridge> */
static int cmd_create(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    int err = br_addbr(bridge);

    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not create bridge %s: %s", bridge, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Bridge %s created", bridge);
    return 0;
}

/* brctl delete <bridge> */
static int cmd_delete(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    int err = br_delbr(bridge);

    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "Could not delete bridge %s: %s", bridge, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Bridge %s deleted", bridge);
    return 0;
}

/* brctl addif <bridge> <interface> — enslave a port to a bridge */
static int cmd_addif(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    char *interface = argv[1];
    int err = br_enslave_if(bridge, interface);

    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not add %s to %s: %s", interface, bridge, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s has been added to bridge %s", interface, bridge);
    return 0;
}

/* brctl delif <bridge> <interface> — release a port from a bridge */
static int cmd_delif(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *interface = argv[1];
    int err = br_release_if(interface);

    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "Could not remove %s from bridge %s: %s", argv[1], argv[0], strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s removed from bridge %s", argv[1], argv[0]);
    return 0;
}

/* brctl addip <bridge> <ip/prefixlen> */
static int cmd_addip(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    char *cidr = argv[1];
    struct in_addr ip, mask;

    if (parse_cidr(cidr, &ip, &mask) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid IP address %s", cidr);
        return -1;
    }

    int err = br_set_address(bridge, ip, mask);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not add IP %s to bridge %s: %s", cidr, bridge, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "IP %s added to bridge %s", cidr, bridge);
    return 0;
}

/* brctl setup <bridge> <ip/prefixlen> (create + addip in one shot) */
static int cmd_setup(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    char *cidr = argv[1];
    struct in_addr ip, mask;

    int err = br_addbr(bridge);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not create bridge %s: %s", bridge, strerror(-err));
        return -1;
    }

    if (parse_cidr(cidr, &ip, &mask) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid IP address %s", cidr);
        return -1;
    }

    err = br_set_address(bridge, ip, mask);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not add IP %s to bridge %s: %s", cidr, bridge, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Bridge %s created with IP %s", bridge, cidr);
    return 0;
}

/* brctl stp <bridge> on|off */
static int cmd_stp(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    int on = parse_onoff(argv[1]);
    if (on < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid STP value %s (expected on/off)", argv[1]);
        return -1;
    }
    int err = br_set_bridge_attr(bridge, IFLA_BR_STP_STATE, (unsigned int)on);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set STP on %s: %s", bridge, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "STP %s on bridge %s", on ? "enabled" : "disabled", bridge);
    return 0;
}

/* brctl setbridgeprio <bridge> <0-65535> */
static int cmd_setbridgeprio(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    long prio;
    if (parse_long(argv[1], 0, 65535, &prio) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid priority %s (expected 0-65535)", argv[1]);
        return -1;
    }
    int err = br_set_bridge_attr(bridge, IFLA_BR_PRIORITY, (unsigned int)prio);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set bridge priority on %s: %s", bridge, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Bridge priority %ld set on %s", prio, bridge);
    return 0;
}

/* brctl setfd <bridge> <secs> — forward delay (2-30s) */
static int cmd_setfd(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    long secs;
    if (parse_long(argv[1], 2, 30, &secs) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid forward delay %s (expected 2-30s)", argv[1]);
        return -1;
    }
    int err = br_set_bridge_attr_secs(bridge, IFLA_BR_FORWARD_DELAY, secs);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set forward delay on %s: %s", bridge, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Forward delay %lds set on %s", secs, bridge);
    return 0;
}

/* brctl sethello <bridge> <secs> — hello time (1-10s) */
static int cmd_sethello(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    long secs;
    if (parse_long(argv[1], 1, 10, &secs) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid hello time %s (expected 1-10s)", argv[1]);
        return -1;
    }
    int err = br_set_bridge_attr_secs(bridge, IFLA_BR_HELLO_TIME, secs);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set hello time on %s: %s", bridge, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Hello time %lds set on %s", secs, bridge);
    return 0;
}

/* brctl setmaxage <bridge> <secs> — max age (6-40s) */
static int cmd_setmaxage(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    long secs;
    if (parse_long(argv[1], 6, 40, &secs) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid max age %s (expected 6-40s)", argv[1]);
        return -1;
    }
    int err = br_set_bridge_attr_secs(bridge, IFLA_BR_MAX_AGE, secs);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set max age on %s: %s", bridge, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Max age %lds set on %s", secs, bridge);
    return 0;
}

/* brctl setageing <bridge> <secs> — MAC ageing time (0 or >=1s; 0 = never age) */
static int cmd_setageing(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    long secs;
    if (parse_long(argv[1], 0, 1000000, &secs) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid ageing time %s", argv[1]);
        return -1;
    }
    int err = br_set_bridge_attr_secs(bridge, IFLA_BR_AGEING_TIME, secs);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set ageing time on %s: %s", bridge, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Ageing time %lds set on %s", secs, bridge);
    return 0;
}

/* brctl vlanfiltering <bridge> on|off */
static int cmd_vlanfiltering(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    int on = parse_onoff(argv[1]);
    if (on < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid value %s (expected on/off)", argv[1]);
        return -1;
    }
    int err = br_set_bridge_attr(bridge, IFLA_BR_VLAN_FILTERING, (unsigned int)on);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set vlan_filtering on %s: %s", bridge, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "VLAN filtering %s on bridge %s", on ? "enabled" : "disabled", bridge);
    return 0;
}

/* brctl setvlanproto <bridge> <0x8100|0x88a8> */
static int cmd_setvlanproto(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    long proto;
    if (parse_long(argv[1], 0, 0xffff, &proto) < 0 ||
        (proto != 0x8100 && proto != 0x88a8)) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid VLAN protocol %s (expected 0x8100 or 0x88a8)", argv[1]);
        return -1;
    }
    int err = br_set_bridge_attr_u16(bridge, IFLA_BR_VLAN_PROTOCOL, (unsigned short)proto);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set VLAN protocol on %s: %s", bridge, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "VLAN protocol 0x%04lx set on %s", proto, bridge);
    return 0;
}

/* brctl mcastsnoop <bridge> on|off */
static int cmd_mcastsnoop(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    int on = parse_onoff(argv[1]);
    if (on < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid value %s (expected on/off)", argv[1]);
        return -1;
    }
    int err = br_set_bridge_attr(bridge, IFLA_BR_MCAST_SNOOPING, (unsigned int)on);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set multicast snooping on %s: %s", bridge, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Multicast snooping %s on bridge %s", on ? "enabled" : "disabled", bridge);
    return 0;
}

/* brctl setgroupfwd <bridge> <mask> — link-local group forwarding mask (0-65535) */
static int cmd_setgroupfwd(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    long mask;
    if (parse_long(argv[1], 0, 65535, &mask) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid group_fwd_mask %s", argv[1]);
        return -1;
    }
    int err = br_set_bridge_attr(bridge, IFLA_BR_GROUP_FWD_MASK, (unsigned int)mask);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set group_fwd_mask on %s: %s", bridge, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "group_fwd_mask 0x%lx set on %s", mask, bridge);
    return 0;
}

/* brctl setportprio <bridge> <port> <0-255> */
static int cmd_setportprio(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *port = argv[1];
    long prio;
    if (parse_long(argv[2], 0, 255, &prio) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid port priority %s (expected 0-255)", argv[2]);
        return -1;
    }
    int err = br_set_port_attr(port, IFLA_BRPORT_PRIORITY, (unsigned int)prio);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set port priority on %s: %s", port, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Port priority %ld set on %s", prio, port);
    return 0;
}

/* brctl setpathcost <bridge> <port> <1-65535> */
static int cmd_setpathcost(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *port = argv[1];
    long cost;
    if (parse_long(argv[2], 1, 65535, &cost) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid path cost %s (expected 1-65535)", argv[2]);
        return -1;
    }
    int err = br_set_port_attr(port, IFLA_BRPORT_COST, (unsigned int)cost);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set path cost on %s: %s", port, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Path cost %ld set on %s", cost, port);
    return 0;
}

/* brctl setportstate <bridge> <port> <0-3> (0=disabled,1=listening,2=learning,3=forwarding) */
static int cmd_setportstate(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *port = argv[1];
    long state;
    if (parse_long(argv[2], 0, 3, &state) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid port state %s (expected 0-3)", argv[2]);
        return -1;
    }
    int err = br_set_port_attr(port, IFLA_BRPORT_STATE, (unsigned int)state);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set port state on %s: %s", port, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Port state %ld set on %s", state, port);
    return 0;
}

/* brctl hairpin <bridge> <port> on|off */
static int cmd_hairpin(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *port = argv[1];
    int on = parse_onoff(argv[2]);
    if (on < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid value %s (expected on/off)", argv[2]);
        return -1;
    }
    int err = br_set_port_attr(port, IFLA_BRPORT_MODE, (unsigned int)(on ? BRIDGE_MODE_HAIRPIN : 0));
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set hairpin mode on %s: %s", port, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Hairpin mode %s on %s", on ? "enabled" : "disabled", port);
    return 0;
}

/* One IPv4 address entry collected from an RTM_GETADDR dump. */
struct br_addr_entry {
    int ifindex;
    struct in_addr addr;
    int prefix;
};

/*
 * Dump every IPv4 address in a single RTM_GETADDR request.
 * NLM_F_REQUEST alone returns EOPNOTSUPP on modern kernels;
 * NLM_F_DUMP is required.  A single recvmsg() datagram may carry
 * several concatenated nlmsg records, so we walk them with
 * NLMSG_OK/NLMSG_NEXT rather than only inspecting the first one.
 *
 * On success returns 0 and stores a malloc'd array in *out (caller
 * frees); *count holds the entry count.  Returns -1 on error.
 */
static int br_dump_addresses(struct br_addr_entry **out, int *count)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifaddrmsg *ifa;
    struct br_addr_entry *entries = NULL;
    int n = 0, cap = 0;
    int ret = -1;

    *out = NULL;
    *count = 0;

    if (netlink_open(&nlh, NETLINK_ROUTE) < 0)
        return -1;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply)
        goto out;

    ifa = (struct ifaddrmsg *)nlmsg_data(msg);
    memset(ifa, 0, sizeof(*ifa));
    ifa->ifa_family = AF_UNSPEC;

    msg->nlmsghdr.nlmsg_type = RTM_GETADDR;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

    if (netlink_send(&nlh, msg) < 0)
        goto out;

    while (1) {
        reply->nlmsghdr.nlmsg_len = NLMSG_ALIGN(NLMSG_GOOD_SIZE);
        int r = netlink_rcv(&nlh, reply);
        if (r <= 0)
            break;

        /* Walk every nlmsg packed into this datagram */
        struct nlmsghdr *nh;
        int len = r;
        for (nh = (struct nlmsghdr *)reply; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE)
                goto done;
            if (nh->nlmsg_type == NLMSG_ERROR)
                goto done;
            if (nh->nlmsg_type != RTM_NEWADDR)
                continue;

            struct ifaddrmsg *ifa_r = (struct ifaddrmsg *)NLMSG_DATA(nh);
            if (ifa_r->ifa_family != AF_INET)
                continue;

            /* Pick the first IFA_LOCAL/IFA_ADDRESS attribute */
            int attrlen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
            struct rtattr *rta = IFA_RTA(ifa_r);
            struct in_addr a;
            int found = 0;
            while (RTA_OK(rta, attrlen)) {
                if (rta->rta_type == IFA_LOCAL || rta->rta_type == IFA_ADDRESS) {
                    memcpy(&a, RTA_DATA(rta), sizeof(a));
                    found = 1;
                    break;
                }
                rta = RTA_NEXT(rta, attrlen);
            }
            if (!found)
                continue;

            if (n == cap) {
                int newcap = cap ? cap * 2 : 8;
                struct br_addr_entry *tmp = realloc(entries, newcap * sizeof(*tmp));
                if (!tmp)
                    goto done;   /* keep whatever was collected so far */
                entries = tmp;
                cap = newcap;
            }
            entries[n].ifindex = ifa_r->ifa_index;
            entries[n].addr = a;
            entries[n].prefix = ifa_r->ifa_prefixlen;
            n++;
        }
    }

done:
    ret = 0;
out:
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    if (ret == 0) {
        *out = entries;
        *count = n;
    } else {
        free(entries);
    }
    return ret;
}

/*
 * Look up the IPv4 address of a single interface from a full address dump.
 * Returns 0 on success, -1 if the interface has no IPv4 address (or on error).
 */
static int br_get_address(int ifindex, struct in_addr *addr, int *prefix)
{
    struct br_addr_entry *entries;
    int count, i;

    if (br_dump_addresses(&entries, &count) < 0)
        return -1;

    for (i = 0; i < count; i++) {
        if (entries[i].ifindex == ifindex) {
            *addr = entries[i].addr;
            *prefix = entries[i].prefix;
            free(entries);
            return 0;
        }
    }

    free(entries);
    return -1;
}

/* brctl show <bridge> — query IP, prefix and flags via netlink */
static int cmd_show(hypervisor_conn_t *conn, int argc, char *argv[])
{
    const char *bridge = argv[0];
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    int ifindex, ret;

    ifindex = if_nametoindex(bridge);
    if (ifindex == 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Bridge %s does not exist", bridge);
        return -1;
    }

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not open netlink socket: %s", strerror(-ret));
        return -1;
    }

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Insufficient memory");
        return -1;
    }

    /* Query interface flags via RTM_GETLINK */
    {
        struct ifinfomsg *ifi = (struct ifinfomsg *)nlmsg_data(msg);
        memset(ifi, 0, sizeof(*ifi));
        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_index = ifindex;

        msg->nlmsghdr.nlmsg_type = RTM_GETLINK;
        msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST;
        msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    }

    char flags_str[64] = "";
    ret = netlink_transaction(&nlh, msg, reply);
    if (ret == 0) {
        struct ifinfomsg *ifi_r = (struct ifinfomsg *)nlmsg_data(reply);
        if (ifi_r->ifi_flags & IFF_UP)      strcat(flags_str, "UP ");
        if (ifi_r->ifi_flags & IFF_RUNNING) strcat(flags_str, "RUNNING ");
    }

    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);

    size_t flen = strlen(flags_str);
    if (flen > 0) flags_str[flen - 1] = '\0';

    /* Query IPv4 address via a fresh handler (avoids reuse issues) */
    struct in_addr ip;
    char ip_str[INET_ADDRSTRLEN] = "";
    int prefix = 0;

    if (br_get_address(ifindex, &ip, &prefix) == 0)
        inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

    if (ip_str[0] && prefix > 0)
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s %s/%d %s", bridge, ip_str, prefix, flags_str);
    else if (ip_str[0])
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s %s %s", bridge, ip_str, flags_str);
    else
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s %s", bridge, flags_str);
    return 0;
}

/* brctl list — enumerate all Linux bridges via RTM_GETLINK dump */
static int cmd_list(hypervisor_conn_t *conn, int argc, char *argv[])
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct br_addr_entry *addrs = NULL;
    int addr_count = 0;
    int ret;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not open netlink socket: %s", strerror(-ret));
        return -1;
    }

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Insufficient memory");
        return -1;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;

    msg->nlmsghdr.nlmsg_type = RTM_GETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    ret = netlink_send(&nlh, msg);
    if (ret < 0) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "netlink send failed: %s", strerror(-ret));
        return -1;
    }

    /* One full address dump, reused for every bridge below */
    br_dump_addresses(&addrs, &addr_count);

    while (1) {
        reply->nlmsghdr.nlmsg_len = NLMSG_ALIGN(NLMSG_GOOD_SIZE);
        ret = netlink_rcv(&nlh, reply);
        if (ret <= 0)
            break;

        /* Walk every nlmsg packed into this datagram */
        struct nlmsghdr *nh;
        int len = ret;
        for (nh = (struct nlmsghdr *)reply; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE)
                goto done;
            if (nh->nlmsg_type == NLMSG_ERROR)
                goto done;
            if (nh->nlmsg_type != RTM_NEWLINK)
                continue;

            struct ifinfomsg *ifi_r = (struct ifinfomsg *)NLMSG_DATA(nh);
            int attrlen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
            struct rtattr *rta = IFLA_RTA(ifi_r);

            char ifname[IFNAMSIZ] = "";
            int is_bridge = 0;
            while (RTA_OK(rta, attrlen)) {
                if (rta->rta_type == IFLA_IFNAME) {
                    strncpy(ifname, (const char *)RTA_DATA(rta), sizeof(ifname) - 1);
                    ifname[sizeof(ifname) - 1] = '\0';
                } else if (rta->rta_type == IFLA_LINKINFO) {
                    struct rtattr *info = (struct rtattr *)RTA_DATA(rta);
                    int info_len = RTA_PAYLOAD(rta);
                    while (RTA_OK(info, info_len)) {
                        if (info->rta_type == IFLA_INFO_KIND &&
                            strcmp((const char *)RTA_DATA(info), "bridge") == 0) {
                            is_bridge = 1;
                            break;
                        }
                        info = RTA_NEXT(info, info_len);
                    }
                }
                rta = RTA_NEXT(rta, attrlen);
            }

            if (is_bridge && ifname[0]) {
                char ip_str[INET_ADDRSTRLEN] = "";
                int prefix = 0, i;

                for (i = 0; i < addr_count; i++) {
                    if (addrs[i].ifindex == (int)ifi_r->ifi_index) {
                        inet_ntop(AF_INET, &addrs[i].addr, ip_str, sizeof(ip_str));
                        prefix = addrs[i].prefix;
                        break;
                    }
                }

                if (ip_str[0])
                    hypervisor_send_reply(conn, HSC_INFO_OK, 0, "%s %s/%d", ifname, ip_str, prefix);
                else
                    hypervisor_send_reply(conn, HSC_INFO_OK, 0, "%s", ifname);
            }
        }
    }

done:
    free(addrs);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "OK");
    return 0;
}


/* brctl commands */
static hypervisor_cmd_t brctl_cmd_array[] = {
   { "addif", 2, 2, cmd_addif, NULL },
   { "create", 1, 1, cmd_create, NULL },
   { "delete", 1, 1, cmd_delete, NULL },
   { "addip", 2, 2, cmd_addip, NULL },
   { "setup", 2, 2, cmd_setup, NULL },
   { "show",  1, 1, cmd_show, NULL },
   { "delif", 2, 2, cmd_delif, NULL },
   { "list",  0, 0, cmd_list, NULL },
   /* bridge-level parameters */
   { "stp", 2, 2, cmd_stp, NULL },
   { "setbridgeprio", 2, 2, cmd_setbridgeprio, NULL },
   { "setfd", 2, 2, cmd_setfd, NULL },
   { "sethello", 2, 2, cmd_sethello, NULL },
   { "setmaxage", 2, 2, cmd_setmaxage, NULL },
   { "setageing", 2, 2, cmd_setageing, NULL },
   { "vlanfiltering", 2, 2, cmd_vlanfiltering, NULL },
   { "setvlanproto", 2, 2, cmd_setvlanproto, NULL },
   { "mcastsnoop", 2, 2, cmd_mcastsnoop, NULL },
   { "setgroupfwd", 2, 2, cmd_setgroupfwd, NULL },
   /* port-level parameters */
   { "setportprio", 3, 3, cmd_setportprio, NULL },
   { "setpathcost", 3, 3, cmd_setpathcost, NULL },
   { "setportstate", 3, 3, cmd_setportstate, NULL },
   { "hairpin", 3, 3, cmd_hairpin, NULL },
   { NULL, -1, -1, NULL, NULL },
};

/* Hypervisor brctl initialization */
int hypervisor_brctl_init(void)
{
   hypervisor_module_t *module;

   module = hypervisor_register_module("brctl", NULL);
   assert(module != NULL);

   hypervisor_register_cmd_array(module, brctl_cmd_array);
   return(0);
}
