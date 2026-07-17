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
#include <linux/if_bridge.h>
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
    ifi->ifi_change = IFF_UP;
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
 * Query a port's current master ifindex via RTM_GETLINK.
 * Returns the master ifindex (0 if the port has no master) or a
 * negative errno on failure.
 */
static int br_get_master(const char *port)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *rta;
    int ret, port_ifindex, attrlen, master = 0;

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

    ifi = (struct ifinfomsg *)nlmsg_data(reply);
    attrlen = reply->nlmsghdr.nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
    rta = IFLA_RTA(ifi);
    while (RTA_OK(rta, attrlen)) {
        if (rta->rta_type == IFLA_MASTER) {
            memcpy(&master, RTA_DATA(rta), sizeof(master));
            break;
        }
        rta = RTA_NEXT(rta, attrlen);
    }

    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return master;
}

/*
 * Verify that a port is currently enslaved to the given bridge.
 * Returns 0 on match, -EINVAL if the port belongs to a different bridge
 * (or none), or a negative errno from the master query.
 */
static int br_check_master(const char *bridge, const char *port)
{
    int bridge_ifindex = if_nametoindex(bridge);
    int master;

    if (bridge_ifindex == 0)
        return -ENODEV;
    master = br_get_master(port);
    if (master < 0)
        return master;
    return (master == bridge_ifindex) ? 0 : -EINVAL;
}

/*
 * Release a port from a specific bridge (RTM_SETLINK + IFLA_MASTER = 0).
 * The port's current master is verified to match the given bridge first,
 * so a port enslaved to a different bridge (or none) is rejected with
 * -EINVAL — matching legacy BRCTL_DEL_IF semantics.
 * Returns 0 on success or a negative errno on failure (NOT -1).
 */
static int br_release_if(const char *bridge, const char *port)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    int ret, port_ifindex;

    /* Verify the port is enslaved to the specified bridge first. */
    ret = br_check_master(bridge, port);
    if (ret < 0)
        return ret;

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
 * Convert a network-order IPv4 netmask into a prefix length by counting
 * its leading 1-bits. Recovers the prefixlen from the mask parse_cidr
 * produces; the mask is always contiguous in the current call paths.
 */
static int netmask_to_prefix(struct in_addr mask)
{
    unsigned int m = ntohl(mask.s_addr);
    int prefix = 0;
    while (m & 0x80000000) { prefix++; m <<= 1; }
    return prefix;
}

/*
 * Parse a "ip/prefixlen" string (e.g. "172.31.1.1/24") into an address and
 * the corresponding netmask. The input string is left untouched.
 * Returns 0 on success, -1 on error (with errno = EINVAL).
 */
int parse_cidr(const char *cidr, struct in_addr *ip, struct in_addr *mask)
{
    char buf[64];
    char *slash, *end;
    long prefix;

    if (strlen(cidr) >= sizeof(buf)) {
        errno = EINVAL;
        return -1;
    }
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    slash = strchr(buf, '/');
    if (slash == NULL) {
        errno = EINVAL;
        return -1;
    }
    *slash = '\0';

    prefix = strtol(slash + 1, &end, 10);
    if (*end != '\0' || end == slash + 1 || prefix < 0 || prefix > 32) {
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
int br_set_address(const char *bridge, struct in_addr ip, struct in_addr mask)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL, *msg2 = NULL;
    struct ifaddrmsg *ifa;
    struct ifinfomsg *ifi;
    int ret, ifindex;

    /* Convert netmask back to prefix length */
    int prefix = netmask_to_prefix(mask);

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
    ifi->ifi_change = IFF_UP;
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
 * IFLA_PROTINFO{attr}). The port must be enslaved to the given bridge,
 * matching classic brctl <bridge> <port> scoping; otherwise -EINVAL.
 * Returns 0 on success or a negative errno (NOT -1).
 */
static int br_set_port_attr(const char *bridge, const char *port, int attr, unsigned char val)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *protinfo;
    int ret, ifindex;

    /* Verify the port belongs to the specified bridge. */
    ret = br_check_master(bridge, port);
    if (ret < 0)
        return ret;

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
    nla_put_u8(msg, attr, val);
    nla_end_nested(msg, protinfo);

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/* Same as above but for u32-valued attributes (e.g. IFLA_BRPORT_COST). */
static int br_set_port_attr_u32(const char *bridge, const char *port, int attr, unsigned int val)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *protinfo;
    int ret, ifindex;

    ret = br_check_master(bridge, port);
    if (ret < 0) return ret;

    ifindex = if_nametoindex(port);
    if (ifindex == 0) return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) return ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg); nlmsg_free(reply); netlink_close(&nlh);
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
    nlmsg_free(msg); nlmsg_free(reply); netlink_close(&nlh);
    return ret;
}

/* Same as br_set_port_attr but for u16-valued port attributes.  IFLA_BRPORT_PRIORITY
 * is declared NLA_U16 in the kernel's br_port_policy, so a 1-byte (u8) payload is
 * rejected by validate_nla with -ERANGE (older kernels parsed short integer attrs
 * leniently, which masked this); the value must be sent as 2 bytes. */
static int br_set_port_attr_u16(const char *bridge, const char *port, int attr, unsigned short val)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *protinfo;
    int ret, ifindex;

    ret = br_check_master(bridge, port);
    if (ret < 0) return ret;

    ifindex = if_nametoindex(port);
    if (ifindex == 0) return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) return ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg); nlmsg_free(reply); netlink_close(&nlh);
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
    nla_put_u16(msg, attr, val);
    nla_end_nested(msg, protinfo);

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg); nlmsg_free(reply); netlink_close(&nlh);
    return ret;
}

/*
 * Add (RTM_SETLINK) or delete (RTM_DELLINK) a VLAN, or a contiguous VLAN
 * range, on a bridge port.  VLANs ride inside IFLA_AF_SPEC — the AF_BRIDGE
 * sibling of IFLA_PROTINFO — exactly as iproute2 `bridge vlan add|del`:
 *
 *   ifinfomsg { ifi_family = AF_BRIDGE, ifi_index = <port> }
 *   IFLA_AF_SPEC (nested) {
 *     IFLA_BRIDGE_VLAN_INFO x 1|2  (struct bridge_vlan_info { flags, vid })
 *   }
 *
 * No IFLA_BRIDGE_FLAGS is sent.  The flag is read in net/core/rtnetlink.c,
 * not br_afspec: an unset flags field takes the MASTER path (br_setlink ->
 * br_afspec), like `bridge vlan add` with no `self`/`master`; BRIDGE_FLAGS_SELF
 * would instead target the port's own ndo_bridge_setlink, which a plain
 * (non-switchdev) port lacks, yielding -EOPNOTSUPP.
 *
 * A single VID is one entry; a range is encoded as a RANGE_BEGIN/RANGE_END
 * pair (the per-VID pvid/untagged flags apply to the whole range).  The port
 * must already be enslaved to the bridge, matching the port-parameter
 * convention.  add maps to the kernel's br_setlink, del to br_dellink.
 * Returns 0 on success or a negative errno (NOT -1).
 */
static int br_vlan_modify(const char *bridge, const char *port,
                          unsigned short vid_start, unsigned short vid_end,
                          unsigned short vflags, int is_add)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *afspec;
    struct bridge_vlan_info vinfo;
    int ret, ifindex;

    ret = br_check_master(bridge, port);
    if (ret < 0) return ret;

    ifindex = if_nametoindex(port);
    if (ifindex == 0) return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) return ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg); nlmsg_free(reply); netlink_close(&nlh);
        return -ENOMEM;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_BRIDGE;
    ifi->ifi_index = ifindex;

    msg->nlmsghdr.nlmsg_type = is_add ? RTM_SETLINK : RTM_DELLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    afspec = nla_begin_nested(msg, IFLA_AF_SPEC);
    afspec->rta_type |= NLA_F_NESTED;

    /* No IFLA_BRIDGE_FLAGS: see the header comment — leaving flags unset is
     * what routes the op to br_setlink (the MASTER path). */

    if (vid_start == vid_end) {
        vinfo.flags = vflags;
        vinfo.vid = vid_start;
        nla_put_buffer(msg, IFLA_BRIDGE_VLAN_INFO, &vinfo, sizeof(vinfo));
    } else {
        /* Encode vid_start..vid_end as a RANGE_BEGIN/RANGE_END pair. */
        vinfo.flags = vflags | BRIDGE_VLAN_INFO_RANGE_BEGIN;
        vinfo.vid = vid_start;
        nla_put_buffer(msg, IFLA_BRIDGE_VLAN_INFO, &vinfo, sizeof(vinfo));

        vinfo.flags = vflags | BRIDGE_VLAN_INFO_RANGE_END;
        vinfo.vid = vid_end;
        nla_put_buffer(msg, IFLA_BRIDGE_VLAN_INFO, &vinfo, sizeof(vinfo));
    }

    nla_end_nested(msg, afspec);

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg); nlmsg_free(reply); netlink_close(&nlh);
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

/*
 * Parse the shared vlan_add/vlan_del argument tail:
 *   <vid> [vid <end>] [pvid] [untagged]
 * argv[0]/[1] are bridge/port; argv[2] is the start VID.  Keywords may follow
 * in any order.  VIDs are 1-4094 (4095 is reserved).  When allow_flags is 0,
 * pvid/untagged are rejected (deletion is by VID only).  A reversed range
 * (end < start) is rejected.
 * Returns 0 on success (fills vid_start/vid_end/vflags), -1 with errno=EINVAL.
 */
static int parse_vlan_args(int argc, char *argv[], int allow_flags,
                           long *vid_start, long *vid_end, unsigned short *vflags)
{
    long start, end;
    unsigned short flags = 0;
    int i;

    if (parse_long(argv[2], 1, 4094, &start) < 0)
        return -1;
    end = start;

    for (i = 3; i < argc; i++) {
        if (allow_flags && !strcasecmp(argv[i], "pvid")) {
            flags |= BRIDGE_VLAN_INFO_PVID;
        } else if (allow_flags && !strcasecmp(argv[i], "untagged")) {
            flags |= BRIDGE_VLAN_INFO_UNTAGGED;
        } else if (!strcasecmp(argv[i], "vid")) {
            if (i + 1 >= argc) {
                errno = EINVAL;
                return -1;
            }
            if (parse_long(argv[++i], 1, 4094, &end) < 0)
                return -1;
        } else {
            errno = EINVAL;
            return -1;
        }
    }

    if (end < start) {
        errno = EINVAL;
        return -1;
    }

    /* A port has exactly one PVID, so pvid on a range is meaningless —
     * the kernel (br_vlan_valid_range) and iproute2 both reject it. */
    if (start != end && (flags & BRIDGE_VLAN_INFO_PVID)) {
        errno = EINVAL;
        return -1;
    }

    *vid_start = start;
    *vid_end = end;
    *vflags = flags;
    return 0;
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
    int err = br_release_if(argv[0], interface);

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

/*
 * Delete an IPv4 address from an interface (RTM_DELADDR).
 * The prefix must match the one used in addip.
 * Returns 0 on success or a negative errno on failure (NOT -1).
 */
static int br_del_address(const char *iface, struct in_addr ip, int prefix)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifaddrmsg *ifa;
    int ret, ifindex;

    ifindex = if_nametoindex(iface);
    if (ifindex == 0)
        return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) return ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg); nlmsg_free(reply); netlink_close(&nlh);
        return -ENOMEM;
    }

    ifa = (struct ifaddrmsg *)nlmsg_data(msg);
    memset(ifa, 0, sizeof(*ifa));
    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = prefix;
    ifa->ifa_index = ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_DELADDR;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

    nla_put_buffer(msg, IFA_LOCAL, &ip, sizeof(ip));

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg); nlmsg_free(reply); netlink_close(&nlh);
    return ret;
}

/* brctl delip <bridge> <ip/prefixlen> */
static int cmd_delip(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    char *cidr = argv[1];
    struct in_addr ip, mask;
    int prefix;

    if (parse_cidr(cidr, &ip, &mask) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid IP address %s", cidr);
        return -1;
    }

    /* Convert mask back to prefix length */
    prefix = netmask_to_prefix(mask);

    int err = br_del_address(bridge, ip, prefix);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "Could not delete IP %s from %s: %s", cidr, bridge, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "IP %s deleted from %s", cidr, bridge);
    return 0;
}

/* brctl setup <bridge> <ip/prefixlen> (create + addip in one shot) */
static int cmd_setup(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    char *cidr = argv[1];
    struct in_addr ip, mask;

    /* Validate the CIDR first so a bad address doesn't leave a
     * half-created bridge behind. */
    if (parse_cidr(cidr, &ip, &mask) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid IP address %s", cidr);
        return -1;
    }

    int err = br_addbr(bridge);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not create bridge %s: %s", bridge, strerror(-err));
        return -1;
    }

    err = br_set_address(bridge, ip, mask);
    if (err < 0) {
        /* setup is create+addip in one shot; roll back the bridge on
         * failure so we don't leave a half-configured bridge behind. */
        br_delbr(bridge);
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
    /* IFLA_BR_VLAN_PROTOCOL is __be16 in the kernel uAPI (read with
     * nla_get_be16); send it in network byte order, otherwise little-endian
     * byte-swaps the value and eth_type_vlan() rejects even 0x8100/0x88a8. */
    int err = br_set_bridge_attr_u16(bridge, IFLA_BR_VLAN_PROTOCOL,
                                     htons((unsigned short)proto));
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
    int err = br_set_port_attr_u16(argv[0], port, IFLA_BRPORT_PRIORITY, (unsigned short)prio);
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
    int err = br_set_port_attr_u32(argv[0], port, IFLA_BRPORT_COST, (unsigned int)cost);
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
    int err = br_set_port_attr(argv[0], port, IFLA_BRPORT_STATE, (unsigned int)state);
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
    int err = br_set_port_attr(argv[0], port, IFLA_BRPORT_MODE, (unsigned int)(on ? BRIDGE_MODE_HAIRPIN : 0));
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set hairpin mode on %s: %s", port, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Hairpin mode %s on %s", on ? "enabled" : "disabled", port);
    return 0;
}

/* brctl isolated <bridge> <port> on|off
 * An isolated port can only talk to the bridge CPU port, not to other
 * bridge ports — used to L2-isolate peers sharing one bridge. */
static int cmd_isolated(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *port = argv[1];
    int on = parse_onoff(argv[2]);
    if (on < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid value %s (expected on/off)", argv[2]);
        return -1;
    }
    int err = br_set_port_attr(argv[0], port, IFLA_BRPORT_ISOLATED, (unsigned int)on);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set isolated mode on %s: %s", port, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Port isolation %s on %s", on ? "enabled" : "disabled", port);
    return 0;
}

/* brctl vlan_add <bridge> <port> <vid> [vid <end>] [pvid] [untagged]
 * Adds a VLAN (or range) to a port: pvid = strip the tag on ingress,
 * untagged = strip it on egress.  The bridge must have vlan_filtering on,
 * else the kernel rejects the request with -EINVAL.  Duplicate VID -> EEXIST. */
static int cmd_vlan_add(hypervisor_conn_t *conn, int argc, char *argv[])
{
    long start, end;
    unsigned short flags;

    if (parse_vlan_args(argc, argv, 1, &start, &end, &flags) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
            "Invalid VLAN spec (expected <bridge> <port> <vid> [vid <end>] [pvid] [untagged])");
        return -1;
    }

    int err = br_vlan_modify(argv[0], argv[1], (unsigned short)start,
                             (unsigned short)end, flags, 1);
    if (err < 0) {
        if (start == end)
            hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                "Could not add VLAN %ld on %s: %s", start, argv[1], strerror(-err));
        else
            hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                "Could not add VLAN %ld-%ld on %s: %s", start, end, argv[1], strerror(-err));
        return -1;
    }

    if (start == end)
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "VLAN %ld added on %s", start, argv[1]);
    else
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "VLAN %ld-%ld added on %s", start, end, argv[1]);
    return 0;
}

/* brctl vlan_del <bridge> <port> <vid> [vid <end>] — delete a VLAN/range from a port */
static int cmd_vlan_del(hypervisor_conn_t *conn, int argc, char *argv[])
{
    long start, end;
    unsigned short flags;

    /* allow_flags=0: deletion is by VID only; reject pvid/untagged. */
    if (parse_vlan_args(argc, argv, 0, &start, &end, &flags) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
            "Invalid VLAN spec (expected <bridge> <port> <vid> [vid <end>])");
        return -1;
    }

    int err = br_vlan_modify(argv[0], argv[1], (unsigned short)start,
                             (unsigned short)end, flags, 0);
    if (err < 0) {
        if (start == end)
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                "Could not delete VLAN %ld on %s: %s", start, argv[1], strerror(-err));
        else
            hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                "Could not delete VLAN %ld-%ld on %s: %s", start, end, argv[1], strerror(-err));
        return -1;
    }

    if (start == end)
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "VLAN %ld deleted from %s", start, argv[1]);
    else
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "VLAN %ld-%ld deleted from %s", start, end, argv[1]);
    return 0;
}

/* One (port, vid, flags) tuple collected from an RTM_GETLINK AF_BRIDGE dump. */
struct br_vlan_entry {
    int ifindex;
    unsigned short vid;
    unsigned short flags;
};

/* Append one (port, vid, flags) to a growable array (cf. br_dump_addresses).
 * Returns 0 on success or -ENOMEM. */
static int append_vlan_entry(struct br_vlan_entry **entries, int *n, int *cap,
                             int ifindex, unsigned short vid, unsigned short flags)
{
    if (*n == *cap) {
        int newcap = *cap ? *cap * 2 : 16;
        struct br_vlan_entry *tmp = realloc(*entries, newcap * sizeof(*tmp));
        if (!tmp)
            return -ENOMEM;
        *entries = tmp;
        *cap = newcap;
    }
    (*entries)[*n].ifindex = ifindex;
    (*entries)[*n].vid = vid;
    (*entries)[*n].flags = flags;
    (*n)++;
    return 0;
}

/*
 * Dump per-port VLAN membership via RTM_GETLINK (AF_BRIDGE) + IFLA_EXT_MASK =
 * RTEXT_FILTER_BRVLAN_COMPRESSED — the compressed variant iproute2 `bridge vlan
 * show` uses: a run of same-flag VIDs arrives as one RANGE_BEGIN/END pair.  The
 * kernel caps dump datagrams at ~32 KiB, so the non-compressed dump cannot
 * carry a port holding ~4000+ VIDs in one message; compressed avoids that.
 * Each RTM_NEWLINK reply carries IFLA_MASTER (the bridge) and
 * IFLA_AF_SPEC{IFLA_BRIDGE_VLAN_INFO}; we keep entries whose master is `bridge`
 * (excluding the bridge device itself), optionally a single `port`, and expand
 * ranges back to per-VID entries so the output is one line per VID regardless
 * of how the VLANs were added.
 * On success returns 0 and a malloc'd array in *out (caller frees); *count
 * holds the entry count.  Returns a negative errno otherwise (NOT -1).
 */
static int br_vlan_dump(const char *bridge, const char *port,
                        struct br_vlan_entry **out, int *count)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct br_vlan_entry *entries = NULL;
    int n = 0, cap = 0, ret = -1;
    int br_ifindex, want_port = 0;

    *out = NULL;
    *count = 0;

    br_ifindex = if_nametoindex(bridge);
    if (br_ifindex == 0)
        return -ENODEV;
    if (port) {
        want_port = if_nametoindex(port);
        if (want_port == 0)
            return -ENODEV;
    }

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0)
        return ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg); nlmsg_free(reply); netlink_close(&nlh);
        return -ENOMEM;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_BRIDGE;

    msg->nlmsghdr.nlmsg_type = RTM_GETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nla_put_u32(msg, IFLA_EXT_MASK, RTEXT_FILTER_BRVLAN_COMPRESSED);

    ret = netlink_send(&nlh, msg);
    if (ret < 0)
        goto out;

    while (1) {
        reply->nlmsghdr.nlmsg_len = NLMSG_ALIGN(NLMSG_GOOD_SIZE);
        int r = netlink_rcv(&nlh, reply);
        if (r < 0) {
            /* netlink_rcv returns the negative errno directly (e.g. -EMSGSIZE
             * on a truncated dump); use r, not -errno — errno is not reliably
             * set on this path. */
            ret = r;
            goto out;
        }
        if (r == 0)
            break;

        struct nlmsghdr *nh;
        int len = r;
        for (nh = (struct nlmsghdr *)reply; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE)
                goto done;
            if (nh->nlmsg_type == NLMSG_ERROR)
                goto out;
            if (nh->nlmsg_type != RTM_NEWLINK)
                continue;

            struct ifinfomsg *ifi_r = (struct ifinfomsg *)NLMSG_DATA(nh);
            if (ifi_r->ifi_index == br_ifindex)
                continue;  /* skip the bridge device itself */
            if (want_port && ifi_r->ifi_index != want_port)
                continue;

            int attrlen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
            struct rtattr *rta = IFLA_RTA(ifi_r);
            int master = 0, have_master = 0;
            struct rtattr *afspec = NULL;
            while (RTA_OK(rta, attrlen)) {
                if (rta->rta_type == IFLA_MASTER) {
                    memcpy(&master, RTA_DATA(rta), sizeof(master));
                    have_master = 1;
                } else if (rta->rta_type == IFLA_AF_SPEC) {
                    afspec = rta;
                }
                rta = RTA_NEXT(rta, attrlen);
            }
            if (!have_master || master != br_ifindex || !afspec)
                continue;

            int alen = RTA_PAYLOAD(afspec);
            struct rtattr *va = (struct rtattr *)RTA_DATA(afspec);
            unsigned short rs_vid = 0, rs_flags = 0;
            int in_range = 0;
            while (RTA_OK(va, alen)) {
                if (va->rta_type == IFLA_BRIDGE_VLAN_INFO &&
                    RTA_PAYLOAD(va) == sizeof(struct bridge_vlan_info)) {
                    struct bridge_vlan_info *vinfo = (struct bridge_vlan_info *)RTA_DATA(va);
                    /* RANGE_* are dump encoding, not per-VID flags; strip them. */
                    unsigned short vf = vinfo->flags &
                        ~(BRIDGE_VLAN_INFO_RANGE_BEGIN | BRIDGE_VLAN_INFO_RANGE_END);
                    if (vinfo->flags & BRIDGE_VLAN_INFO_RANGE_BEGIN) {
                        rs_vid = vinfo->vid;
                        rs_flags = vf;
                        in_range = 1;
                    } else if (in_range &&
                               (vinfo->flags & BRIDGE_VLAN_INFO_RANGE_END)) {
                        unsigned int v;
                        for (v = rs_vid; v <= vinfo->vid; v++) {
                            ret = append_vlan_entry(&entries, &n, &cap,
                                                    ifi_r->ifi_index, v, rs_flags);
                            if (ret)
                                goto out;
                        }
                        in_range = 0;
                    } else {
                        ret = append_vlan_entry(&entries, &n, &cap,
                                                ifi_r->ifi_index, vinfo->vid, vf);
                        if (ret)
                            goto out;
                    }
                }
                va = RTA_NEXT(va, alen);
            }
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

/* brctl vlan_show <bridge> [port] — list per-port VLAN membership.
 * One line per (port, vid): "<port> <vid> [PVID] [Egress Untagged]". */
static int cmd_vlan_show(hypervisor_conn_t *conn, int argc, char *argv[])
{
    const char *bridge = argv[0];
    const char *port = (argc >= 2) ? argv[1] : NULL;
    struct br_vlan_entry *entries;
    int count = 0, i;

    int err = br_vlan_dump(bridge, port, &entries, &count);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
            "Could not dump VLANs on %s: %s", bridge, strerror(-err));
        return -1;
    }

    for (i = 0; i < count; i++) {
        char ifname[IFNAMSIZ];
        const char *name = if_indextoname(entries[i].ifindex, ifname);
        char flags[32] = "";
        if (entries[i].flags & BRIDGE_VLAN_INFO_PVID)
            strncat(flags, " PVID", sizeof(flags) - strlen(flags) - 1);
        if (entries[i].flags & BRIDGE_VLAN_INFO_UNTAGGED)
            strncat(flags, " Egress Untagged", sizeof(flags) - strlen(flags) - 1);
        hypervisor_send_reply(conn, HSC_INFO_MSG, 0, "%s %u%s",
                              name ? name : "?", entries[i].vid, flags);
    }
    free(entries);

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%d VLAN entr%s",
                          count, (count == 1) ? "y" : "ies");
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
        if (r < 0) {
            /* A receive error (e.g. -EMSGSIZE when a dump datagram
             * overflows our buffer) means the dump is incomplete, not
             * finished — report failure rather than silently returning
             * a truncated address list as if it were complete. */
            ret = -1;
            goto out;
        }
        if (r == 0)
            break;

        /* Walk every nlmsg packed into this datagram */
        struct nlmsghdr *nh;
        int len = r;
        for (nh = (struct nlmsghdr *)reply; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE)
                goto done;
            if (nh->nlmsg_type == NLMSG_ERROR) {
                /* A dump never contains NLMSG_ERROR on success; treat it
                 * as a real failure rather than end-of-dump so kernel
                 * errors (permissions, malformed request) aren't hidden. */
                ret = -1;
                goto out;
            }
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
                if (!tmp) {
                    /* allocation failed: report the error rather than
                     * returning a partial dump as if it were complete. */
                    ret = -1;
                    goto out;
                }
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

/*
 * brctl show <bridge> — query IP, prefix and flags via netlink */
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
    if (ret < 0) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not query bridge %s flags: %s", bridge, strerror(-ret));
        return -1;
    }

    {
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


/* brctl commands */
static hypervisor_cmd_t brctl_cmd_array[] = {
   { "addif", 2, 2, cmd_addif, NULL },
   { "create", 1, 1, cmd_create, NULL },
   { "delete", 1, 1, cmd_delete, NULL },
   { "addip", 2, 2, cmd_addip, NULL },
   { "delip", 2, 2, cmd_delip, NULL },
   { "setup", 2, 2, cmd_setup, NULL },
   { "show",  1, 1, cmd_show, NULL },
   { "delif", 2, 2, cmd_delif, NULL },
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
   { "isolated", 3, 3, cmd_isolated, NULL },
   /* VLAN filtering — per-port VID membership (needs vlanfiltering on) */
   { "vlan_add", 3, 7, cmd_vlan_add, NULL },
   { "vlan_del", 3, 5, cmd_vlan_del, NULL },
   { "vlan_show", 1, 2, cmd_vlan_show, NULL },
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
