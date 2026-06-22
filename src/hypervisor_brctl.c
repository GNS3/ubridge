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
        return -1;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        errno = ENOMEM;
        return -1;
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
 */
static int br_delbr(const char *bridge)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    int ret;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0)
        return -1;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        errno = ENOMEM;
        return -1;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = if_nametoindex(bridge);

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
 * Enslave a port interface to a bridge (RTM_SETLINK + IFLA_MASTER).
 */
static int br_enslave_if(const char *bridge, const char *port)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    int ret, br_ifindex, port_ifindex;

    br_ifindex = if_nametoindex(bridge);
    port_ifindex = if_nametoindex(port);
    if (br_ifindex == 0 || port_ifindex == 0) {
        errno = ENODEV;
        return -1;
    }

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0)
        return -1;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        errno = ENOMEM;
        return -1;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = port_ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_SETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    nla_put_u32(msg, IFLA_MASTER, br_ifindex);

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/*
 * Release a port from its bridge (RTM_SETLINK + IFLA_MASTER = 0).
 */
static int br_release_if(const char *port)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    int ret, port_ifindex;

    port_ifindex = if_nametoindex(port);
    if (port_ifindex == 0) {
        errno = ENODEV;
        return -1;
    }

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0)
        return -1;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        errno = ENOMEM;
        return -1;
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
        return -1;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0)
        return -1;

    /* Step 1 – add/replace IPv4 address (RTM_NEWADDR) */
    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        errno = ENOMEM;
        return -1;
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
        return -1;
    }

    /* Step 2 – bring the interface up (RTM_SETLINK IFF_UP) */
    msg2 = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg2) {
        nlmsg_free(msg);
        nlmsg_free(reply);
        netlink_close(&nlh);
        errno = ENOMEM;
        return -1;
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

/* brctl create <bridge> */
static int cmd_create(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];

    if (br_addbr(bridge) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not create bridge %s: %s", bridge, strerror(errno));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Bridge %s created", bridge);
    return 0;
}

/* brctl delete <bridge> */
static int cmd_delete(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];

    if (br_delbr(bridge) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "Could not delete bridge %s: %s", bridge, strerror(errno));
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

    if (br_enslave_if(bridge, interface) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not add %s to %s: %s", interface, bridge, strerror(errno));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s has been added to bridge %s", interface, bridge);
    return 0;
}

/* brctl delif <bridge> <interface> — release a port from a bridge */
static int cmd_delif(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *interface = argv[1];

    if (br_release_if(interface) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "Could not remove %s from bridge %s: %s", argv[1], argv[0], strerror(errno));
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

    if (br_set_address(bridge, ip, mask) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not add IP %s to bridge %s: %s", cidr, bridge, strerror(errno));
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

    if (br_addbr(bridge) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not create bridge %s: %s", bridge, strerror(errno));
        return -1;
    }

    if (parse_cidr(cidr, &ip, &mask) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid IP address %s", cidr);
        return -1;
    }

    if (br_set_address(bridge, ip, mask) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not add IP %s to bridge %s: %s", cidr, bridge, strerror(errno));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Bridge %s created with IP %s", bridge, cidr);
    return 0;
}

/* brctl show <bridge> — query IP, prefix and flags via netlink */
static int cmd_show(hypervisor_conn_t *conn, int argc, char *argv[])
{
    const char *bridge = argv[0];
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    int ifindex, ret;

    ifindex = if_nametoindex(bridge);
    if (ifindex == 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Bridge %s does not exist", bridge);
        return -1;
    }

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not open netlink socket: %s", strerror(errno));
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
    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_GETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    char flags_str[64] = "";
    ret = netlink_transaction(&nlh, msg, reply);
    if (ret == 0) {
        struct ifinfomsg *ifi_r = (struct ifinfomsg *)nlmsg_data(reply);
        if (ifi_r->ifi_flags & IFF_UP)      strcat(flags_str, "UP ");
        if (ifi_r->ifi_flags & IFF_RUNNING) strcat(flags_str, "RUNNING ");
    }
    size_t flen = strlen(flags_str);
    if (flen > 0) flags_str[flen - 1] = '\0';

    /* Query IPv4 address via RTM_GETADDR */
    struct ifaddrmsg *ifa;
    char ip_str[INET_ADDRSTRLEN] = "";
    int prefix = 0;

    ifa = (struct ifaddrmsg *)nlmsg_data(msg);
    memset(ifa, 0, sizeof(*ifa));
    ifa->ifa_family = AF_INET;
    ifa->ifa_index = ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_GETADDR;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

    ret = netlink_transaction(&nlh, msg, reply);
    if (ret == 0) {
        struct ifaddrmsg *ifa_r = (struct ifaddrmsg *)nlmsg_data(reply);
        int attrlen = reply->nlmsghdr.nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        struct rtattr *rta = IFA_RTA(ifa_r);
        prefix = ifa_r->ifa_prefixlen;
        while (RTA_OK(rta, attrlen)) {
            if (rta->rta_type == IFA_LOCAL) {
                struct in_addr addr;
                memcpy(&addr, RTA_DATA(rta), sizeof(addr));
                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                break;
            }
            rta = RTA_NEXT(rta, attrlen);
        }
    }

    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);

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
    int ret;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not open netlink socket: %s", strerror(errno));
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

    while (1) {
        reply->nlmsghdr.nlmsg_len = NLMSG_ALIGN(NLMSG_GOOD_SIZE);
        ret = netlink_rcv(&nlh, reply);
        if (ret <= 0)
            break;

        if (reply->nlmsghdr.nlmsg_type == NLMSG_DONE)
            break;
        if (reply->nlmsghdr.nlmsg_type == NLMSG_ERROR)
            break;

        struct ifinfomsg *ifi_r = (struct ifinfomsg *)nlmsg_data(reply);
        int attrlen = reply->nlmsghdr.nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
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
            /* Query IP for this bridge */
            int br_ifindex = ifi_r->ifi_index;
            struct in_addr addr;
            char ip_str[INET_ADDRSTRLEN] = "";
            int prefix = 0;

            struct ifaddrmsg *addr_msg;
            addr_msg = (struct ifaddrmsg *)nlmsg_data(msg);
            memset(addr_msg, 0, sizeof(*addr_msg));
            addr_msg->ifa_family = AF_INET;
            addr_msg->ifa_index = br_ifindex;

            msg->nlmsghdr.nlmsg_type = RTM_GETADDR;
            msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST;
            msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

            reply->nlmsghdr.nlmsg_len = NLMSG_ALIGN(NLMSG_GOOD_SIZE);
            if (netlink_transaction(&nlh, msg, reply) == 0) {
                struct ifaddrmsg *ifa_r = (struct ifaddrmsg *)nlmsg_data(reply);
                int alen = reply->nlmsghdr.nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
                struct rtattr *ar = IFA_RTA(ifa_r);
                prefix = ifa_r->ifa_prefixlen;
                while (RTA_OK(ar, alen)) {
                    if (ar->rta_type == IFA_LOCAL) {
                        memcpy(&addr, RTA_DATA(ar), sizeof(addr));
                        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                        break;
                    }
                    ar = RTA_NEXT(ar, alen);
                }
            }

            if (ip_str[0])
                hypervisor_send_reply(conn, HSC_INFO_OK, 0, "%s %s/%d", ifname, ip_str, prefix);
            else
                hypervisor_send_reply(conn, HSC_INFO_OK, 0, "%s", ifname);
        }
    }

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
