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
 * link — generic network interface management via netlink.
 *
 * Provides veth pair creation, IP assignment, and link state control
 * without requiring the ip command (benefits from ubridge's cap_net_admin).
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
#include <linux/veth.h>
#include "netlink/nl.h"
#include "ubridge.h"
#include "hypervisor.h"
#include "hypervisor_link.h"
#include "hypervisor_brctl.h"

/* --------------------------------------------------------------------------
 * veth pair creation (RTM_NEWLINK + IFLA_INFO_KIND="veth")
 * --------------------------------------------------------------------------
 */

static int link_veth_pair(const char *name, const char *peer)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *linkinfo, *infodata, *veth_peer;
    int ret;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) return ret;

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

    nla_put_string(msg, IFLA_IFNAME, name);
    linkinfo = nla_begin_nested(msg, IFLA_LINKINFO);
    nla_put_string(msg, IFLA_INFO_KIND, "veth");
    infodata = nla_begin_nested(msg, IFLA_INFO_DATA);
    veth_peer = nla_begin_nested(msg, VETH_INFO_PEER);

    /* Zeroed ifinfomsg (raw, no NLA header) for the peer */
    {
        struct ifinfomsg peer_ifi;
        memset(&peer_ifi, 0, sizeof(peer_ifi));
        peer_ifi.ifi_family = AF_UNSPEC;
        memcpy(NLMSG_TAIL(&msg->nlmsghdr), &peer_ifi, sizeof(peer_ifi));
        msg->nlmsghdr.nlmsg_len += sizeof(peer_ifi);
    }
    nla_put_string(msg, IFLA_IFNAME, peer);

    nla_end_nested(msg, veth_peer);
    nla_end_nested(msg, infodata);
    nla_end_nested(msg, linkinfo);

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/* --------------------------------------------------------------------------
 * Set link state up/down (RTM_SETLINK + IFF_UP)
 * --------------------------------------------------------------------------
 */

static int link_set_state(const char *iface, int up)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    int ret, ifindex;

    ifindex = if_nametoindex(iface);
    if (ifindex == 0) return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) return ret;

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
    ifi->ifi_change |= IFF_UP;
    if (up) ifi->ifi_flags |= IFF_UP;

    msg->nlmsghdr.nlmsg_type = RTM_SETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    ret = netlink_transaction(&nlh, msg, reply);
    nlmsg_free(msg);
    nlmsg_free(reply);
    netlink_close(&nlh);
    return ret;
}

/* --------------------------------------------------------------------------
 * Command handlers
 * --------------------------------------------------------------------------
 */

/* link veth <name> <peer> */
static int cmd_veth(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *name = argv[0], *peer = argv[1];

    if (strlen(name) >= IF_NAMESIZE || strlen(peer) >= IF_NAMESIZE) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "Interface name too long (max 15 chars)");
        return -1;
    }

    int err = link_veth_pair(name, peer);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not create veth pair %s/%s: %s",
                              name, peer, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1,
                          "Veth pair %s/%s created", name, peer);
    return 0;
}

/* link addr <iface> <ip/prefix> */
static int cmd_addr(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *iface = argv[0];
    char *cidr = argv[1];
    struct in_addr ip, mask;

    if (parse_cidr(cidr, &ip, &mask) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "Invalid IP address %s", cidr);
        return -1;
    }

    int err = br_set_address(iface, ip, mask);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not set IP %s on %s: %s",
                              cidr, iface, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1,
                          "IP %s set on %s", cidr, iface);
    return 0;
}

/* link set <iface> up|down */
static int cmd_set(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *iface = argv[0];
    char *state = argv[1];
    int up;

    if (!strcasecmp(state, "up"))
        up = 1;
    else if (!strcasecmp(state, "down"))
        up = 0;
    else {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "Invalid link state %s (expected up/down)", state);
        return -1;
    }

    int err = link_set_state(iface, up);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not set link %s %s: %s",
                              iface, state, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1,
                          "Interface %s %s", iface, state);
    return 0;
}

/* --------------------------------------------------------------------------
 * Module registration
 * --------------------------------------------------------------------------
 */

static hypervisor_cmd_t link_cmd_array[] = {
   { "veth", 2, 2, cmd_veth, NULL },
   { "addr", 2, 2, cmd_addr,  NULL },
   { "set",  2, 2, cmd_set,   NULL },
   { NULL, -1, -1, NULL, NULL },
};

int hypervisor_link_init(void)
{
   hypervisor_module_t *module;

   module = hypervisor_register_module("link", NULL);
   assert(module != NULL);

   hypervisor_register_cmd_array(module, link_cmd_array);
   return 0;
}
