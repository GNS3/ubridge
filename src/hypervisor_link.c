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
 * Provides veth pair creation, IP assignment, link state control, and
 * L2-only hardening (IPv6 address generation off) without requiring the
 * ip command (benefits from ubridge's cap_net_admin).
 */

#include <unistd.h>
#include <stdio.h>
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
    struct nlmsg *msg = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *linkinfo, *infodata, *veth_peer;
    int ret;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) return ret;

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

    ret = nl_xact(&nlh, msg);
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
    struct nlmsg *msg = NULL;
    struct ifinfomsg *ifi;
    int ret, ifindex;

    ifindex = if_nametoindex(iface);
    if (ifindex == 0) return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) return ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg) {
        netlink_close(&nlh);
        return -ENOMEM;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;
    ifi->ifi_change = IFF_UP;
    if (up) ifi->ifi_flags |= IFF_UP;

    msg->nlmsghdr.nlmsg_type = RTM_SETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    ret = nl_xact(&nlh, msg);
    netlink_close(&nlh);
    return ret;
}

/* --------------------------------------------------------------------------
 * Set the device MTU (RTM_SETLINK + IFLA_MTU)
 * --------------------------------------------------------------------------
 */

static int link_set_mtu(const char *iface, int mtu)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL;
    struct ifinfomsg *ifi;
    int ret, ifindex;

    ifindex = if_nametoindex(iface);
    if (ifindex == 0) return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) return ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg) {
        netlink_close(&nlh);
        return -ENOMEM;
    }

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_SETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    nla_put_u32(msg, IFLA_MTU, mtu);

    ret = nl_xact(&nlh, msg);
    netlink_close(&nlh);
    return ret;
}

/* --------------------------------------------------------------------------
 * Delete an interface (RTM_DELLINK).
 * Deleting one end of a veth pair removes the other automatically.
 * --------------------------------------------------------------------------
 */

static int link_delete(const char *iface)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL;
    struct ifinfomsg *ifi;
    int ret, ifindex;

    ifindex = if_nametoindex(iface);
    if (ifindex == 0) return -ENODEV;

    ret = netlink_open(&nlh, NETLINK_ROUTE);
    if (ret < 0) return ret;

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

/* --------------------------------------------------------------------------
 * L2-only hardening — IFLA_INET6_ADDR_GEN_MODE = NONE + link-local removal
 * --------------------------------------------------------------------------
 *
 * A host-side anchor that is UP gets an IPv6 link-local address from the
 * kernel with no user-space actor involved, and with it the kernel's own MLD
 * reports, DAD neighbour solicitations and router solicitations. On an
 * emulated link those frames land in captures (an idle link is then not
 * quiet) and the host answers ND for its own link-local, so an emulated IPv6
 * router can form an adjacency with the host — a phantom neighbour.
 *
 * Setting the address generation mode to NONE stops the kernel from
 * provisioning one. An address that already exists is deleted explicitly:
 * measured on 7.2, the mode change alone leaves it in place (it survives the
 * mode change and even a down/up cycle), so the deletion is what cleans up an
 * anchor that was brought UP before this call. Both are read back before
 * success is reported, so a caller may treat OK as verified rather than
 * requested.
 *
 * Everything here goes over netlink; nothing writes
 * /proc/sys/net/ipv6/conf/<if>/disable_ipv6. Those files are root-owned mode
 * 0644, so a setcap'd non-root ubridge can be refused by the DAC check
 * despite holding CAP_NET_ADMIN.
 */

/* Set the device's IPv6 address generation mode (RTM_SETLINK + IFLA_AF_SPEC).
 * Returns 0 on success or a negative errno (EINVAL/EOPNOTSUPP on a kernel or
 * device without IFLA_INET6_ADDR_GEN_MODE). */
static int l2only_set_gen_mode(struct nl_handler *nlh, int ifindex, unsigned char mode)
{
    struct nlmsg *msg = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *af_spec, *af6;
    int ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg)
        return -ENOMEM;

    ifi = (struct ifinfomsg *)nlmsg_data(msg);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_SETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    /* IFLA_AF_SPEC holds one nest per address family, keyed by the family
     * number, and the family's ->set_link_af parses that nest. Sending the
     * attribute directly under IFLA_AF_SPEC (no AF_INET6 level) is rejected
     * with EAFNOSUPPORT — verified against the message `ip link set dev X
     * addrgenmode none` sends. */
    af_spec = nla_begin_nested(msg, IFLA_AF_SPEC);
    af6 = nla_begin_nested(msg, AF_INET6);
    nla_put_u8(msg, IFLA_INET6_ADDR_GEN_MODE, mode);
    nla_end_nested(msg, af6);
    nla_end_nested(msg, af_spec);

    ret = nl_xact(nlh, msg);
    return ret;
}

/* Read the device's IPv6 address generation mode back (RTM_GETLINK →
 * IFLA_AF_SPEC → IFLA_INET6_ADDR_GEN_MODE). Returns the mode (>= 0) or a
 * negative errno; -ENODATA when the device reports no such attribute (a
 * device without an IPv6 stack at all). */
static int l2only_get_gen_mode(struct nl_handler *nlh, int ifindex)
{
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifinfomsg *ifi;
    struct rtattr *rta;
    int ret, attrlen;

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

    /* No NLM_F_ACK: the answer is the RTM_NEWLINK message itself. */
    msg->nlmsghdr.nlmsg_type = RTM_GETLINK;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    ret = netlink_transaction(nlh, msg, reply);
    if (ret < 0)
        goto out;

    ret = -ENODATA;
    if (reply->nlmsghdr.nlmsg_type != RTM_NEWLINK)
        goto out;

    ifi = (struct ifinfomsg *)NLMSG_DATA(&reply->nlmsghdr);
    attrlen = reply->nlmsghdr.nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
    for (rta = IFLA_RTA(ifi); RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
        struct rtattr *af6;
        int af6len;

        if (rta->rta_type != IFLA_AF_SPEC)
            continue;

        /* Same two levels as the request: the family nest, then the mode. */
        af6len = RTA_PAYLOAD(rta);
        for (af6 = (struct rtattr *)RTA_DATA(rta); RTA_OK(af6, af6len);
             af6 = RTA_NEXT(af6, af6len)) {
            struct rtattr *mode;
            int modelen;

            if (af6->rta_type != AF_INET6)
                continue;

            modelen = RTA_PAYLOAD(af6);
            for (mode = (struct rtattr *)RTA_DATA(af6); RTA_OK(mode, modelen);
                 mode = RTA_NEXT(mode, modelen)) {
                if (mode->rta_type == IFLA_INET6_ADDR_GEN_MODE &&
                    RTA_PAYLOAD(mode) >= 1) {
                    ret = *(unsigned char *)RTA_DATA(mode);
                    goto out;
                }
            }
        }
    }

out:
    nlmsg_free(msg);
    nlmsg_free(reply);
    return ret;
}

/* Delete one IPv6 address (RTM_DELADDR). Returns 0 or a negative errno. */
static int l2only_del_addr(struct nl_handler *nlh, int ifindex, const struct in6_addr *addr,
                           unsigned char prefixlen, unsigned char scope)
{
    struct nlmsg *msg = NULL;
    struct ifaddrmsg *ifa;
    int ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg)
        return -ENOMEM;

    ifa = (struct ifaddrmsg *)nlmsg_data(msg);
    memset(ifa, 0, sizeof(*ifa));
    ifa->ifa_family = AF_INET6;
    ifa->ifa_prefixlen = prefixlen;
    ifa->ifa_scope = scope;
    ifa->ifa_index = ifindex;

    msg->nlmsghdr.nlmsg_type = RTM_DELADDR;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

    nla_put_buffer(msg, IFA_LOCAL, addr, sizeof(*addr));
    nla_put_buffer(msg, IFA_ADDRESS, addr, sizeof(*addr));

    ret = nl_xact(nlh, msg);
    return ret;
}

/*
 * Walk this host's IPv6 addresses and act on the link-local ones (fe80::/10)
 * that belong to <ifindex>. With <delete> set each is removed; otherwise they
 * are only counted. Returns the number found, or a negative errno — an
 * incomplete dump is reported as an error rather than as "none found".
 */
static int l2only_link_local(struct nl_handler *nlh, int ifindex, int delete)
{
    struct nlmsg *msg = NULL, *reply = NULL;
    struct ifaddrmsg *ifa;
    int found = 0, ret;

    msg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    reply = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!msg || !reply) {
        ret = -ENOMEM;
        goto out;
    }

    ifa = (struct ifaddrmsg *)nlmsg_data(msg);
    memset(ifa, 0, sizeof(*ifa));
    ifa->ifa_family = AF_INET6;

    /* NLM_F_REQUEST alone returns EOPNOTSUPP here; a dump is required, and
     * one recvmsg datagram may carry several concatenated nlmsg records. */
    msg->nlmsghdr.nlmsg_type = RTM_GETADDR;
    msg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

    if (netlink_send(nlh, msg) < 0) {
        ret = -errno;
        goto out;
    }

    for (;;) {
        struct nlmsghdr *nh;
        int len, r;

        reply->nlmsghdr.nlmsg_len = NLMSG_ALIGN(NLMSG_GOOD_SIZE);
        r = netlink_rcv(nlh, reply);
        if (r < 0) {            /* truncated dump: never report it as complete */
            ret = r;
            goto out;
        }
        if (r == 0)
            break;

        len = r;
        for (nh = (struct nlmsghdr *)reply; NLMSG_OK(nh, len);
             nh = NLMSG_NEXT(nh, len)) {
            struct ifaddrmsg *ifa_r;
            struct rtattr *rta;
            struct in6_addr addr;
            int attrlen, have_addr = 0, derr;

            if (nh->nlmsg_type == NLMSG_DONE)
                goto done;
            if (nh->nlmsg_type == NLMSG_ERROR) {
                /* Some kernels end a dump with an NLMSG_ERROR(err=0) ack
                 * instead of NLMSG_DONE; a real error is a failure. */
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nh);
                if (e->error == 0)
                    goto done;
                ret = e->error;
                goto out;
            }
            if (nh->nlmsg_type != RTM_NEWADDR)
                continue;

            ifa_r = (struct ifaddrmsg *)NLMSG_DATA(nh);
            if (ifa_r->ifa_family != AF_INET6 || (int)ifa_r->ifa_index != ifindex)
                continue;

            attrlen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
            for (rta = IFA_RTA(ifa_r); RTA_OK(rta, attrlen);
                 rta = RTA_NEXT(rta, attrlen)) {
                if (rta->rta_type != IFA_LOCAL && rta->rta_type != IFA_ADDRESS)
                    continue;
                if (RTA_PAYLOAD(rta) >= sizeof(addr)) {
                    memcpy(&addr, RTA_DATA(rta), sizeof(addr));
                    have_addr = 1;
                }
                break;
            }
            if (!have_addr || !IN6_IS_ADDR_LINKLOCAL(&addr))
                continue;

            found++;
            if (!delete)
                continue;

            derr = l2only_del_addr(nlh, ifindex, &addr, ifa_r->ifa_prefixlen,
                                   ifa_r->ifa_scope);
            /* Already gone (it can lapse between the dump and the delete, e.g.
             * a DAD timeout removing it) is the outcome we wanted: the
             * read-back is what decides, not this call. */
            if (derr < 0 && derr != -EADDRNOTAVAIL && derr != -ENOENT) {
                ret = derr;
                goto out;
            }
        }
    }

done:
    ret = found;

out:
    nlmsg_free(msg);
    nlmsg_free(reply);
    return ret;
}

/*
 * Apply (<on>) or clear (off) L2-only on <iface>.
 *
 * Returns 0 only after a read-back confirms the device state — no IPv6
 * address generation, and for `on` no link-local left on the device — or a
 * negative errno: -ENODEV for a missing device, -EINVAL/-EOPNOTSUPP on a
 * kernel without IFLA_INET6_ADDR_GEN_MODE, -EIO when the kernel reports a
 * state other than the one asked for.
 */
int link_set_l2only(const char *iface, int on)
{
    struct nl_handler nlh;
    int ifindex, want, mode, err;

    ifindex = if_nametoindex(iface);
    if (ifindex == 0)
        return -ENODEV;

    /* one handler for the whole sequence: the helpers used to open and
     * close their own socket each (a veth pair cost ~10 socket lifecycles
     * and 4 full address dumps per `link veth`) */
    err = netlink_open(&nlh, NETLINK_ROUTE);
    if (err < 0)
        return err;

    /* The kernel's built-in default is EUI-64, which is what `off` restores
     * (the link-local comes back on the next down/up cycle). */
    want = on ? IN6_ADDR_GEN_MODE_NONE : IN6_ADDR_GEN_MODE_EUI64;

    err = l2only_set_gen_mode(&nlh, ifindex, (unsigned char)want);
    if (err < 0)
        goto out;

    if (on) {
        err = l2only_link_local(&nlh, ifindex, 1);
        if (err < 0)
            goto out;
    }

    mode = l2only_get_gen_mode(&nlh, ifindex);
    if (mode < 0) {
        err = mode;
        goto out;
    }
    if (mode != want) {
        fprintf(stderr, "ubridge: %s: addrgenmode read-back is %d, expected %d\n",
                iface, mode, want);
        err = -EIO;
        goto out;
    }

    if (on) {
        /* the read-back is what decides: a failed dump is an error, not
         * "no link-local left" (it used to pass as verified) */
        int n = l2only_link_local(&nlh, ifindex, 0);

        if (n < 0) {
            err = n;
            goto out;
        }
        if (n > 0) {
            fprintf(stderr, "ubridge: %s: an IPv6 link-local address is still present\n", iface);
            err = -EIO;
            goto out;
        }
    }

    err = 0;
out:
    netlink_close(&nlh);
    return err;
}

/*
 * Creator-side wrapper: harden a device that was just created, without ever
 * failing the creation over it. A kernel (or device) that cannot do this at
 * all — EINVAL/EOPNOTSUPP, the spec's "old kernel" path — is logged and
 * ignored; every other error is real and returned for the caller to report.
 */
int link_harden_l2only(const char *iface)
{
    int err = link_set_l2only(iface, 1);

    if (err == -EINVAL || err == -EOPNOTSUPP) {
        fprintf(stderr, "ubridge: %s: no IPv6 address-generation control (%s), "
                        "left as the kernel defaults it\n", iface, strerror(-err));
        return 0;
    }

    return err;
}

/*
 * Creator-side MTU twin of link_harden_l2only(): apply UBRIDGE_DEFAULT_MTU to
 * a device that was just created, so jumbo guest frames are not silently
 * dropped at veth xmit / bridge egress. A kernel (or device kind) that cannot
 * take the value — EINVAL/EOPNOTSUPP — is logged and ignored, exactly like
 * the hardening wrapper's "old kernel" path; every other error is real and
 * returned for the caller to report.
 */
int link_apply_default_mtu(const char *iface)
{
    int err = link_set_mtu(iface, UBRIDGE_DEFAULT_MTU);

    if (err == -EINVAL || err == -EOPNOTSUPP) {
        fprintf(stderr, "ubridge: %s: no MTU %d (%s), "
                        "left as the kernel defaults it\n",
                iface, UBRIDGE_DEFAULT_MTU, strerror(-err));
        return 0;
    }

    return err;
}

/* --------------------------------------------------------------------------
 * Command handlers
 * --------------------------------------------------------------------------
 */

/* link l2only <iface> [on|off] — make an existing device pure L2. */
static int cmd_l2only(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *iface = argv[0];
    char *state = (argc >= 2) ? argv[1] : "on";
    int on, err;

    if (!strcasecmp(state, "on"))
        on = 1;
    else if (!strcasecmp(state, "off"))
        on = 0;
    else {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "Invalid L2-only state %s (expected on/off)", state);
        return -1;
    }

    err = link_set_l2only(iface, on);
    if (err < 0) {
        if (err == -ENODEV) {
            hypervisor_send_reply(conn, HSC_ERR_UNK_OBJ, 1,
                                  "No such device %s", iface);
            return -1;
        }
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not set L2-only %s on %s: %s",
                              on ? "on" : "off", iface, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1,
                          on ? "L2-only set on %s" : "L2-only cleared on %s", iface);
    return 0;
}

/* link delete <iface> — delete an interface (RTM_DELLINK).
 * For a veth pair, deleting one end removes the other automatically. */
static int cmd_delete(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *iface = argv[0];
    int err = link_delete(iface);

    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1,
                              "Could not delete %s: %s", iface, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Interface %s deleted", iface);
    return 0;
}

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

    /* Both ends are host-side, so both are hardened (see the L2-only block
     * above). */
    err = link_harden_l2only(name);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not set L2-only on %s: %s",
                              name, strerror(-err));
        return -1;
    }
    err = link_harden_l2only(peer);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not set L2-only on %s: %s",
                              peer, strerror(-err));
        return -1;
    }

    /* Jumbo-safe MTU on both ends — the veth transport itself never drops by
     * MTU on the normal path (veth_xmit has no check; the rcv->mtu gate in
     * veth_xdp_xmit is the XDP path), but either end may serve as a bridge
     * port, and the bridge egress check (is_skb_forwardable) gates frames
     * against the egress port's MTU. */
    err = link_apply_default_mtu(name);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not set MTU on %s: %s", name, strerror(-err));
        return -1;
    }
    err = link_apply_default_mtu(peer);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not set MTU on %s: %s", peer, strerror(-err));
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
   { "delete", 1, 1, cmd_delete, NULL },
   { "l2only", 1, 2, cmd_l2only, NULL },
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
