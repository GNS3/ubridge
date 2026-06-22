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
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_bridge.h>
#include <linux/sockios.h>
#include <dirent.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "netlink/nl.h"
#include "ubridge.h"
#include "hypervisor.h"
#include "hypervisor_brctl.h"


static int cmd_addif(hypervisor_conn_t *conn, int argc, char *argv[])
{
    int err = -1;
    char *bridge = argv[0];
    char *interface = argv[1];
    struct ifreq ifr;

    int ifindex = if_nametoindex(interface);

    if (ifindex == 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not find interface %s", interface);
        return -1;
    }

    int br_socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
    #ifdef SIOCBRADDIF
        ifr.ifr_ifindex = ifindex;
        err = ioctl(br_socket_fd, SIOCBRADDIF, &ifr);
        if (err < 0)
    #endif
    {
        unsigned long args[4] = { BRCTL_ADD_IF, ifindex, 0, 0 };

        ifr.ifr_data = (char *) args;
        err = ioctl(br_socket_fd, SIOCDEVPRIVATE, &ifr);
    }

    // When interface is already added to the bridge EBUSY is raised
    if (err < 0 && errno != EBUSY) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not add interface %s to %s: %s", interface, bridge, strerror(errno));
        goto out;
    }

    // Change the status of the interface to up
    // Get the original flags
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(br_socket_fd, SIOCGIFFLAGS, &ifr) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not up interface %s", interface);
        err = -1;
        goto out;
    }
    // Add the up flag
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(br_socket_fd, SIOCSIFFLAGS, &ifr) < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not up interface %s", interface);
        err = -1;
        goto out;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s has been added to bridge %s", interface, bridge);
    err = 0;

out:
    close(br_socket_fd);
    return (err);
}


/*
 * Create a bridge device via netlink (RTM_NEWLINK + IFLA_INFO_KIND "bridge").
 * This is the standard interface on modern kernels; SIOCBRADDBR has been
 * deprecated in recent kernels and returns EOPNOTSUPP.
 */
static int br_addbr_netlink(const char *bridge)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL;
    struct nlmsg *reply = NULL;
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
 * Create a Linux bridge device.
 *
 * Tries three methods, in order of preference:
 *   1. SIOCBRADDBR ioctl  — works on kernels < 5.x or those with the old
 *      bridge ioctl interface compiled in.
 *   2. RTM_NEWLINK netlink — standard on modern kernels (≥ 5.x), where the
 *      ioctl path returns EOPNOTSUPP.
 *   3. BRCTL_ADD_BRIDGE via SIOCDEVPRIVATE — legacy fallback for very old
 *      kernels that lack both SIOCBRADDBR and the netlink bridge kind.
 *
 * errno from the failing call is preserved across close().
 */
static int br_addbr(char *bridge)
{
#ifdef SIOCBRADDBR
    /* Method 1 – modern ioctl (deprecated in newer kernels) */
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            int err = ioctl(fd, SIOCBRADDBR, bridge);
            int saved_errno = errno;
            close(fd);
            if (err == 0)
                return 0;
            /* EOPNOTSUPP / ENOTTY means the ioctl path is not supported
             * by the running kernel → fall through to netlink. */
            if (saved_errno != EOPNOTSUPP && saved_errno != ENOTTY) {
                errno = saved_errno;
                return -1;
            }
        }
    }
#endif

    /* Method 2 – netlink (RTM_NEWLINK), the modern interface */
    if (br_addbr_netlink(bridge) == 0)
        return 0;

    /* Method 3 – legacy BRCTL_ADD_BRIDGE via SIOCDEVPRIVATE */
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;
        struct ifreq ifr;
        unsigned long args[4];
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
        args[0] = BRCTL_ADD_BRIDGE;
        args[1] = (unsigned long)bridge;
        args[2] = 0;
        args[3] = 0;
        ifr.ifr_data = (char *)args;
        int err = ioctl(fd, SIOCDEVPRIVATE, &ifr);
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return err;
    }
}

/*
 * Delete a bridge device via netlink (RTM_DELLINK).
 * The interface is identified by index (if_nametoindex).
 */
static int br_delbr_netlink(const char *bridge)
{
    struct nl_handler nlh;
    struct nlmsg *msg = NULL;
    struct nlmsg *reply = NULL;
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
 * Delete a Linux bridge device.
 *
 * Tries three methods, in order of preference:
 *   1. SIOCBRDELBR ioctl
 *   2. RTM_DELLINK netlink  — modern kernels where the ioctl returns
 *      EOPNOTSUPP.
 *   3. BRCTL_DEL_BRIDGE via SIOCDEVPRIVATE — legacy fallback.
 *
 * errno from the failing call is preserved across close().
 */
static int br_delbr(char *bridge)
{
#ifdef SIOCBRDELBR
    /* Method 1 – modern ioctl (deprecated in newer kernels) */
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            int err = ioctl(fd, SIOCBRDELBR, bridge);
            int saved_errno = errno;
            close(fd);
            if (err == 0)
                return 0;
            /* EOPNOTSUPP / ENOTTY means the ioctl path is not supported
             * by the running kernel → fall through to netlink. */
            if (saved_errno != EOPNOTSUPP && saved_errno != ENOTTY) {
                errno = saved_errno;
                return -1;
            }
        }
    }
#endif

    /* Method 2 – netlink (RTM_DELLINK), the modern interface */
    if (br_delbr_netlink(bridge) == 0)
        return 0;

    /* Method 3 – legacy BRCTL_DEL_BRIDGE via SIOCDEVPRIVATE */
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;
        struct ifreq ifr;
        unsigned long args[4];
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
        args[0] = BRCTL_DEL_BRIDGE;
        args[1] = (unsigned long)bridge;
        args[2] = 0;
        args[3] = 0;
        ifr.ifr_data = (char *)args;
        int err = ioctl(fd, SIOCDEVPRIVATE, &ifr);
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return err;
    }
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
 * Set an IPv4 address and netmask on an interface and bring it up.
 * errno from the failing ioctl is preserved across the close().
 */
static int br_set_address(char *bridge, struct in_addr ip, struct in_addr mask)
{
    struct ifreq ifr;
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    int fd, saved_errno;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, bridge, IFNAMSIZ);

    /* Set the address */
    sin->sin_family = AF_INET;
    sin->sin_addr = ip;
    if (ioctl(fd, SIOCSIFADDR, &ifr) < 0)
        goto err;

    /* Set the netmask */
    sin->sin_addr = mask;
    if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0)
        goto err;

    /* Bring the interface up */
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
        goto err;
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
        goto err;

    close(fd);
    return 0;

err:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
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

/* brctl show <bridge> — return IP address and flags */
static int cmd_show(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *bridge = argv[0];
    struct ifreq ifr;
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not open socket: %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, bridge, IFNAMSIZ);

    /* Get IP address */
    char ip_str[INET_ADDRSTRLEN] = "";
    int prefix = 0;
    int has_ip = 0;

    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        has_ip = 1;
    } else if (errno != EADDRNOTAVAIL) {
        /* Real error (not just "no IP assigned") */
        close(fd);
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not show %s: %s", bridge, strerror(errno));
        return -1;
    }

    /* Get netmask and convert to prefix length */
    if (has_ip) {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
        if (ioctl(fd, SIOCGIFNETMASK, &ifr) == 0) {
            unsigned int mask = ntohl(sin->sin_addr.s_addr);
            while (mask & 0x80000000) { prefix++; mask <<= 1; }
        }
    }

    /* Get interface flags */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
    char flags_str[64] = "";
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        if (ifr.ifr_flags & IFF_UP)      strcat(flags_str, "UP ");
        if (ifr.ifr_flags & IFF_RUNNING) strcat(flags_str, "RUNNING ");
    }
    close(fd);

    /* Trim trailing space */
    size_t flen = strlen(flags_str);
    if (flen > 0) flags_str[flen - 1] = '\0';

    if (has_ip && prefix > 0)
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s %s/%d %s", bridge, ip_str, prefix, flags_str);
    else if (has_ip)
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s %s %s", bridge, ip_str, flags_str);
    else
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s %s", bridge, flags_str);
    return 0;
}

/* brctl delif <bridge> <interface> — remove an interface from a bridge */
static int cmd_delif(hypervisor_conn_t *conn, int argc, char *argv[])
{
    int err = -1;
    char *bridge = argv[0];
    char *interface = argv[1];
    struct ifreq ifr;

    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "Could not find interface %s", interface);
        return -1;
    }

    int br_socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
    #ifdef SIOCBRDELIF
        ifr.ifr_ifindex = ifindex;
        err = ioctl(br_socket_fd, SIOCBRDELIF, &ifr);
        if (err < 0)
    #endif
    {
        unsigned long args[4] = { BRCTL_DEL_IF, ifindex, 0, 0 };
        ifr.ifr_data = (char *) args;
        err = ioctl(br_socket_fd, SIOCDEVPRIVATE, &ifr);
    }

    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "Could not remove interface %s from %s: %s", interface, bridge, strerror(errno));
        goto out;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s removed from bridge %s", interface, bridge);
    err = 0;

out:
    close(br_socket_fd);
    return (err);
}

/* brctl list — enumerate all Linux bridges */
static int cmd_list(hypervisor_conn_t *conn, int argc, char *argv[])
{
    DIR *dir = opendir("/sys/class/net/");
    if (!dir) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not list network interfaces: %s", strerror(errno));
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        char bridge_path[512];
        snprintf(bridge_path, sizeof(bridge_path), "/sys/class/net/%s/bridge", entry->d_name);

        struct stat st;
        if (stat(bridge_path, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;

        /* It's a bridge — try to get IP */
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            continue;

        struct ifreq ifr;
        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
        char ip_str[INET_ADDRSTRLEN] = "";
        int prefix = 0;

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, entry->d_name, IFNAMSIZ);

        if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
            inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));

            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, entry->d_name, IFNAMSIZ);
            if (ioctl(fd, SIOCGIFNETMASK, &ifr) == 0) {
                unsigned int mask = ntohl(sin->sin_addr.s_addr);
                while (mask & 0x80000000) { prefix++; mask <<= 1; }
            }
        }
        close(fd);

        if (ip_str[0])
            hypervisor_send_reply(conn, HSC_INFO_OK, 0, "%s %s/%d", entry->d_name, ip_str, prefix);
        else
            hypervisor_send_reply(conn, HSC_INFO_OK, 0, "%s", entry->d_name);
    }
    closedir(dir);

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
   { "show", 1, 1, cmd_show, NULL },
   { "delif", 2, 2, cmd_delif, NULL },
   { "list", 0, 0, cmd_list, NULL },
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
