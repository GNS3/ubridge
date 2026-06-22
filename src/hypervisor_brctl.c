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
 * Create a Linux bridge device (SIOCBRADDBR).
 * errno from the failing ioctl is preserved across the close().
 */
static int br_addbr(char *bridge)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int err, saved_errno;

    if (fd < 0)
        return -1;

#ifdef SIOCBRADDBR
    err = ioctl(fd, SIOCBRADDBR, bridge);
    if (err < 0)
#endif
    {
        struct ifreq ifr;
        unsigned long args[4];

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
        args[0] = BRCTL_ADD_BRIDGE;
        args[1] = (unsigned long)bridge;
        args[2] = 0;
        args[3] = 0;
        ifr.ifr_data = (char *)args;
        err = ioctl(fd, SIOCDEVPRIVATE, &ifr);
    }

    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return err;
}

/*
 * Delete a Linux bridge device (SIOCBRDELBR).
 * errno from the failing ioctl is preserved across the close().
 */
static int br_delbr(char *bridge)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int err, saved_errno;

    if (fd < 0)
        return -1;

#ifdef SIOCBRDELBR
    err = ioctl(fd, SIOCBRDELBR, bridge);
    if (err < 0)
#endif
    {
        struct ifreq ifr;
        unsigned long args[4];

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
        args[0] = BRCTL_DEL_BRIDGE;
        args[1] = (unsigned long)bridge;
        args[2] = 0;
        args[3] = 0;
        ifr.ifr_data = (char *)args;
        err = ioctl(fd, SIOCDEVPRIVATE, &ifr);
    }

    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return err;
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


/* brctl commands */
static hypervisor_cmd_t brctl_cmd_array[] = {
   { "addif", 2, 2, cmd_addif, NULL },
   { "create", 1, 1, cmd_create, NULL },
   { "delete", 1, 1, cmd_delete, NULL },
   { "addip", 2, 2, cmd_addip, NULL },
   { "setup", 2, 2, cmd_setup, NULL },
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
