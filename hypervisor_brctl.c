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
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_bridge.h>
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
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not found interface %s", interface);
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


/* brctl commands */
static hypervisor_cmd_t brctl_cmd_array[] = {
   { "addif", 2, 2, cmd_addif, NULL },
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
