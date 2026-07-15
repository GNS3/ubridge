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
 * tap — persistent TAP device lifecycle management.
 *
 * Creates/destroys persistent TAP devices (/dev/net/tun) and assigns
 * ownership so that an unprivileged emulator (QEMU) can open them. This
 * lets ubridge act purely as a control-plane daemon: the data plane flows
 * kernel-side between the persistent TAP and a kernel bridge (see the
 * brctl module), never through ubridge's user-space NIO relay.
 *
 * Design: stateless. A persistent TAP survives its creating fd being
 * closed, so each command opens /dev/net/tun, re-attaches to the named
 * device with TUNSETIFF, performs the ioctl, and closes the fd. ubridge
 * holds no per-device fd or registry.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "hypervisor.h"
#include "hypervisor_tap.h"

/* IFF_TUN_EXCL has been in <linux/if_tun.h> since 2.6.26; guard anyway. */
#ifndef IFF_TUN_EXCL
#define IFF_TUN_EXCL 0x8000
#endif

/*
 * Return 0 if <name> is an existing network device, -ENODEV otherwise.
 * set_owner and delete must refuse a non-existent name: TUNSETIFF would
 * otherwise silently CREATE a transient TAP instead of failing. Mirrors the
 * if_nametoindex existence check used by the brctl module (e.g. br_enslave_if).
 */
static int tap_require_existing(const char *name)
{
    return if_nametoindex(name) ? 0 : -ENODEV;
}

/* --------------------------------------------------------------------------
 * Low-level helpers — each returns 0 on success or a negative errno.
 * -------------------------------------------------------------------------- */

/*
 * Open /dev/net/tun and attach to a TAP device named <name>.
 * <extra_flags> is OR'd into IFF_TAP|IFF_NO_PI (create passes IFF_TUN_EXCL
 * so re-attaching to an existing device fails with -EBUSY; set_owner and
 * delete pass 0 because they must attach to an already-persistent device).
 * Returns the fd on success, or a negative errno on failure.
 */
static int tap_attach(const char *name, int extra_flags)
{
    struct ifreq ifr;
    int fd;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        return -errno;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI | extra_flags;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }

    return fd;
}

/* Create a persistent TAP device named <name>. */
static int tap_create(const char *name)
{
    int fd, ret;

    fd = tap_attach(name, IFF_TUN_EXCL);
    if (fd < 0)
        return fd;

    if (ioctl(fd, TUNSETPERSIST, 1) < 0) {
        ret = -errno;
        close(fd);
        return ret;
    }

    close(fd);
    return 0;
}

/* Set the owner (uid) of a persistent TAP device named <name>. */
static int tap_set_owner(const char *name, uid_t uid)
{
    int fd, ret;

    ret = tap_require_existing(name);
    if (ret < 0)
        return ret;

    fd = tap_attach(name, 0);
    if (fd < 0)
        return fd;

    if (ioctl(fd, TUNSETOWNER, uid) < 0) {
        ret = -errno;
        close(fd);
        return ret;
    }

    close(fd);
    return 0;
}

/* Delete a persistent TAP device named <name>. */
static int tap_delete(const char *name)
{
    int fd, ret;

    ret = tap_require_existing(name);
    if (ret < 0)
        return ret;

    fd = tap_attach(name, 0);
    if (fd < 0)
        return fd;

    if (ioctl(fd, TUNSETPERSIST, 0) < 0) {
        ret = -errno;
        close(fd);
        return ret;
    }

    close(fd);
    return 0;
}

/* --------------------------------------------------------------------------
 * Command handlers
 * -------------------------------------------------------------------------- */

/* tap create <name> */
static int cmd_create(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *name = argv[0];
    int err;

    if (strlen(name) >= IFNAMSIZ) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "TAP name %s too long (max %d)", name, IFNAMSIZ - 1);
        return -1;
    }

    err = tap_create(name);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not create TAP %s: %s", name, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Persistent TAP %s created", name);
    return 0;
}

/* tap set_owner <name> <uid> */
static int cmd_set_owner(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *name = argv[0];
    char *end;
    unsigned long uid;
    int err;

    if (strlen(name) >= IFNAMSIZ) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "TAP name %s too long (max %d)", name, IFNAMSIZ - 1);
        return -1;
    }

    errno = 0;
    uid = strtoul(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' || uid > 0xFFFFFFFFu) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "Invalid uid %s", argv[1]);
        return -1;
    }

    err = tap_set_owner(name, (uid_t)uid);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not set owner on TAP %s: %s", name, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Owner %u set on TAP %s", (unsigned)uid, name);
    return 0;
}

/* tap delete <name> */
static int cmd_delete(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *name = argv[0];
    int err;

    if (strlen(name) >= IFNAMSIZ) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "TAP name %s too long (max %d)", name, IFNAMSIZ - 1);
        return -1;
    }

    err = tap_delete(name);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "Could not delete TAP %s: %s", name, strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "TAP %s deleted", name);
    return 0;
}

/* --------------------------------------------------------------------------
 * Command table + module registration
 * -------------------------------------------------------------------------- */

static hypervisor_cmd_t tap_cmd_array[] = {
   { "create",    1, 1, cmd_create,    NULL },
   { "set_owner", 2, 2, cmd_set_owner, NULL },
   { "delete",    1, 1, cmd_delete,    NULL },
   { NULL, -1, -1, NULL, NULL },
};

/* Hypervisor tap initialization */
int hypervisor_tap_init(void)
{
   hypervisor_module_t *module;

   module = hypervisor_register_module("tap", NULL);
   assert(module != NULL);

   hypervisor_register_cmd_array(module, tap_cmd_array);
   return(0);
}
