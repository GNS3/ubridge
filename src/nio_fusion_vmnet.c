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

 /* Most of this code was authored by Regis "HPReg" Duchesne, hpreg@vmware.com, on 2015/09/09. */

#include <sys/types.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/sys_domain.h>
#include <strings.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "ubridge.h"
#include "nio_fusion_vmnet.h"

/* Create a socket and connect it to the vmnet kext. */
static int nio_fusion_vmnet_open_socket(char *vmnet_name)
{
   int fd;
   struct ctl_info info;
   struct sockaddr_ctl addr;
   socklen_t opt_len;
   u_int32_t api_version;
   u_int32_t flags = IFF_UP | IFF_PROMISC;
   int hub_num;

   if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) < 0 ) {
      fprintf(stderr, "nio_fusion_vmnet_open_socket: socket: %s\n", strerror(errno));
      return (-1);
   }

   memset((void *)&info, 0, sizeof(info));
   strncpy(info.ctl_name, VMNET_KEXT_NAME, sizeof(info.ctl_name));

   if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
      fprintf(stderr, "nio_fusion_vmnet_open_socket: CTLIOCGINFO: %s\n", strerror(errno));
      close(fd);
      return (-1);
   }

   memset(&addr, 0, sizeof(addr));
   addr.sc_len = sizeof addr;
   addr.sc_family = AF_SYSTEM;
   addr.ss_sysaddr = AF_SYS_CONTROL;
   addr.sc_id = info.ctl_id;

   /* This call requires root privileges. */
   if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      fprintf(stderr, "nio_fusion_vmnet_open_socket: connect: %s\n", strerror(errno));
      return (-1);
   }

   /* Retrieve and check the version of the vmnet kext. VMware bumps the major version of the vmnet kext
      every time they change its ABI in an incompatible way. However, such changes are not frequent */

   opt_len = sizeof(api_version);
   if (getsockopt(fd, SYSPROTO_CONTROL, VMNET_SO_APIVERSION, &api_version, &opt_len) == -1) {
      fprintf(stderr, "nio_fusion_vmnet_open_socket: getsockopt: %s\n", strerror(errno));
      return (-1);
   }

   /* last API version bump (version 5 to 6) occurred on 2009/05/13, right before VMware Fusion 2.0.5 shipped. */
   if (VMNET_ABI_VERSION_MAJOR(api_version) != 6) {
      fprintf(stderr, "nio_fusion_vmnet_open_socket: required API version is 6: %s\n", strerror(errno));
      return (-1);
   }

   /* The VMware Fusion network interface vmnet<N> is always connected to
     (virtual) hub number N. Connect our socket to another port on that hub. */
   if (sscanf(vmnet_name, "vmnet%d", &hub_num) != 1) {
      fprintf(stderr, "nio_fusion_vmnet_open_socket: invalid vmnet interface name\n");
      return (-1);
   }

   if (setsockopt(fd, SYSPROTO_CONTROL, VMNET_SO_BINDTOHUB, &hub_num, sizeof(hub_num)) < 0) {
      fprintf(stderr, "nio_fusion_vmnet_open_socket: setsockopt: %s\n", strerror(errno));
      return (-1);
   }

   /* Put our port of the hub in promiscuous mode, to allow it to receive all 
      network traffic that goes through the hub. */

   if (setsockopt(fd, SYSPROTO_CONTROL, VMNET_SO_IFFLAGS, &flags, sizeof(flags)) < 0) {
      fprintf(stderr, "nio_fusion_vmnet_open_socket: setsockopt: %s\n", strerror(errno));
      return (-1);
   }

   return (fd);
}

static void nio_fusion_vmnet_free(nio_fusion_vmnet_t *nio_fusion_vmnet)
{
   if (nio_fusion_vmnet->fd != -1)
      close(nio_fusion_vmnet->fd);
}

static ssize_t nio_fusion_vmnet_send(nio_tap_t *nio_fusion_vmnet, void *pkt, size_t pkt_len)
{
   return (write(nio_fusion_vmnet->fd, pkt, pkt_len));
}

static ssize_t nio_fusion_vmnet_recv(nio_tap_t *nio_fusion_vmnet, void *pkt, size_t max_len)
{
   return (read(nio_fusion_vmnet->fd, pkt, max_len));
}

/* Create a new NIO Fusion VMnet */
nio_t *create_nio_fusion_vmnet(char *vmnet_name)
{
   nio_fusion_vmnet_t *nio_fusion_vmnet;
   nio_t *nio;

   if (!(nio = create_nio()))
      return NULL;

   nio_fusion_vmnet = &nio->u.nio_fusion_vmnet;

   if (strncmp("vmnet", vmnet_name, 5) != 0) {
      fprintf(stderr, "create_nio_fusion_vmnet: bad VMnet interface string specified.\n");
      free_nio(nio);
      return NULL;
   }

   nio_fusion_vmnet->fd = nio_fusion_vmnet_open_socket(vmnet_name);

   if (nio_fusion_vmnet->fd < 0) {
      free_nio(nio);
      return NULL;
   }

   nio->type = NIO_TYPE_FUSION_VMNET;
   nio->send = (void *)nio_fusion_vmnet_send;
   nio->recv = (void *)nio_fusion_vmnet_recv;
   nio->free = (void *)nio_fusion_vmnet_free;
   nio->dptr = &nio->u.nio_fusion_vmnet;

   return nio;
}
