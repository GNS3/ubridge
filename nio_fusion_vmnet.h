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

#ifndef NIO_FUSION_VMNET_H_
#define NIO_FUSION_VMNET_H_

#include "nio.h"

#define VMNET_KEXT_NAME "com.vmware.kext.vmnet"

/* The 3 calls to communication with the vmnet kext. */
enum {
   VMNET_SO_APIVERSION = 0, /* API version will never change. */
   VMNET_SO_BINDTOHUB  = 3,
   VMNET_SO_IFFLAGS    = 6,
};

#define VMNET_ABI_VERSION_MAJOR(v) ((v) >> 16)

nio_t *create_nio_fusion_vmnet(char *vmnet_name);

#endif /* !NIO_FUSION_VMNET_H_ */
