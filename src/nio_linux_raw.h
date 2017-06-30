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

#ifndef NIO_LINUX_RAW_H_
#define NIO_LINUX_RAW_H_

#include "nio.h"

#define VLAN_HEADER_LEN 4

typedef struct {
    u_int16_t vlan_tp_id;
    u_int16_t vlan_tci;
} vlan_tag_t;

nio_t *create_nio_linux_raw(char *dev_name);

#endif /* !NIO_LINUX_RAW_H_ */
