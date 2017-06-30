/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2016 GNS3 Technologies Inc.
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

#ifndef HYPERVISOR_IOL_BRIDGE_H_
#define HYPERVISOR_IOL_BRIDGE_H_

#include <netinet/in.h>
#include "ubridge.h"

/* IOL header */

/* offsets */
#define IOL_DST_IDS                     0
#define IOL_SRC_IDS                     2
#define IOL_DST_PORT                    4
#define IOL_SRC_PORT                    5
#define IOL_MSG_TYPE                    6
#define IOL_CHANNEL                     7
/* sizes */
#define IOL_HDR_SIZE                    8
#define IOL_IDS_SIZE                    2
#define IOL_PORT_SIZE                   1
#define IOL_MSG_SIZE                    1
#define IOL_CHANNEL_SIZE                1
/* values */
#define IOL_MSG_TYPE_FREE               0
#define IOL_MSG_TYPE_DATA               1

/* offsets */
#define IOL_PORT_UNIT                   7
#define IOL_PORT_BAY                    3
/* lengths */
#define IOL_PORT_UNIT_LEN               4
#define IOL_PORT_BAY_LEN                4

#define MAX_PORTS                       256
#define MAX_MTU                         0x1000

typedef struct port
{
  unsigned char bay;
  unsigned char unit;
} port_t;

typedef struct
{
  int iol_id;
  int iol_bridge_sock;
  char *parent_bridge_name;
  port_t port;
  struct sockaddr_un iol_sockaddr;
  nio_t *destination_nio;
  packet_filter_t *packet_filters;
  unsigned char header[IOL_HDR_SIZE];
  pcap_capture_t *capture;
  pthread_t tid;
} iol_nio_t;

typedef struct iol_bridge {
  char *name;
  int running;
  int application_id;
  int iol_bridge_sock;
  int sock_lock;
  struct sockaddr_un bridge_sockaddr;
  pthread_t bridge_tid;
  iol_nio_t *port_table;
  struct iol_bridge *next;
} iol_bridge_t;

extern iol_bridge_t *iol_bridge_list;

int hypervisor_iol_bridge_init(void);
int unlock_unix_socket(int fd, const char *name);

#endif /* !HYPERVISOR_IOL_BRIDGE_H_ */
