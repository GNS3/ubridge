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

#ifndef NIO_H_
#define NIO_H_

#include <stdlib.h>
#include <pcap.h>

#define NIO_MAX_PKT_SIZE    2048
#define NIO_DEV_MAXLEN      64

enum {
    NIO_TYPE_UDP = 1,
    NIO_TYPE_ETHERNET,
    NIO_TYPE_TAP,
};

typedef struct {
    int fd;
    int local_port;
    int remote_port;
    char *remote_host;
} nio_udp_t;

typedef struct {
    int fd;
} nio_tap_t;

typedef struct {
    pcap_t *pcap_dev;
} nio_ethernet_t;

typedef struct {
    u_int type;
    void *dptr;

    union {
        nio_udp_t nio_udp;
        nio_tap_t nio_tap;
        nio_ethernet_t nio_ethernet;
    } u;

    ssize_t (*send)(void *nio, void *pkt, size_t len);
    ssize_t (*recv)(void *nio, void *pkt, size_t len);
    void (*free)(void *nio);

} nio_t;

nio_t *create_nio(void);
int free_nio(void *data);

ssize_t nio_send(nio_t *nio, void *pkt, size_t len);
ssize_t nio_recv(nio_t *nio, void *pkt, size_t max_len);

#endif /* !NIO_H_ */
