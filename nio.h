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
#include <stdarg.h>
#include <sys/un.h>
#include <pcap.h>

#define m_min(a,b) (((a) < (b)) ? (a) : (b))

#define NIO_MAX_PKT_SIZE    65535
#define NIO_DEV_MAXLEN      64

enum {
    NIO_TYPE_UDP = 1,
    NIO_TYPE_ETHERNET,
    NIO_TYPE_TAP,
    NIO_TYPE_LINUX_RAW,
    NIO_TYPE_FUSION_VMNET,
    NIO_TYPE_UNIX,
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
    int fd;
    int dev_id;
} nio_linux_raw_t;

typedef struct {
    int fd;
} nio_fusion_vmnet_t;

typedef struct {
    int fd;
    char *local_filename;
    struct sockaddr_un remote_sock;
} nio_unix_t;

typedef struct {
    u_int type;
    void *dptr;
    char *desc;

    union {
        nio_udp_t nio_udp;
        nio_tap_t nio_tap;
        nio_ethernet_t nio_ethernet;
        nio_linux_raw_t nio_linux_raw;
        nio_fusion_vmnet_t nio_fusion_vmnet;
        nio_unix_t nio_unix;
    } u;

    ssize_t (*send)(void *nio, void *pkt, size_t len);
    ssize_t (*recv)(void *nio, void *pkt, size_t len);
    void (*free)(void *nio);

    ssize_t packets_in, packets_out;
    ssize_t bytes_in, bytes_out;

} nio_t;

nio_t *create_nio(void);
void add_nio_desc(nio_t *nio, const char *fmt, ...);
int free_nio(void *data);

ssize_t nio_send(nio_t *nio, void *pkt, size_t len);
ssize_t nio_recv(nio_t *nio, void *pkt, size_t max_len);
void dump_packet(FILE *f_output, u_char *pkt, u_int len);

#endif /* !NIO_H_ */
