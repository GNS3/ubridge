/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2017 GNS3 Technologies Inc.
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

#ifndef FILTER_H_
#define FILTER_H_

#include <sys/types.h>
#include <stdlib.h>

enum {
    FILTER_TYPE_FREQUENCY_DROP = 1,
    FILTER_TYPE_PACKET_LOSS,
    FILTER_TYPE_DELAY,
    FILTER_TYPE_CORRUPT,
    FILTER_TYPE_BPF,
};

enum {
   FILTER_ACTION_DROP = 0,
   FILTER_ACTION_PASS,
   FILTER_ACTION_ALTER,
   FILTER_ACTION_DUPLICATE,
};

typedef struct packet_filter {
   u_int type;
   char *name;
   void *data;
   int (*setup)(void **opt, int argc, char *argv[]);
   int (*handler)(void *pkt, size_t len, void *opt);
   void (*free)(void **opt);
   struct packet_filter *next;
} packet_filter_t;

int add_packet_filter(packet_filter_t **packet_filters, char *filter_name, char *filter_type, int argc, char *argv[]);
packet_filter_t *find_packet_filter(packet_filter_t *packet_filters, char *filter_name);
int delete_packet_filter(packet_filter_t **packet_filters, char *filter_name);
void free_packet_filters(packet_filter_t *filter);

#endif /* !FILTER_H_ */
