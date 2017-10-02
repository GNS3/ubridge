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

#ifndef UBRIDGE_H_
#define UBRIDGE_H_

#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#ifdef CYGWIN
/* Needed for pcap_open() flags */
#define HAVE_REMOTE
#endif

#include <pcap.h>

#include "nio.h"
#include "packet_filter.h"

#define NAME          "ubridge"
#define VERSION       "0.9.14"
#define CONFIG_FILE   "ubridge.ini"

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE  1
#endif

#define handle_error_en(en, msg) \
        do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

typedef struct {
    pcap_t *fd;
    pcap_dumper_t *dumper;
    pthread_mutex_t lock;
} pcap_capture_t;

typedef struct bridge {
  char *name;
  int running;
  pthread_t source_tid;
  pthread_t destination_tid;
  nio_t *source_nio;
  nio_t *destination_nio;
  pcap_capture_t *capture;
  packet_filter_t *packet_filters;
  struct bridge *next;
} bridge_t;

extern bridge_t *bridge_list;
extern pthread_mutex_t global_lock;
extern int debug_level;

void ubridge_reset();
void *source_nio_listener(void *data);
void *destination_nio_listener(void *data);

#endif /* !UBRIDGE_H_ */
