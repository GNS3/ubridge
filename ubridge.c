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

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>

#include "ubridge.h"
#include "parse.h"
#include "pcap_capture.h"


static void bridge_nios(nio_t *source_nio, nio_t *destination_nio, pcap_capture_t *capture)
{
  ssize_t bytes_received, bytes_sent;
  unsigned char pkt[NIO_MAX_PKT_SIZE];

  while (1) {

    /* received from the source NIO */
    bytes_received = nio_recv(source_nio, &pkt, NIO_MAX_PKT_SIZE);
    if (bytes_received == -1) {
        if (errno == ECONNREFUSED)
           continue;
        perror("recv");
        break;
    }

    /* printf("received %zd bytes\n", bytes_received); */

    /* dump the packet to a PCAP file if capture is activated */
    pcap_capture_packet(capture, pkt, bytes_received);

    /* send what we received to the destination NIO */
    bytes_sent = nio_send(destination_nio, pkt, bytes_received);
    if (bytes_sent == -1) {
       switch (errno) {
       /* Socket file doesn't exist */
       case ENOENT:
       case ECONNREFUSED:
         continue;
       default:
         perror("send");
         break;
       }
    }
    /* printf("sent %zd bytes\n", bytes_sent); */
  }
}

/* Source NIO thread */
static void *source_nio_listener(void *data)
{
  bridge_t *bridge = data;

  printf("Source NIO listener thread for %s has started\n", bridge->name);
  if (bridge->source_nio && bridge->destination_nio)
    /* bridges from the source NIO to the destination NIO */
    bridge_nios(bridge->source_nio, bridge->destination_nio, bridge->capture);
  printf("Source NIO listener thread for %s has stopped\n", bridge->name);
  pthread_exit(NULL);
}

/* Destination NIO thread */
static void *destination_nio_listener(void *data)
{
  bridge_t *bridge = data;

  printf("Destination NIO listener thread for %s has started\n", bridge->name);
  if (bridge->source_nio && bridge->destination_nio)
    /* bridges from the destination NIO to the source NIO */
    bridge_nios(bridge->destination_nio, bridge->source_nio, bridge->capture);
  printf("Destination NIO listener thread for %s has stopped\n", bridge->name);
  pthread_exit(NULL);
}

static void free_bridges(bridge_t *bridge)
{
  bridge_t *next;

  while (bridge != NULL) {
    if (bridge->name)
       free(bridge->name);
    pthread_cancel(bridge->source_tid);
    pthread_join(bridge->source_tid, NULL);
    pthread_cancel(bridge->destination_tid);
    pthread_join(bridge->destination_tid, NULL);
    free_nio(bridge->source_nio);
    free_nio(bridge->destination_nio);
    free_pcap_capture(bridge->capture);
    next = bridge->next;
    free(bridge);
    bridge = next;
  }
}

static void create_threads(pthread_attr_t *thread_attrs, bridge_t *bridge)
{
    int s;

    while (bridge != NULL) {
       s = pthread_create(&(bridge->source_tid), thread_attrs, &source_nio_listener, bridge);
       if (s != 0)
         handle_error_en(s, "pthread_create");
       s = pthread_create(&(bridge->destination_tid), thread_attrs, &destination_nio_listener, bridge);
       if (s != 0)
         handle_error_en(s, "pthread_create");
       bridge = bridge->next;
    }
}

static void ubridge(char *config_file)
{
  int sig;
  int s;
  sigset_t sigset;
  pthread_attr_t thread_attrs;

  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGTERM);
  sigaddset(&sigset, SIGHUP);
  pthread_sigmask(SIG_BLOCK, &sigset, NULL);

  s = pthread_attr_init(&thread_attrs);
  if (s != 0)
    handle_error_en(s, "pthread_attr_init");
  s = pthread_attr_setdetachstate(&thread_attrs, PTHREAD_CREATE_DETACHED);
  if (s != 0)
    handle_error_en(s, "pthread_attr_setdetachstate");

  while (1) {
    bridge_t *bridges = NULL;
    if (!parse_config(config_file, &bridges))
      break;

    create_threads(&thread_attrs, bridges);
    sigwait (&sigset, &sig);
    printf("Received signal %d\n", sig);
    free_bridges(bridges);
    if (sig == SIGTERM || sig == SIGINT)
      break;
  }

  printf("Exiting\n");
  pthread_attr_destroy(&thread_attrs);
}

static void print_usage(const char *program_name)
{
  printf("Usage: %s [OPTION]\n"
         "\n"
         "Options:\n"
         "  -h                   print this message and exit\n"
         "  -f FILE              specify a INI configuration file (default: %s)\n"
         "  -v                   print version and exit\n",
         program_name,
         CONFIG_FILE);
}

int main(int argc, char **argv)
{
  char opt;
  char *config_file = CONFIG_FILE;

  while ((opt = getopt(argc, argv, "hvf:")) != -1) {
    switch (opt) {
	  case 'v':
	    printf("%s version %s\n", NAME, VERSION);
	    exit(EXIT_SUCCESS);
	  case 'h':
	    print_usage(argv[0]);
	    exit(EXIT_SUCCESS);
	  case 'f':
        config_file = optarg;
        break;
      default:
        exit(EXIT_FAILURE);
	}
  }

  ubridge(config_file);
  return (EXIT_SUCCESS);
}
