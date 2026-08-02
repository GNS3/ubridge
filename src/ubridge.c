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
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>

#ifdef USE_SYSTEM_INIPARSER
#include <iniparser.h>
#else
#include "iniparser/iniparser.h"
#endif

#include "ubridge.h"
#include "parse.h"
#include "pcap_capture.h"
#include "packet_filter.h"
#include "delay_line.h"
#include "hypervisor.h"
#include "hypervisor_iol_bridge.h"

char *config_file = CONFIG_FILE;
pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;
bridge_t *bridge_list = NULL;
int debug_level = 0;
int hypervisor_mode = 0;

/* Send callback for the delay line's release thread: forward a due packet out
 * the transmitting NIO and account for it. (When no delay filter is present,
 * bridge_nios sends inline instead and does this accounting itself.) */
static ssize_t delay_send_cb(void *ctx, const void *pkt, size_t len)
{
   nio_t *tx_nio = ctx;
   ssize_t bytes_sent;

   bytes_sent = nio_send(tx_nio, (void *)pkt, len);
   if (bytes_sent == -1) {
      perror("send");
      return -1;
   }
   tx_nio->packets_out++;
   tx_nio->bytes_out += bytes_sent;
   return bytes_sent;
}

/* pthread cleanup helper: destroy whichever delay line is currently active.
 * bridge_nios() reassigns its local `delay_line` as filters come and go, so
 * the handler reads it through a pointer-to-pointer — capturing the pointer's
 * value at push time would go stale when the line is recreated. */
static void delay_line_destroy_indir(void *arg)
{
   delay_line_destroy(*(delay_line_t **)arg);
}

static int bridge_nios(nio_t *rx_nio, nio_t *tx_nio, bridge_t *bridge)
{
  ssize_t bytes_received, bytes_sent;
  unsigned char pkt[NIO_MAX_PKT_SIZE];
  int drop_packet;
  int latency_ms = 0, jitter_ms = 0;
  delay_line_t *delay_line = NULL;
  int rc = 0;

  /* The delay line is managed lazily inside the loop, not created once at
   * start: GNS3 starts the bridge first and applies packet filters only
   * afterwards (gns3-server add_ubridge_udp_connection: `bridge start` then
   * `_ubridge_apply_filters`), and filters can be reset/re-added at runtime.
   * So we re-read the delay config on each packet and (re)create/destroy the
   * line to match. delay_line always holds the current line or NULL. */
  pthread_cleanup_push(delay_line_destroy_indir, &delay_line);

  while (1) {

    /* receive from the receiving NIO */
    drop_packet = FALSE;
    bytes_received = nio_recv(rx_nio, &pkt, NIO_MAX_PKT_SIZE);
    if (bytes_received == -1) {
        perror("recv");
        if (errno == ECONNREFUSED || errno == ENETDOWN)
           continue;
        rc = -1;
        break;
    }

    if (bytes_received > NIO_MAX_PKT_SIZE) {
        fprintf(stderr, "received frame is %zd bytes (maximum is %d bytes)\n", bytes_received, NIO_MAX_PKT_SIZE);
        continue;
    }

    rx_nio->packets_in++;
    rx_nio->bytes_in += bytes_received;

    if (debug_level > 0) {
        if (rx_nio == bridge->source_nio)
           printf("Received %zd bytes on bridge '%s' (source NIO)\n", bytes_received, bridge->name);
        else
           printf("Received %zd bytes on bridge '%s' (destination NIO)\n", bytes_received, bridge->name);
        if (debug_level > 1)
            dump_packet(stdout, pkt, bytes_received);
    }

    int have_delay;

    /* Lock the shared filter list while we walk it — the hypervisor thread
     * mutates it via add/delete/reset_packet_filter under global_lock too. */
    pthread_mutex_lock(&global_lock);
    if (bridge->packet_filters != NULL) {
         int pkt_dir = (rx_nio == bridge->source_nio) ? PKT_DIR_TX : PKT_DIR_RX;
         packet_filter_t *filter = bridge->packet_filters;
         packet_filter_t *next;
         while (filter != NULL) {
             if (!filter->enabled) {   /* paused: bypass this filter */
                 filter = filter->next;
                 continue;
             }
             if (filter->handler(pkt, bytes_received, filter->data, pkt_dir) == FILTER_ACTION_DROP) {
                 if (debug_level > 0)
                    printf("Packet dropped by packet filter '%s' on bridge '%s'\n", filter->name, bridge->name);
                 drop_packet = TRUE;
                 break;
             }
             next = filter->next;
             filter = next;
         }
     }
    /* snapshot the delay config while the list is stable */
    have_delay = packet_filter_get_delay(bridge->packet_filters, &latency_ms, &jitter_ms);
    pthread_mutex_unlock(&global_lock);

    if (drop_packet == TRUE)
       continue;

    /* dump the packet to a PCAP file if capture is activated */
    pcap_capture_packet(bridge->capture, pkt, bytes_received);

    /* (re)sync the delay line using the snapshotted config — create/destroy
     * outside the lock so a join inside destroy doesn't block other bridges. */
    {
       int cur_lat = -1, cur_jit = -1;
       delay_line_config(delay_line, &cur_lat, &cur_jit);  /* current line's config, or -1 */
       if (have_delay) {
          if (delay_line == NULL || latency_ms != cur_lat || jitter_ms != cur_jit) {
             delay_line_t *old = delay_line;
             delay_line = NULL;                 /* visible as NULL to a cancel-time cleanup */
             delay_line_destroy(old);
             delay_line = delay_line_create(latency_ms, jitter_ms, delay_send_cb, tx_nio);
             if (delay_line == NULL)
                fprintf(stderr, "bridge '%s': could not create delay line, forwarding without delay\n", bridge->name);
          }
       } else if (delay_line != NULL) {
          delay_line_t *old = delay_line;
          delay_line = NULL;
          delay_line_destroy(old);
       }
    }

    if (delay_line) {
        /* hand the packet to the release thread; never block the recv loop.
         * On enqueue failure (out of memory or queue full) the packet is dropped. */
        if (delay_line_enqueue(delay_line, pkt, bytes_received) != 0 && debug_level > 0)
           printf("Packet dropped by delay line on bridge '%s'\n", bridge->name);
        continue;
    }

    /* send what we received to the transmitting NIO */
    bytes_sent = nio_send(tx_nio, pkt, bytes_received);
    if (bytes_sent == -1) {
        perror("send");

        /* EINVAL can be caused by sending to a blackhole route, this happens if a NIC link status changes */
        if (errno == ECONNREFUSED || errno == ENETDOWN || errno == EINVAL)
           continue;

        /* The linux TAP driver returns EIO if the device is not up.
           From the ubridge side this is not an error, so we should ignore it. */
        if (tx_nio->type == NIO_TYPE_TAP && errno == EIO)
            continue;

        rc = -1;
        break;
    }

    tx_nio->packets_out++;
    tx_nio->bytes_out += bytes_sent;
  }

  /* runs delay_line_destroy (no-op when no delay filter), joining the release
   * thread and freeing any queued packets. On pthread_cancel the cleanup
   * stack runs it instead and this line is never reached. */
  pthread_cleanup_pop(1);
  return rc;
}

/* Source NIO thread */
void *source_nio_listener(void *data)
{
  bridge_t *bridge = data;

  printf("Source NIO listener thread for %s has started\n", bridge->name);
  if (bridge->source_nio && bridge->destination_nio)
    /* bridges from the source NIO to the destination NIO */
    if (bridge_nios(bridge->source_nio, bridge->destination_nio, bridge) == -1) {
        fprintf(stderr, "Source NIO listener thread for %s has stopped because of an error: %s \n", bridge->name, strerror(errno));
        exit(EXIT_FAILURE);
    }
  printf("Source NIO listener thread for %s has stopped\n", bridge->name);
  pthread_exit(NULL);
}

/* Destination NIO thread */
void *destination_nio_listener(void *data)
{
  bridge_t *bridge = data;

  printf("Destination NIO listener thread for %s has started\n", bridge->name);
  if (bridge->source_nio && bridge->destination_nio)
      /* bridges from the destination NIO to the source NIO */
      if (bridge_nios(bridge->destination_nio, bridge->source_nio, bridge) == -1) {
         fprintf(stderr, "Destination NIO listener thread for %s has stopped because of an error: %s \n", bridge->name, strerror(errno));
         exit(EXIT_FAILURE);
      }
  printf("Destination NIO listener thread for %s has stopped\n", bridge->name);
  pthread_exit(NULL);
}

static void free_bridges(bridge_t *bridge)
{
  bridge_t *next;

  while (bridge != NULL) {
    if (bridge->name)
       free(bridge->name);
    if (bridge->running) {
       pthread_cancel(bridge->source_tid);
       pthread_join(bridge->source_tid, NULL);
       bridge->source_tid = 0;
       pthread_cancel(bridge->destination_tid);
       pthread_join(bridge->destination_tid, NULL);
       bridge->destination_tid = 0;
    }
    free_nio(bridge->source_nio);
    free_nio(bridge->destination_nio);
    free_pcap_capture(bridge->capture);
    free_packet_filters(bridge->packet_filters);
    next = bridge->next;
    free(bridge);
    bridge = next;
  }
}

static void free_iol_bridges(iol_bridge_t *bridge)
{
  iol_bridge_t *next;
  int i;

  while (bridge != NULL) {
    if (bridge->name)
       free(bridge->name);

    if (bridge->running) {
       pthread_cancel(bridge->bridge_tid);
       pthread_join(bridge->bridge_tid, NULL);
       bridge->bridge_tid = 0;

       for (i = 0; i < MAX_PORTS; i++) {
           if (bridge->port_table[i].destination_nio != NULL) {
              pthread_cancel(bridge->port_table[i].tid);
              pthread_join(bridge->port_table[i].tid, NULL);
              bridge->port_table[i].tid = 0;
              /* destroy delay lines (joins their release threads) before
               * freeing the NIO / closing the IOL socket they send through */
              delay_line_destroy(bridge->port_table[i].delay_line_nio);
              delay_line_destroy(bridge->port_table[i].delay_line_iol);
              free_pcap_capture(bridge->port_table[i].capture);
              free_packet_filters(bridge->port_table[i].packet_filters);
              free_nio(bridge->port_table[i].destination_nio);
          }
       }
       free(bridge->port_table);
    }

    /* close after delay lines are torn down: their release threads sendto
     * this socket, so they must be joined first */
    close(bridge->iol_bridge_sock);
    unlink(bridge->bridge_sockaddr.sun_path);
    if ((unlock_unix_socket(bridge->sock_lock, bridge->bridge_sockaddr.sun_path)) == -1)
       fprintf(stderr, "failed to unlock %s\n", bridge->bridge_sockaddr.sun_path);

    next = bridge->next;
    free(bridge);
    bridge = next;
  }
}

static void create_threads(bridge_t *bridge)
{
    int s;

    while (bridge != NULL) {
       s = pthread_create(&(bridge->source_tid), NULL, &source_nio_listener, bridge);
       if (s != 0)
         handle_error_en(s, "pthread_create");
       s = pthread_create(&(bridge->destination_tid), NULL, &destination_nio_listener, bridge);
       if (s != 0)
         handle_error_en(s, "pthread_create");
       bridge = bridge->next;
    }
}

void ubridge_reset()
{
   free_bridges(bridge_list);
   free_iol_bridges(iol_bridge_list);
}

/* Generic signal handler */
void signal_gen_handler(int sig)
{
   switch(sig) {
      case SIGTERM:
      case SIGINT:
         /* CTRL+C has been pressed */
         if (hypervisor_mode)
            hypervisor_stopsig();
         break;
         /* SIGHUP: configuration reload */
      case SIGHUP:
         break;
      default:
         fprintf(stderr, "Unhandled signal %d\n", sig);
   }
}

int iniparser_error_handler(const char *format, ...)
{
  int ret;
  va_list argptr;
  char *syntax_error = strstr(format, "iniparser: syntax error");

  if(syntax_error != NULL) {
     va_start(argptr, format);
     char *filename = va_arg(argptr, char *);
     int lineno = va_arg(argptr, int);
     ret = fprintf(stderr, "iniparser: syntax error in %s on line %d\n", filename, lineno);
     va_end(argptr);
  }
  else {
     va_start(argptr, format);
     ret = vfprintf(stderr, format, argptr);
     va_end(argptr);
  }

  return ret;
}

static void ubridge(char *hypervisor_ip_address, int hypervisor_tcp_port, char *hypervisor_socket_path)
{
   if (hypervisor_mode) {
       struct sigaction act;

       memset(&act, 0, sizeof(act));
       act.sa_handler = signal_gen_handler;
       act.sa_flags = SA_RESTART;
       sigaction(SIGHUP, &act, NULL);
       sigaction(SIGTERM, &act, NULL);
       sigaction(SIGINT, &act, NULL);
       sigaction(SIGPIPE, &act, NULL);

      run_hypervisor(hypervisor_ip_address, hypervisor_tcp_port, hypervisor_socket_path);
      free_bridges(bridge_list);
      free_iol_bridges(iol_bridge_list);
   }
   else {
      sigset_t sigset;
      int sig;

      iniparser_set_error_callback(&iniparser_error_handler);
      sigemptyset(&sigset);
      sigaddset(&sigset, SIGINT);
      sigaddset(&sigset, SIGTERM);
      sigaddset(&sigset, SIGHUP);
      pthread_sigmask(SIG_BLOCK, &sigset, NULL);

      while (1) {
         if (!parse_config(config_file, &bridge_list))
            break;
         create_threads(bridge_list);
         sigwait(&sigset, &sig);

         free_bridges(bridge_list);
         bridge_list = NULL;
         if (sig == SIGTERM || sig == SIGINT)
            break;
         printf("Reloading configuration\n");
     }
   }
}

/* Display all network devices on this host */
static void display_network_devices(void)
{
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *device_list, *device;
   int res;

   printf("Network device list:\n\n");

   res = pcap_findalldevs(&device_list, pcap_errbuf);

   if (res < 0) {
      fprintf(stderr, "PCAP: unable to find device list (%s)\n", pcap_errbuf);
      return;
   }

   for(device = device_list; device; device = device->next)
      printf("  %s => %s\n", device->name, device->description ? device->description : "no description");
   printf("\n");

   pcap_freealldevs(device_list);
}

static void print_usage(const char *program_name)
{
  printf("Usage: %s [OPTION]\n"
         "\n"
         "Options:\n"
         "  -h                           : Print this message and exit\n"
         "  -f <file>                    : Specify a INI configuration file (default: %s)\n"
         "  -H [<ip_address>:]<tcp_port> : Hypervisor mode over TCP (default bind: 127.0.0.1)\n"
         "  -U <socket_path>             : Hypervisor mode over UNIX socket (recommended)\n"
         "  -e                           : Display all available network devices and exit\n"
         "  -d <level>                   : Debug level\n"
         "  -v                           : Print version and exit\n",
         program_name,
         CONFIG_FILE);
}

int main(int argc, char **argv)
{
  int hypervisor_tcp_port = 0;
  char *hypervisor_ip_address = NULL;
  char *hypervisor_socket_path = NULL;
  int opt;
  char *index;
  size_t len;

  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);

  while ((opt = getopt(argc, argv, "hved:f:H:U:")) != -1) {
    switch (opt) {
      case 'H':
        hypervisor_mode = 1;
        index = strrchr(optarg, ':');
        if (!index) {
           hypervisor_tcp_port = atoi(optarg);
        } else {
           len = index - optarg;
           hypervisor_ip_address = realloc(hypervisor_ip_address, len + 1);

           if (!hypervisor_ip_address) {
              fprintf(stderr, "Unable to set hypervisor IP address!\n");
              exit(EXIT_FAILURE);
           }
           memcpy(hypervisor_ip_address, optarg, len);
           hypervisor_ip_address[len] = '\0';
           hypervisor_tcp_port = atoi(index + 1);
        }
        break;
      case 'U':
        hypervisor_mode = 1;
        hypervisor_socket_path = optarg;
        break;
	  case 'v':
	    printf("%s version %s\n", NAME, VERSION);
	    exit(EXIT_SUCCESS);
	  case 'h':
	    print_usage(argv[0]);
	    exit(EXIT_SUCCESS);
	  case 'e':
	    display_network_devices();
	    exit(EXIT_SUCCESS);
	  case 'd':
        debug_level = atoi(optarg);
        break;
	  case 'f':
        config_file = optarg;
        break;
      default:
        exit(EXIT_FAILURE);
	}
  }
  printf("uBridge version %s running with %s\n", VERSION, pcap_lib_version());
  ubridge(hypervisor_ip_address, hypervisor_tcp_port, hypervisor_socket_path);
  return (EXIT_SUCCESS);
}
