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

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ubridge.h"

static void display_network_devices(void)
{
  char       pcap_errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *device_list, *device;
  int        res;

  printf("Network device list:\n\n");
  res = pcap_findalldevs(&device_list, pcap_errbuf);
  if (res < 0) {
    fprintf(stderr, "PCAP: unable to find device list (%s)\n", pcap_errbuf);
    return;
  }

  for (device = device_list; device; device = device->next)
    printf("  %s => %s\n", device->name,
           device->description ? device->description : "no description");
  printf("\n");

  pcap_freealldevs(device_list);
}

static void print_usage(const char *program_name)
{
  printf("Usage: %s [OPTION]\n"
         "\n"
         "Options:\n"
         "  -h                           : Print this message and exit\n"
         "  -f <file>                    : Specify a INI configuration file "
         "(default: %s)\n"
         "  -H [<ip_address>:]<tcp_port> : Hypervisor mode over TCP (default "
         "bind: 127.0.0.1)\n"
         "  -U <socket_path>             : Hypervisor mode over UNIX socket "
         "(recommended)\n"
         "  -e                           : Display all available network "
         "devices and exit\n"
         "  -d <level>                   : Debug level\n"
         "  -v                           : Print version and exit\n",
         program_name, CONFIG_FILE);
}

ubridge_options_t parse_cli_args(int argc, char **argv)
{
  int               opt;
  char             *index;
  bool              mode_selected = false;
  ubridge_options_t opts = {
    .debug_level = 0,
    .config.path = CONFIG_FILE,
    .mode = UBRIDGE_MODE_CONFIG_FILE
  };

  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);

  while ((opt = getopt(argc, argv, "hved:f:H:U:")) != -1) {
    switch (opt) {
    case 'H':
      if (mode_selected)
        goto err;
      mode_selected = true;
      opts.mode = UBRIDGE_MODE_HYPERVISOR_TCP;
      index = strrchr(optarg, ':');
      if (!index) {
        opts.tcp.port = atoi(optarg);
        opts.tcp.ip = NULL;
      } else {
        opts.tcp.ip = strndup(optarg, index - optarg);
        if (!opts.tcp.ip) {
          fprintf(stderr, "Unable to set hypervisor IP address!\n");
          exit(EXIT_FAILURE);
        }
        opts.tcp.port = atoi(index + 1);
      }
      break;
    case 'U':
      if (mode_selected)
        goto err;
      mode_selected = true;
      opts.mode = UBRIDGE_MODE_HYPERVISOR_UNIX;
      opts.unix_socket.path = optarg;
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
      opts.debug_level = atoi(optarg);
      break;
    case 'f':
      if (mode_selected)
        goto err;
      mode_selected = true;
      opts.mode = UBRIDGE_MODE_CONFIG_FILE;
      opts.config.path = optarg;
      break;
    default:
      exit(EXIT_FAILURE);
    }
  }
  return opts;

err:
  fprintf(stderr, "Only one of -f, -H, or -U may be specified\n");
  if (opts.mode == UBRIDGE_MODE_HYPERVISOR_TCP)
    free(opts.tcp.ip);
  exit(EXIT_FAILURE);
}
