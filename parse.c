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

#include "parse.h"
#include "nio_udp.h"
#include "nio_ethernet.h"
#include "nio_tap.h"
#include "pcap_capture.h"

#ifdef LINUX_RAW
#include "nio_linux_raw.h"
#endif

static nio_t *create_udp_tunnel(const char *params)
{
  nio_t *nio;
  char *local_port;
  char *remote_host;
  char *remote_port;

  printf("Creating UDP tunnel %s\n", params);
  local_port = strtok((char *)params, ":");
  remote_host = strtok(NULL, ":");
  remote_port = strtok(NULL, ":");
  if (local_port == NULL || remote_host == NULL || remote_port == NULL) {
     fprintf(stderr, "invalid UDP tunnel syntax\n");
     return NULL;
  }

  nio = create_nio_udp(atoi(local_port), remote_host, atoi(remote_port));
  if (!nio)
    fprintf(stderr, "unable to create UDP NIO\n");
  return nio;
}

static nio_t *open_ethernet_device(const char *dev_name)
{
  nio_t *nio;

  printf("Opening Ethernet device %s\n", dev_name);
  nio = create_nio_ethernet((char *)dev_name);
  if (!nio)
    fprintf(stderr, "unable to open Ethernet device\n");
  return nio;
}

static nio_t *open_tap_device(const char *dev_name)
{
  nio_t *nio;

  printf("Opening TAP device %s\n", dev_name);
  nio = create_nio_tap((char *)dev_name);
  if (!nio)
    fprintf(stderr, "unable to open TAP device\n");
  return nio;
}

#ifdef LINUX_RAW
static nio_t *open_linux_raw(const char *dev_name)
{
  nio_t *nio;

  printf("Opening Linux RAW device %s\n", dev_name);
  nio = create_nio_linux_raw((char *)dev_name);
  if (!nio)
    fprintf(stderr, "unable to open RAW device\n");
  return nio;
}
#endif

static int getstr(dictionary *ubridge_config, const char *section, const char *entry, const char **value)
{
    char key[MAX_KEY_SIZE];

    snprintf(key, MAX_KEY_SIZE, "%s:%s", section, entry);
    *value = iniparser_getstring(ubridge_config, key, NULL);
    if (*value)
      return TRUE;
    return FALSE;
}

static bridge_t *add_bridge(bridge_t **head)
{
   bridge_t *bridge;

   if ((bridge = malloc(sizeof(*bridge))) != NULL) {
      bridge->next = *head;
      *head = bridge;
   }
   return bridge;
}

static void parse_capture(dictionary *ubridge_config, const char *bridge_name, bridge_t *bridge)
{
    const char *pcap_file = NULL;
    const char *pcap_linktype = "EN10MB";

    getstr(ubridge_config, bridge_name, "pcap_protocol", &pcap_linktype);
    if (getstr(ubridge_config, bridge_name, "pcap_file", &pcap_file)) {
        printf("Starting packet capture to %s with protocol %s\n", pcap_file, pcap_linktype);
        bridge->capture = create_pcap_capture(pcap_file, pcap_linktype);
    }
}

int parse_config(char *filename, bridge_t **bridges)
{
    dictionary *ubridge_config = NULL;
    const char *value;
    const char *bridge_name;
    int i, nsec;

    if ((ubridge_config = iniparser_load(filename)) == NULL) {
       return FALSE;
    }

    nsec = iniparser_getnsec(ubridge_config);
    for (i = 0; i < nsec; i++) {
        bridge_t *bridge;
        nio_t *source_nio = NULL;
        nio_t *destination_nio = NULL;

        bridge_name = iniparser_getsecname(ubridge_config, i);
        printf("Parsing %s\n", bridge_name);

        if (getstr(ubridge_config, bridge_name, "source_udp", &value))
           source_nio = create_udp_tunnel(value);
        else if (getstr(ubridge_config, bridge_name, "source_ethernet", &value))
           source_nio = open_ethernet_device(value);
        else if (getstr(ubridge_config, bridge_name, "source_tap", &value))
           source_nio = open_tap_device(value);
#ifdef LINUX_RAW
        else if (getstr(ubridge_config, bridge_name, "source_linux_raw", &value))
           source_nio = open_linux_raw(value);
#endif
        else
           fprintf(stderr, "source NIO not found\n");

        if (getstr(ubridge_config, bridge_name, "destination_udp", &value))
           destination_nio = create_udp_tunnel(value);
        else if (getstr(ubridge_config, bridge_name, "destination_ethernet", &value))
           destination_nio = open_ethernet_device(value);
        else if (getstr(ubridge_config, bridge_name, "destination_tap", &value))
           destination_nio = open_tap_device(value);
#ifdef LINUX_RAW
        else if (getstr(ubridge_config, bridge_name, "destination_linux_raw", &value))
           source_nio = open_linux_raw(value);
#endif
        else
           fprintf(stderr, "destination NIO not found\n");

        if (source_nio && destination_nio) {
           bridge = add_bridge(bridges);
           bridge->name = strdup(bridge_name);
           bridge->source_nio = source_nio;
           bridge->destination_nio = destination_nio;
           parse_capture(ubridge_config, bridge_name, bridge);
        }
        else if (source_nio != NULL)
           free_nio(source_nio);
        else if (destination_nio != NULL)
           free_nio(destination_nio);
    }
    iniparser_freedict(ubridge_config);
    return TRUE;
}
