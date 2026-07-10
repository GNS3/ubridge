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
 *
 * marker engine + `marker` hypervisor module.
 *
 * marker_emit() is called by the `mark` packet filter on a match. It sends one
 * UDP datagram per match to a configured sink (gns3server), fire-and-forget.
 * No listener thread, no accept loop, no per-node server — ubridge is purely a
 * UDP client here. The sink/node are configured via `marker sink`/`marker node`
 * commands or the UBRIDGE_MARKER_SINK / UBRIDGE_MARKER_NODE env vars at start.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>

#include "hypervisor.h"
#include "marker.h"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int             g_fd = -1;                 /* cached UDP socket, -1 if none */
static struct sockaddr_storage g_sink;            /* resolved sink address */
static socklen_t       g_sink_len = 0;
static int             g_enabled = 0;             /* sink configured? */
static char            g_sink_display[72] = "";   /* "host:port" for status */
static char            g_node[64] = "";           /* node id echoed in signals */
static unsigned long   g_emitted = 0;

/* --------------------------------------------------------------------------
 * Engine
 * -------------------------------------------------------------------------- */

/* Configure the UDP sink. Resolves <host>:<port>, (re)opens the socket. 0 or -errno. */
int marker_set_sink(const char *host, int port)
{
    struct addrinfo hints, *res = NULL;
    char port_str[16];
    int fd, err;

    if (!host || port <= 0 || port > 65535)
        return -EINVAL;

    snprintf(port_str, sizeof(port_str), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0)
        return -ENOENT;   /* unresolvable / unreachable */

    fd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        err = errno;
        freeaddrinfo(res);
        return -err;
    }

    pthread_mutex_lock(&g_lock);
    if (g_fd >= 0)
        close(g_fd);
    g_fd = fd;
    memset(&g_sink, 0, sizeof(g_sink));
    memcpy(&g_sink, res->ai_addr, res->ai_addrlen);
    g_sink_len = res->ai_addrlen;
    g_enabled = 1;
    snprintf(g_sink_display, sizeof(g_sink_display), "%s:%d", host, port);
    pthread_mutex_unlock(&g_lock);

    freeaddrinfo(res);
    return 0;
}

int marker_clear_sink(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_fd >= 0)
        close(g_fd);
    g_fd = -1;
    g_enabled = 0;
    g_sink_len = 0;
    g_sink_display[0] = '\0';
    pthread_mutex_unlock(&g_lock);
    return 0;
}

void marker_set_node(const char *node_id)
{
    pthread_mutex_lock(&g_lock);
    if (node_id) {
        strncpy(g_node, node_id, sizeof(g_node) - 1);
        g_node[sizeof(g_node) - 1] = '\0';
    } else {
        g_node[0] = '\0';
    }
    pthread_mutex_unlock(&g_lock);
}

/* Emit one marker signal (UDP, fire-and-forget). No-op if no sink. */
void marker_emit(const char *filter_name, const char *tag, size_t len)
{
    char line[256];
    struct timeval tv;
    const char *node;
    int n;

    pthread_mutex_lock(&g_lock);
    if (!g_enabled || g_fd < 0) {
        pthread_mutex_unlock(&g_lock);
        return;
    }

    node = g_node[0] ? g_node : "-";
    gettimeofday(&tv, NULL);
    n = snprintf(line, sizeof(line),
                 "MARK %lu.%06lu node=%s filter=%s tag=%s len=%zu\n",
                 (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec,
                 node,
                 filter_name ? filter_name : "-",
                 tag ? tag : "-",
                 len);
    if (n > 0)
        sendto(g_fd, line, strlen(line), 0, (struct sockaddr *)&g_sink, g_sink_len);
    g_emitted++;
    pthread_mutex_unlock(&g_lock);
}

int marker_status(marker_status_t *out)
{
    if (!out)
        return -EINVAL;
    pthread_mutex_lock(&g_lock);
    out->enabled = g_enabled;
    snprintf(out->sink, sizeof(out->sink), "%s", g_sink_display);
    snprintf(out->node, sizeof(out->node), "%s", g_node);
    out->emitted = g_emitted;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

/* --------------------------------------------------------------------------
 * `marker` module commands
 * -------------------------------------------------------------------------- */

/* marker sink <host> <port> */
static int cmd_sink(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *host = argv[0];
    char *end;
    long port = strtol(argv[1], &end, 10);
    int err;

    if (end == argv[1] || *end != '\0' || port <= 0 || port > 65535) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "invalid port '%s' (1-65535)", argv[1]);
        return -1;
    }
    err = marker_set_sink(host, (int)port);
    if (err < 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not set marker sink %s:%ld: %s", host, port, strerror(-err));
        return -1;
    }
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "marker sink set to %s:%ld", host, port);
    return 0;
}

/* marker node <id> */
static int cmd_node(hypervisor_conn_t *conn, int argc, char *argv[])
{
    marker_set_node(argv[0]);
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "marker node set to %s", argv[0]);
    return 0;
}

/* marker off — clear the sink */
static int cmd_off(hypervisor_conn_t *conn, int argc, char *argv[])
{
    marker_clear_sink();
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "marker sink cleared");
    return 0;
}

/* marker status */
static int cmd_status(hypervisor_conn_t *conn, int argc, char *argv[])
{
    marker_status_t s;
    marker_status(&s);
    hypervisor_send_reply(conn, HSC_INFO_MSG, 0, "enabled=%d sink=%s node=%s emitted=%lu",
                          s.enabled, s.enabled ? s.sink : "(none)", s.node[0] ? s.node : "(none)", s.emitted);
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "OK");
    return 0;
}

static hypervisor_cmd_t marker_cmd_array[] = {
   { "sink",   2, 2, cmd_sink,   NULL },   /* <host> <port> */
   { "node",   1, 1, cmd_node,   NULL },
   { "off",    0, 0, cmd_off,    NULL },
   { "status", 0, 0, cmd_status, NULL },
   { NULL, -1, -1, NULL, NULL },
};

/* Parse "host:port" (last colon) → set sink. */
static void marker_env_sink(const char *s)
{
    const char *colon = strrchr(s, ':');
    char host[64];
    int port;
    if (!colon)
        return;
    if ((size_t)(colon - s) >= sizeof(host))
        return;
    memcpy(host, s, colon - s);
    host[colon - s] = '\0';
    port = atoi(colon + 1);
    if (port > 0)
        marker_set_sink(host, port);
}

/* Hypervisor marker initialization */
int hypervisor_marker_init(void)
{
   hypervisor_module_t *module;

   module = hypervisor_register_module("marker", NULL);
   assert(module != NULL);
   hypervisor_register_cmd_array(module, marker_cmd_array);

   /* Env defaults: controller may inject at launch instead of via commands. */
   {
      const char *sink = getenv("UBRIDGE_MARKER_SINK");
      const char *node = getenv("UBRIDGE_MARKER_NODE");
      if (sink && *sink)
          marker_env_sink(sink);
      if (node && *node)
          marker_set_node(node);
   }
   return(0);
}
