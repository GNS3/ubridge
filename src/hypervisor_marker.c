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
 *
 * Kernel-dataplane markers (`marker add_kernel`) are the "hooked on an
 * interface" variant of the mark filter: docker nodes bridge veth → kernel
 * bridge → veth in the kernel, so the ubridge relay no longer sees that
 * traffic. Each kernel marker sniffs its interface with a dedicated
 * AF_PACKET socket + reader thread and emits the same signals. See the
 * kernel-marker section below.
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
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <pcap.h>   /* must precede pcap_capture.h: pcap_capture_t uses libpcap types */
#include "ubridge.h"   /* defines pcap_capture_t itself */
#include "pcap_capture.h"

#include "hypervisor.h"
#include "marker.h"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int             g_fd = -1;                 /* cached UDP socket, -1 if none */
static struct sockaddr_storage g_sink;            /* resolved sink address */
static socklen_t       g_sink_len = 0;
static int             g_enabled = 0;             /* sink configured? */
static int             g_paused = 0;              /* emission paused (`marker pause`)? */
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
void marker_emit(const char *filter_name, const char *tag, const char *link, size_t len, const char *dir)
{
    char line[256];
    struct timeval tv;
    const char *node;
    int n;

    pthread_mutex_lock(&g_lock);
    if (!g_enabled || g_fd < 0 || g_paused) {
        pthread_mutex_unlock(&g_lock);
        return;
    }

    node = g_node[0] ? g_node : "-";
    gettimeofday(&tv, NULL);
    n = snprintf(line, sizeof(line),
                 "MARK %lu.%06lu node=%s filter=%s link=%s tag=%s len=%zu dir=%s\n",
                 (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec,
                 node,
                 filter_name ? filter_name : "-",
                 link ? link : "-",
                 tag ? tag : "-",
                 len,
                 dir ? dir : "-");
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
    out->paused = g_paused;
    snprintf(out->sink, sizeof(out->sink), "%s", g_sink_display);
    snprintf(out->node, sizeof(out->node), "%s", g_node);
    out->emitted = g_emitted;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

/* --------------------------------------------------------------------------
 * Kernel-dataplane markers (`marker add_kernel`)
 *
 * GNS3 docker nodes have a kernel data plane (veth → kernel bridge → veth);
 * frames never reach ubridge's relay, so a `mark` filter hooked on a bridge
 * NIO cannot see them. A kernel marker is the interface-hooked variant of the
 * mark filter: one AF_PACKET/SOCK_RAW socket bound to the interface's ifindex
 * (ETH_P_ALL, non-promiscuous) and one reader thread applying the same
 * libpcap cBPF per packet via pcap_offline_filter — deliberately NOT
 * SO_ATTACH_FILTER, to keep the linktype offset semantics (C_HDLC, PPP, ...).
 * On match it emits the same marker signal and optionally appends the packet
 * to a pcap. Purely observational: it never drops or alters frames.
 *
 * Uniqueness key is (ifname, name): the same marker name may live on several
 * interfaces. Lifecycle is the ubridge process — no shutdown command.
 * -------------------------------------------------------------------------- */

/* Which directions a kernel marker fires on. 0 must mean "both" (the struct
 * is calloc'd); see the MARK_DIR_* comment in packet_filter.c for why this is
 * a separate enum from the marker dir strings. */
enum {
    KMARK_DIR_BOTH = 0,
    KMARK_DIR_TX   = 1,   /* only frames arriving from the node (node sending)   */
    KMARK_DIR_RX   = 2,   /* only frames forwarded to the node (node receiving)  */
};

typedef struct kernel_marker {
    char *name;
    char *ifname;
    char *tag;              /* optional, echoed in the signal */
    char *link;             /* optional, echoed in the signal */
    pcap_capture_t *cap;    /* optional: append matched packets to this pcap */
    struct bpf_program fp;  /* compiled cBPF, applied in user space per packet */
    int dir_match;          /* KMARK_DIR_* */
    volatile int enabled;   /* 0 = installed but silent (enable off) */
    volatile int stop;      /* cooperative stop flag for the reader thread */
    int sock;               /* AF_PACKET socket */
    pthread_t tid;
    struct kernel_marker *next;
} kernel_marker_t;

static kernel_marker_t *g_kmarkers = NULL;
/* Guards the g_kmarkers list. Command handlers already serialize under the
 * dispatcher's global_lock; the reader threads take no list lock and only
 * touch their own marker, so this only protects the list itself. */
static pthread_mutex_t g_km_lock = PTHREAD_MUTEX_INITIALIZER;

/* Reader thread: sniff frames, apply the cBPF, emit signal + pcap on match.
 * Cooperative stop: the socket carries a 1s SO_RCVTIMEO so the loop wakes at
 * least once per second to re-check km->stop. Deliberately NOT pthread_cancel
 * — this path holds mutexes while writing files (pcap dump, marker sink). */
static void *kernel_marker_thread(void *arg)
{
    kernel_marker_t *km = (kernel_marker_t *)arg;
    unsigned char buf[65535];

    while (!km->stop) {
        struct sockaddr_ll from;
        socklen_t fromlen = sizeof(from);
        struct pcap_pkthdr pkthdr;
        const char *dir;
        ssize_t n;

        n = recvfrom(km->sock, buf, sizeof(buf), 0,
                     (struct sockaddr *)&from, &fromlen);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                continue;   /* recv timeout (stop tick) or signal: loop re-checks km->stop */
            break;          /* real error (interface gone): the marker goes quiet */
        }

        /* dir is relative to the capture node: a frame leaving the host-side
         * end (PACKET_OUTGOING) is being delivered to the node, i.e. the node
         * receives ("rx"); anything else arrived from the node, i.e. the node
         * sent ("tx"). The dir parameter filters post-recv by pkttype;
         * omitted = both directions. */
        dir = (from.sll_pkttype == PACKET_OUTGOING) ? "rx" : "tx";
        if ((km->dir_match == KMARK_DIR_TX && from.sll_pkttype == PACKET_OUTGOING) ||
            (km->dir_match == KMARK_DIR_RX && from.sll_pkttype != PACKET_OUTGOING))
            continue;

        memset(&pkthdr, 0, sizeof(pkthdr));
        pkthdr.caplen = (u_int)n;
        pkthdr.len = (u_int)n;
        if (pcap_offline_filter(&km->fp, &pkthdr, buf)) {
            if (km->enabled) {   /* enable off: keep reading, no emit / no pcap */
                marker_emit(km->name, km->tag, km->link, (size_t)n, dir);
                if (km->cap)
                    pcap_capture_packet(km->cap, buf, (size_t)n);
            }
        }
    }
    return NULL;
}

/* Find a kernel marker by (ifname, name). Caller holds g_km_lock. */
static kernel_marker_t *km_find(const char *ifname, const char *name)
{
    kernel_marker_t *km;

    for (km = g_kmarkers; km != NULL; km = km->next)
        if (!strcmp(km->ifname, ifname) && !strcmp(km->name, name))
            return km;
    return NULL;
}

/* Stop the reader thread and release every resource of an already-unlinked
 * marker. The join returns within ~1s (SO_RCVTIMEO stop tick). */
static void km_free(kernel_marker_t *km)
{
    km->stop = 1;
    pthread_join(km->tid, NULL);
    close(km->sock);
    pcap_freecode(&km->fp);
    if (km->cap)
        free_pcap_capture(km->cap);
    free(km->tag);
    free(km->link);
    free(km->name);
    free(km->ifname);
    free(km);
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
    int nkm = 0;
    kernel_marker_t *km;

    marker_status(&s);
    pthread_mutex_lock(&g_km_lock);
    for (km = g_kmarkers; km != NULL; km = km->next)
        nkm++;
    pthread_mutex_unlock(&g_km_lock);

    hypervisor_send_reply(conn, HSC_INFO_MSG, 0, "enabled=%d paused=%d sink=%s node=%s emitted=%lu kernel=%d",
                          s.enabled, s.paused, s.enabled ? s.sink : "(none)", s.node[0] ? s.node : "(none)", s.emitted, nkm);
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "OK");
    return 0;
}

/* marker pause — suppress signal emission without clearing the sink (the UDP
 * socket stays open, so resume is instant). Per-filter `enabled` is unaffected;
 * this is a global gate checked in marker_emit(). */
static int cmd_pause(hypervisor_conn_t *conn, int argc, char *argv[])
{
    pthread_mutex_lock(&g_lock);
    g_paused = 1;
    pthread_mutex_unlock(&g_lock);
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "marker paused (sink retained)");
    return 0;
}

/* marker resume — re-enable signal emission after `marker pause`. */
static int cmd_resume(hypervisor_conn_t *conn, int argc, char *argv[])
{
    pthread_mutex_lock(&g_lock);
    g_paused = 0;
    pthread_mutex_unlock(&g_lock);
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "marker resumed");
    return 0;
}

/* marker add_kernel <name> <ifname> "<bpf>" [tag <id>] [link <id>]
 *                     [dir <tx|rx>] [linktype <name>] [pcap "<path>"]
 *
 * Keyword syntax mirrors the relay `mark` filter exactly: pairs in any order,
 * each keyword at most once, no dangling value. */
static int cmd_add_kernel(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *name = argv[0];
    char *ifname = argv[1];
    char *filter = argv[2];
    const char *linktype_str = "EN10MB";   /* link layer for BPF offsets + pcap header */
    kernel_marker_t *km;
    pcap_t *pd;
    struct sockaddr_ll sll;
    struct timeval tv;
    int link_type, ifindex, err, i, started = 0;
    int have_linktype = 0, have_tag = 0, have_link = 0, have_dir = 0, have_pcap = 0;

    /* an odd trailing token is a value without a keyword (same rule as mark_setup) */
    if ((argc - 3) & 1) {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "dangling value without keyword");
        return -1;
    }

    pthread_mutex_lock(&g_km_lock);
    err = (km_find(ifname, name) != NULL);
    pthread_mutex_unlock(&g_km_lock);
    if (err) {   /* EALREADY semantics: same name may exist on another interface */
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "kernel marker '%s' already exists on %s", name, ifname);
        return -1;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        hypervisor_send_reply(conn, HSC_ERR_UNK_OBJ, 1,
                              "Could not add kernel marker on %s: %s", ifname, strerror(ENODEV));
        return -1;
    }

    if (!(km = calloc(1, sizeof(*km)))) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Could not add kernel marker: %s", strerror(ENOMEM));
        return -1;
    }
    km->sock = -1;
    km->enabled = 1;

    /* First pass: pick up an optional "linktype <name>" pair before compiling,
     * since the DLT fixes the BPF field offsets (14-byte Ethernet header vs
     * 4-byte HDLC/PPP etc.). The pair may sit anywhere among the keywords. */
    for (i = 3; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "linktype")) {
            if (have_linktype)
                goto dup_keyword;
            have_linktype = 1;
            linktype_str = argv[i + 1];
        }
    }
    if ((link_type = pcap_datalink_name_to_val(linktype_str)) == -1) {
        fprintf(stderr, "mark: unknown linktype '%s', assuming Ethernet.\n", linktype_str);
        link_type = DLT_EN10MB;
        linktype_str = "EN10MB";
    }

    /* Compile with the same source and error wording as the mark filter — the
     * controller greps the reply text ("compile filter" / libpcap's "syntax
     * error") to degrade a bad expression to a warning instead of failing. */
    pd = pcap_open_dead(link_type, 65535);
    if (pcap_compile(pd, &km->fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "Cannot compile mark filter '%s': %s\n", filter, pcap_geterr(pd));
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1,
                              "Failed to add kernel marker '%s': cannot compile filter '%s': %s",
                              name, filter, pcap_geterr(pd));
        pcap_close(pd);
        goto fail;
    }
    pcap_close(pd);

    /* Second pass: the remaining keyword/value pairs ("linktype" consumed). */
    for (i = 3; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "linktype")) {
            continue;
        } else if (!strcmp(argv[i], "tag")) {
            if (have_tag)
                goto dup_keyword;
            have_tag = 1;
            free(km->tag);
            km->tag = strdup(argv[i + 1]);
        } else if (!strcmp(argv[i], "link")) {
            if (have_link)
                goto dup_keyword;
            have_link = 1;
            free(km->link);
            km->link = strdup(argv[i + 1]);
        } else if (!strcmp(argv[i], "pcap")) {
            if (have_pcap)
                goto dup_keyword;
            have_pcap = 1;
            if (!(km->cap = create_pcap_capture(argv[i + 1], linktype_str))) {
                hypervisor_send_reply(conn, HSC_ERR_FILE, 1,
                                      "Could not add kernel marker: cannot open pcap '%s'", argv[i + 1]);
                goto fail;
            }
        } else if (!strcmp(argv[i], "dir")) {
            if (have_dir)
                goto dup_keyword;
            have_dir = 1;
            if (!strcmp(argv[i + 1], "tx"))
                km->dir_match = KMARK_DIR_TX;
            else if (!strcmp(argv[i + 1], "rx"))
                km->dir_match = KMARK_DIR_RX;
            else {
                fprintf(stderr, "mark: invalid dir '%s' (expected tx or rx)\n", argv[i + 1]);
                hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                                      "invalid dir '%s' (expected tx or rx)", argv[i + 1]);
                goto fail;
            }
        } else {
            hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "unknown keyword '%s'", argv[i]);
            goto fail;
        }
    }

    km->name = strdup(name);
    km->ifname = strdup(ifname);

    if ((km->sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        err = errno;
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not add kernel marker: %s", strerror(err));
        goto fail;
    }

    /* 1s receive timeout: the reader loop's cooperative-stop tick. */
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(km->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(km->sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        err = errno;
        hypervisor_send_reply(conn, HSC_ERR_BINDING, 1,
                              "Could not add kernel marker: cannot bind to %s: %s", ifname, strerror(err));
        goto fail;
    }
    /* Non-promiscuous by design: only frames the host already sends/receives
     * on this end (the data-plane traffic itself) — unlike
     * `capture start_kernel`, which opts into PACKET_MR_PROMISC. */

    err = pthread_create(&km->tid, NULL, kernel_marker_thread, km);
    if (err != 0) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Could not add kernel marker: %s", strerror(err));
        goto fail;   /* thread never started: plain cleanup, no join below */
    }
    started = 1;

    pthread_mutex_lock(&g_km_lock);
    km->next = g_kmarkers;
    g_kmarkers = km;
    pthread_mutex_unlock(&g_km_lock);

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "kernel marker '%s' added on %s", name, ifname);
    return 0;

dup_keyword:
    hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "duplicate keyword '%s'", argv[i]);
fail:
    if (started) {
        km->stop = 1;
        pthread_join(km->tid, NULL);
    }
    if (km->sock >= 0)
        close(km->sock);
    pcap_freecode(&km->fp);
    if (km->cap)
        free_pcap_capture(km->cap);
    free(km->tag);
    free(km->link);
    free(km->name);
    free(km->ifname);
    free(km);
    return -1;
}

/* marker delete_kernel <ifname> <name> — idempotent (unknown → OK). */
static int cmd_delete_kernel(hypervisor_conn_t *conn, int argc, char *argv[])
{
    kernel_marker_t *km, *prev;

    pthread_mutex_lock(&g_km_lock);
    for (km = g_kmarkers, prev = NULL; km != NULL; prev = km, km = km->next)
        if (!strcmp(km->ifname, argv[0]) && !strcmp(km->name, argv[1]))
            break;
    if (km != NULL) {
        if (prev == NULL)
            g_kmarkers = km->next;
        else
            prev->next = km->next;
    }
    pthread_mutex_unlock(&g_km_lock);

    if (km == NULL) {
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "no kernel marker '%s' on %s", argv[1], argv[0]);
        return 0;
    }
    km_free(km);   /* stops the reader thread, closes the socket, frees all resources */
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "kernel marker '%s' deleted on %s", argv[1], argv[0]);
    return 0;
}

/* marker enable_kernel <ifname> <name> <on|off> */
static int cmd_enable_kernel(hypervisor_conn_t *conn, int argc, char *argv[])
{
    kernel_marker_t *km;
    int on;

    if (!strcmp(argv[2], "on"))
        on = 1;
    else if (!strcmp(argv[2], "off"))
        on = 0;
    else {
        hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1,
                              "invalid state '%s' (expected on or off)", argv[2]);
        return -1;
    }

    pthread_mutex_lock(&g_km_lock);
    km = km_find(argv[0], argv[1]);
    pthread_mutex_unlock(&g_km_lock);

    if (km == NULL) {
        hypervisor_send_reply(conn, HSC_ERR_UNK_OBJ, 1, "no kernel marker '%s' on %s", argv[1], argv[0]);
        return -1;
    }
    /* off = installed but silent (paused tap): the thread keeps reading but
     * emits no signal and writes no pcap; on resumes instantly. */
    km->enabled = on;
    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "kernel marker '%s' %s on %s",
                          argv[1], on ? "enabled" : "paused", argv[0]);
    return 0;
}

static hypervisor_cmd_t marker_cmd_array[] = {
   { "sink",   2, 2, cmd_sink,   NULL },   /* <host> <port> */
   { "node",   1, 1, cmd_node,   NULL },
   { "off",    0, 0, cmd_off,    NULL },
   { "pause",  0, 0, cmd_pause,  NULL },
   { "resume", 0, 0, cmd_resume, NULL },
   { "status", 0, 0, cmd_status, NULL },
   /* add_kernel <name> <if> "<bpf>" [tag <id>] [link <id>] [dir <tx|rx>]
    *            [linktype <name>] [pcap "<path>"]  (3 + up to 5 pairs) */
   { "add_kernel",    3, 13, cmd_add_kernel,    NULL },
   { "delete_kernel", 2, 2,  cmd_delete_kernel, NULL },   /* <if> <name> */
   { "enable_kernel", 3, 3,  cmd_enable_kernel, NULL },   /* <if> <name> <on|off> */
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
