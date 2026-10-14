/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2015 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   Free Software Foundation, either version 3 of the License, or
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
 * capture — kernel-side packet capture via AF_PACKET.
 *
 * Captures frames on a kernel interface (typically a persistent TAP created by
 * the tap module, or a bridge managed by brctl) into a pcap file. Needed for
 * the kernel data plane: once frames flow TAP -> kernel bridge -> TAP they
 * never reach ubridge's user-space NIO relay, so the bridge module's NIO-level
 * capture can't see them. This opens an AF_PACKET raw socket bound to the
 * interface and writes frames to pcap, reusing the existing pcap writer
 * (create_pcap_capture / pcap_capture_packet / free_pcap_capture).
 *
 * Model: one capture per interface, any number of interfaces — each driven by
 * a dedicated thread looping on recvfrom(). Stop is cooperative: the socket
 * carries a 1s SO_RCVTIMEO tick so the loop re-checks a stop flag at least
 * once per second. Deliberately NOT pthread_cancel — this path holds a mutex
 * while writing files (pcap_capture_packet), same reasoning as the kernel
 * markers. Mirrors the marker module's kernel-marker list (g_kmarkers):
 * a singly linked list guarded by a mutex; reader threads never touch the
 * list and only reach their own entry.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "ubridge.h"
#include "pcap_capture.h"
#include "hypervisor.h"
#include "hypervisor_capture.h"

typedef struct kernel_capture {
    pcap_capture_t *cap;        /* pcap writer (owned by this entry) */
    int sock;                   /* AF_PACKET raw socket */
    pthread_t tid;              /* reader thread */
    volatile int stop;          /* cooperative stop flag for the reader thread */
    char ifname[IFNAMSIZ];      /* captured interface (list key) */
    struct kernel_capture *next;
} kernel_capture_t;

static kernel_capture_t *g_captures = NULL;
/* Guards the g_captures list. Command handlers already serialize under the
 * dispatcher's global_lock; the reader threads take no list lock and only
 * touch their own entry, so this only protects the list itself. */
static pthread_mutex_t g_captures_lock = PTHREAD_MUTEX_INITIALIZER;

/* Reader thread: read frames from the AF_PACKET socket, write to pcap.
 * Cooperative stop: the socket carries a 1s SO_RCVTIMEO so the loop wakes at
 * least once per second to re-check kc->stop. */
static void *capture_thread(void *arg)
{
    kernel_capture_t *kc = (kernel_capture_t *)arg;
    unsigned char buf[65535];

    while (!kc->stop) {
        ssize_t n = recvfrom(kc->sock, buf, sizeof(buf), 0, NULL, NULL);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                continue;   /* recv timeout (stop tick) or signal: loop re-checks kc->stop */
            break;          /* real error (interface gone): the reader stops */
        }
        pcap_capture_packet(kc->cap, buf, (size_t)n);
    }

    return NULL;
}

/* Start capturing <ifname> into <pcap_file> (link type <dlt>, default EN10MB).
 * One capture per interface: -EALREADY only when <ifname> is already captured,
 * a different interface may always be captured too. */
static int capture_start(const char *ifname, const char *pcap_file, const char *dlt)
{
    struct sockaddr_ll sll;
    struct packet_mreq mreq;
    struct timeval tv;
    kernel_capture_t *kc;
    int ifindex, err;

    pthread_mutex_lock(&g_captures_lock);

    for (kc = g_captures; kc != NULL; kc = kc->next)
        if (!strcmp(kc->ifname, ifname)) {
            pthread_mutex_unlock(&g_captures_lock);
            return -EALREADY;
        }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        pthread_mutex_unlock(&g_captures_lock);
        return -ENODEV;
    }

    if (!(kc = calloc(1, sizeof(*kc)))) {
        err = ENOMEM;
        goto fail;
    }
    kc->sock = -1;

    if (!(kc->cap = create_pcap_capture(pcap_file, dlt ? dlt : "EN10MB"))) {
        err = (errno != 0) ? errno : EIO;
        goto fail;
    }

    if ((kc->sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        err = errno;
        goto fail;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(kc->sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        err = errno;
        goto fail;
    }

    /* Promiscuous mode (best-effort) to catch all frames on the interface. */
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    setsockopt(kc->sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    /* 1s receive timeout: the reader loop's cooperative-stop tick. */
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(kc->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    strncpy(kc->ifname, ifname, IFNAMSIZ - 1);
    kc->ifname[IFNAMSIZ - 1] = '\0';

    err = pthread_create(&kc->tid, NULL, capture_thread, kc);
    if (err != 0)
        goto fail;   /* thread never started: plain cleanup, no join below */

    kc->next = g_captures;
    g_captures = kc;
    pthread_mutex_unlock(&g_captures_lock);
    return 0;

fail:
    if (kc != NULL) {
        if (kc->sock >= 0)
            close(kc->sock);
        if (kc->cap != NULL)
            free_pcap_capture(kc->cap);
        free(kc);
    }
    pthread_mutex_unlock(&g_captures_lock);
    return -err;
}

/* Stop the reader thread and release every resource of an already-unlinked
 * entry. The join returns within ~1s (SO_RCVTIMEO stop tick). */
static void kc_free(kernel_capture_t *kc)
{
    kc->stop = 1;
    pthread_join(kc->tid, NULL);
    close(kc->sock);
    free_pcap_capture(kc->cap);
    free(kc);
}

/* Stop the capture on <ifname>, or every capture when <ifname> is NULL.
 * Unlinking happens under g_captures_lock, joining outside it — a ~1s join
 * must not hold up other interfaces' start/stop. Returns the number of
 * captures stopped, or -ENODEV when a specific interface has no capture. */
static int capture_stop(const char *ifname)
{
    kernel_capture_t *kc, *prev;
    int stopped = 0;

    pthread_mutex_lock(&g_captures_lock);
    for (;;) {
        for (kc = g_captures, prev = NULL; kc != NULL; prev = kc, kc = kc->next)
            if (ifname == NULL || !strcmp(kc->ifname, ifname))
                break;
        if (kc == NULL)
            break;
        if (prev == NULL)
            g_captures = kc->next;
        else
            prev->next = kc->next;
        pthread_mutex_unlock(&g_captures_lock);
        kc_free(kc);
        stopped++;
        pthread_mutex_lock(&g_captures_lock);
    }
    pthread_mutex_unlock(&g_captures_lock);

    if (stopped == 0 && ifname != NULL)
        return -ENODEV;
    return stopped;
}

/* --------------------------------------------------------------------------
 * Command handlers
 * -------------------------------------------------------------------------- */

/* capture start_kernel <if> <pcap> [dlt] */
static int cmd_start_kernel(hypervisor_conn_t *conn, int argc, char *argv[])
{
    char *ifname = argv[0];
    char *pcap_file = argv[1];
    char *dlt = (argc >= 3) ? argv[2] : NULL;
    int err = capture_start(ifname, pcap_file, dlt);

    if (err < 0) {
        int code = (-err == EALREADY) ? HSC_ERR_START :
                   (-err == ENODEV) ? HSC_ERR_UNK_OBJ : HSC_ERR_FILE;
        if (-err == EALREADY)
            hypervisor_send_reply(conn, code, 1, "already capturing on %s", ifname);
        else
            hypervisor_send_reply(conn, code, 1, "Could not start kernel capture: %s", strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "kernel capture started on %s -> %s", ifname, pcap_file);
    return 0;
}

/* capture stop_kernel [if] — with an interface, stop that capture only;
 * without one, stop every capture. */
static int cmd_stop_kernel(hypervisor_conn_t *conn, int argc, char *argv[])
{
    int err = capture_stop((argc >= 1) ? argv[0] : NULL);

    if (err < 0) {
        /* -ENODEV, targeted stop only: no capture on that interface. */
        hypervisor_send_reply(conn, HSC_ERR_UNK_OBJ, 1, "no kernel capture on %s", argv[0]);
        return -1;
    }

    if (argc >= 1)
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "kernel capture stopped on %s", argv[0]);
    else if (err == 0)
        /* Idempotent: no active capture is not an error. */
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "no active kernel capture");
    else
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "stopped %d kernel capture%s", err, (err == 1) ? "" : "s");
    return 0;
}

/* capture status — one line per active capture, marker-style. */
static int cmd_status(hypervisor_conn_t *conn, int argc, char *argv[])
{
    kernel_capture_t *kc;

    /* Entries can only be unlinked by another command, and commands serialize
     * under the dispatcher's global_lock, so replying under the list lock is
     * safe (hypervisor_send_reply never takes it). */
    pthread_mutex_lock(&g_captures_lock);
    for (kc = g_captures; kc != NULL; kc = kc->next)
        hypervisor_send_reply(conn, HSC_INFO_MSG, 0, "kernel capture on %s", kc->ifname);
    pthread_mutex_unlock(&g_captures_lock);

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "OK");
    return 0;
}

/* --------------------------------------------------------------------------
 * Command table + module registration
 * -------------------------------------------------------------------------- */

static hypervisor_cmd_t capture_cmd_array[] = {
   /* start_kernel <if> <pcap> [dlt] */
   { "start_kernel", 2, 3, cmd_start_kernel, NULL },
   /* stop_kernel [if] — no argument stops every capture */
   { "stop_kernel",  0, 1, cmd_stop_kernel,  NULL },
   { "status",       0, 0, cmd_status,       NULL },
   { NULL, -1, -1, NULL, NULL },
};

/* Hypervisor capture initialization */
int hypervisor_capture_init(void)
{
   hypervisor_module_t *module;

   module = hypervisor_register_module("capture", NULL);
   assert(module != NULL);

   hypervisor_register_cmd_array(module, capture_cmd_array);
   return(0);
}
