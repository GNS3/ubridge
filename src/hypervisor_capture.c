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
 * Model: a single (singleton) capture at a time, driven by a dedicated thread
 * that loops on recvfrom(). Stop is via pthread_cancel + pthread_join (recvfrom
 * is a cancellation point), mirroring how free_bridges() stops the NIO listener
 * threads — no cooperative stop flag.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "ubridge.h"
#include "pcap_capture.h"
#include "hypervisor.h"
#include "hypervisor_capture.h"

typedef struct {
    pcap_capture_t *cap;        /* reused pcap writer (NULL when idle) */
    int sock;                   /* AF_PACKET raw socket (-1 when idle) */
    pthread_t tid;              /* capture thread */
    volatile int running;       /* 1 while the capture thread is alive */
    char ifname[IFNAMSIZ];      /* captured interface (informational) */
} kernel_capture_t;

static kernel_capture_t g_capture = { .cap = NULL, .sock = -1, .running = 0 };
static pthread_mutex_t g_capture_lock = PTHREAD_MUTEX_INITIALIZER;

/* Capture thread: read frames from the AF_PACKET socket, write to pcap. */
static void *capture_thread(void *arg)
{
    kernel_capture_t *kc = (kernel_capture_t *)arg;
    unsigned char buf[65535];

    for (;;) {
        ssize_t n = recvfrom(kc->sock, buf, sizeof(buf), 0, NULL, NULL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            break;
        }
        pcap_capture_packet(kc->cap, buf, (size_t)n);
    }

    return NULL;
}

/* Start capturing <ifname> into <pcap_file> (link type <dlt>, default EN10MB). */
static int capture_start(const char *ifname, const char *pcap_file, const char *dlt)
{
    struct sockaddr_ll sll;
    struct packet_mreq mreq;
    int ifindex, fd, err;

    pthread_mutex_lock(&g_capture_lock);

    if (g_capture.running) {
        pthread_mutex_unlock(&g_capture_lock);
        return -EALREADY;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        pthread_mutex_unlock(&g_capture_lock);
        return -ENODEV;
    }

    g_capture.cap = create_pcap_capture(pcap_file, dlt ? dlt : "EN10MB");
    if (!g_capture.cap) {
        err = (errno != 0) ? -errno : -EIO;
        pthread_mutex_unlock(&g_capture_lock);
        return err;
    }

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        err = -errno;
        free_pcap_capture(g_capture.cap);
        g_capture.cap = NULL;
        pthread_mutex_unlock(&g_capture_lock);
        return err;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        err = -errno;
        close(fd);
        free_pcap_capture(g_capture.cap);
        g_capture.cap = NULL;
        pthread_mutex_unlock(&g_capture_lock);
        return err;
    }

    /* Promiscuous mode (best-effort) to catch all frames on the interface. */
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    g_capture.sock = fd;
    strncpy(g_capture.ifname, ifname, IFNAMSIZ - 1);
    g_capture.ifname[IFNAMSIZ - 1] = '\0';

    err = pthread_create(&g_capture.tid, NULL, capture_thread, &g_capture);
    if (err != 0) {
        close(g_capture.sock);
        g_capture.sock = -1;
        g_capture.ifname[0] = '\0';
        free_pcap_capture(g_capture.cap);
        g_capture.cap = NULL;
        pthread_mutex_unlock(&g_capture_lock);
        return -err;   /* pthread_create returns an errno value */
    }

    g_capture.running = 1;
    pthread_mutex_unlock(&g_capture_lock);
    return 0;
}

/* Stop the active capture. Returns 0 or -ENODEV if none is active. */
static int capture_stop(void)
{
    pthread_mutex_lock(&g_capture_lock);

    if (!g_capture.running) {
        pthread_mutex_unlock(&g_capture_lock);
        return -ENODEV;
    }

    /* Cancel first, then join: the thread dies at recvfrom() (a cancellation
     * point) before we close its socket / free the pcap writer it references. */
    pthread_cancel(g_capture.tid);
    pthread_join(g_capture.tid, NULL);

    g_capture.running = 0;
    close(g_capture.sock);
    g_capture.sock = -1;
    free_pcap_capture(g_capture.cap);
    g_capture.cap = NULL;
    g_capture.ifname[0] = '\0';

    pthread_mutex_unlock(&g_capture_lock);
    return 0;
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
        hypervisor_send_reply(conn, code, 1, "Could not start kernel capture: %s", strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "kernel capture started on %s -> %s", ifname, pcap_file);
    return 0;
}

/* capture stop_kernel */
static int cmd_stop_kernel(hypervisor_conn_t *conn, int argc, char *argv[])
{
    int err = capture_stop();

    if (err < 0) {
        if (-err == ENODEV) {
            /* Idempotent: no active capture is not an error. */
            hypervisor_send_reply(conn, HSC_INFO_OK, 1, "no active kernel capture");
            return 0;
        }
        hypervisor_send_reply(conn, HSC_ERR_STOP, 1, "Could not stop kernel capture: %s", strerror(-err));
        return -1;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "kernel capture stopped");
    return 0;
}

/* --------------------------------------------------------------------------
 * Command table + module registration
 * -------------------------------------------------------------------------- */

static hypervisor_cmd_t capture_cmd_array[] = {
   /* start_kernel <if> <pcap> [dlt] */
   { "start_kernel", 2, 3, cmd_start_kernel, NULL },
   { "stop_kernel",  0, 0, cmd_stop_kernel, NULL },
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
