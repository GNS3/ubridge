/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2016 GNS3 Technologies Inc. & James E. Carpenter
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

#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ubridge.h"
#include "nio.h"
#include "nio_udp.h"
#include "hypervisor.h"
#include "hypervisor_iol_bridge.h"
#include "pcap_capture.h"
#include "packet_filter.h"
#include "delay_line.h"

iol_bridge_t *iol_bridge_list = NULL;

/* Serializes IOL delay-line pointer access between the relay listeners
 * (iol_delay_route) and command handlers that destroy delay lines
 * (cmd_delete_nio_udp / create_iol_port_entry / cmd_reset_packet_filters).
 *
 * Deliberately a separate mutex from global_lock: those command handlers
 * cancel+join the NIO listener while running under global_lock (the hypervisor
 * dispatcher holds it around every command). If iol_delay_route took
 * global_lock, the listener could be blocked on it at cancel time and never
 * reach a cancellation point, deadlocking the join. The destroy path takes
 * iol_delay_lock only around the delay-line teardown — after the cancel+join —
 * so the two never contend during a join. */
static pthread_mutex_t iol_delay_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- delay line send callbacks (one per IOL direction) ---- */

/* NIO -> IOL: prepend the port's pre-calculated IOL header and sendto the
 * IOL instance. ctx = the port's iol_nio_t. */
static ssize_t iol_sendto_iol_cb(void *ctx, const void *pkt, size_t len)
{
   iol_nio_t *iol_nio = ctx;
   unsigned char buf[IOL_HDR_SIZE + MAX_MTU];

   if (len > MAX_MTU)
      len = MAX_MTU;
   memcpy(buf, iol_nio->header, IOL_HDR_SIZE);
   memcpy(buf + IOL_HDR_SIZE, pkt, len);
   return sendto(iol_nio->iol_bridge_sock, buf, len + IOL_HDR_SIZE, 0,
                 (struct sockaddr *)&iol_nio->iol_sockaddr, sizeof(iol_nio->iol_sockaddr));
}

/* IOL -> NIO: forward via the destination NIO and account for it. ctx = nio. */
static ssize_t iol_nio_send_cb(void *ctx, const void *pkt, size_t len)
{
   nio_t *nio = ctx;
   ssize_t sent = nio_send(nio, (void *)pkt, len);

   if (sent != -1) {
      nio->packets_out++;
      nio->bytes_out += sent;
   }
   return sent;
}

/* Lazily sync *dl to the delay config (have_delay / lat / jit, snapshotted by
 * the caller) and, if delaying, enqueue the packet. Returns TRUE if consumed
 * (the caller must skip its inline send).
 *
 * *dl lives in the shared port_table and is destroyed by command handlers, so
 * the whole read/create/destroy/enqueue is serialized against them with
 * iol_delay_lock (see the note on why not global_lock above). */
static int iol_delay_route(delay_line_t **dl, int have_delay, int lat, int jit,
                           delay_send_fn fn, void *ctx,
                           const void *pkt, size_t len, const char *name)
{
   int cur_lat = -1, cur_jit = -1;
   int consumed = FALSE;

   pthread_mutex_lock(&iol_delay_lock);
   delay_line_config(*dl, &cur_lat, &cur_jit);   /* current line's config, or -1 */

   if (have_delay) {
      if (*dl == NULL || lat != cur_lat || jit != cur_jit) {
         delay_line_destroy(*dl);
         *dl = delay_line_create(lat, jit, fn, ctx);
         if (*dl == NULL)
            fprintf(stderr, "IOL bridge '%s': could not create delay line, forwarding without delay\n", name);
      }
   } else if (*dl != NULL) {
      delay_line_destroy(*dl);
      *dl = NULL;
   }

   if (*dl) {
      if (delay_line_enqueue(*dl, pkt, len) != 0 && debug_level > 0)
         printf("Packet dropped by delay line on IOL bridge '%s'\n", name);
      consumed = TRUE;
   }
   pthread_mutex_unlock(&iol_delay_lock);
   return consumed;
}

static iol_bridge_t *find_bridge(char *bridge_name)
{
   iol_bridge_t *bridge;
   iol_bridge_t *next;

   bridge = iol_bridge_list;
   while (bridge != NULL) {
     if (!strcmp(bridge->name, bridge_name))
         return bridge;
     next = bridge->next;
     bridge = next;
   }
   return (NULL);
}

void *iol_nio_listener(void *data)
{
   iol_nio_t *iol_nio = data;
   iol_bridge_t *bridge;
   ssize_t bytes_received, bytes_sent;
   unsigned char pkt[IOL_HDR_SIZE + MAX_MTU];
   nio_t *nio = iol_nio->destination_nio;
   int drop_packet;

   printf("Listener thread for IOL instance %d on port %d/%d has started\n", iol_nio->iol_id, iol_nio->port.bay, iol_nio->port.unit);
   bridge = find_bridge(iol_nio->parent_bridge_name);
   if (bridge == NULL) {
      fprintf(stderr, "parent bridge '%s' doesn't exist\n", iol_nio->parent_bridge_name);
      pthread_exit(NULL);
   }

   while (1)
     {
        /* Put received bytes after the (absent) IOU header */
        drop_packet = FALSE;
        bytes_received = nio_recv(nio, &pkt[IOL_HDR_SIZE], MAX_MTU);
        if (bytes_received == -1) {
            perror("recv");
            if (errno == ECONNREFUSED || errno == ENETDOWN)
               continue;
            exit(EXIT_FAILURE);
        }

        if (bytes_received > MAX_MTU) {
            fprintf(stderr, "received frame is %zd bytes (maximum is %d bytes)\n", bytes_received, MAX_MTU);
            continue;
        }

        nio->packets_in++;
        nio->bytes_in += bytes_received;

        if (debug_level > 0) {
            printf("Received %zd bytes from destination NIO on IOL bridge '%s'\n", bytes_received, bridge->name);
            if (debug_level > 1)
               dump_packet(stdout, &pkt[IOL_HDR_SIZE], bytes_received);
        }

        /* filter the packet if there is a filter configured; snapshot the
         * delay config under the same lock the hypervisor mutates the list with */
        int have_delay = FALSE, lat_ms = 0, jit_ms = 0;
        pthread_mutex_lock(&global_lock);
        if (iol_nio->packet_filters != NULL) {
             packet_filter_t *filter = iol_nio->packet_filters;
             packet_filter_t *next;
             while (filter != NULL) {
                 if (!filter->enabled) {   /* paused: bypass this filter */
                     filter = filter->next;
                     continue;
                 }
                 if (filter->handler(&pkt[IOL_HDR_SIZE], bytes_received, filter->data, PKT_DIR_RX) == FILTER_ACTION_DROP) {
                     if (debug_level > 0)
                        printf("Packet dropped by packet filter '%s' from destination NIO on IOL bridge '%s'\n", filter->name, bridge->name);
                     drop_packet = TRUE;
                     break;
                 }
                 next = filter->next;
                 filter = next;
             }
         }
        have_delay = packet_filter_get_delay(iol_nio->packet_filters, &lat_ms, &jit_ms);
        pthread_mutex_unlock(&global_lock);

        if (drop_packet == TRUE)
           continue;

        /* Dump the packet to a PCAP file if capture is activated */
        pcap_capture_packet(iol_nio->capture, &pkt[IOL_HDR_SIZE], bytes_received);

        /* route through the NIO->IOL delay line if a delay filter is set */
        if (iol_delay_route(&iol_nio->delay_line_nio, have_delay, lat_ms, jit_ms,
                            iol_sendto_iol_cb, iol_nio,
                            &pkt[IOL_HDR_SIZE], bytes_received, bridge->name))
           continue;

        /* Add the length of the IOU header we'll be sending */
        bytes_received += IOL_HDR_SIZE;


       /* Send the packet to the IOU node(s) in our segment. For each
        * node, we copy the pre-calculated IOU header into the
        * beginning of the buffer before sending.
        */
        memcpy(pkt, &(iol_nio->header), sizeof(iol_nio->header));
        bytes_sent = sendto(iol_nio->iol_bridge_sock, pkt, bytes_received, 0, (struct sockaddr *)&iol_nio->iol_sockaddr, sizeof(iol_nio->iol_sockaddr));
        if (bytes_sent == -1) {
           perror("sendto");
           if (errno == ECONNREFUSED || errno == ENETDOWN || errno == ENOENT)
              continue;
           exit(EXIT_FAILURE);
        }
     }

  printf("Listener thread for IOL instance %d on port %d/%d has stopped\n", iol_nio->iol_id, iol_nio->port.bay, iol_nio->port.unit);
  pthread_exit(NULL);
}

void *iol_bridge_listener(void *data)
{
   iol_bridge_t *bridge = data;
   nio_t *nio;
   ssize_t bytes_received, bytes_sent;
   unsigned char pkt[IOL_HDR_SIZE + MAX_MTU];
   unsigned int port;
   int drop_packet;

   printf("IOL bridge listener thread for %s with ID %d has started\n", bridge->name, bridge->application_id);
   while (1)
    {
       /* This receives from an IOL instance */
       drop_packet = FALSE;
       bytes_received = read(bridge->iol_bridge_sock, pkt, IOL_HDR_SIZE + MAX_MTU);
       if (bytes_received == -1) {
           perror("recv");
           if (errno == ECONNREFUSED || errno == ENETDOWN)
              continue;
           exit(EXIT_FAILURE);
       }

       if (debug_level > 0) {
           printf("Received %zd bytes from IOL instance on IOL bridge '%s'\n", bytes_received, bridge->name);
           if (debug_level > 1)
              dump_packet(stdout, pkt, bytes_received);
       }

       if (bytes_received <= IOL_HDR_SIZE)
          continue;

       /* Get the port number we were addressed as */
       port = pkt[IOL_DST_PORT];

       /* Send on the packet, minus the IOL header */
       bytes_received -= IOL_HDR_SIZE;

        /* filter the packet if there is a filter configured; snapshot the
         * delay config under the same lock the hypervisor mutates the list with.
         * Re-validate destination_nio under the lock: it may have been set to
         * NULL by cmd_delete_nio_udp while we were blocked in read(). */
       int have_delay = FALSE, lat_ms = 0, jit_ms = 0;
       pthread_mutex_lock(&global_lock);
       nio = bridge->port_table[port].destination_nio;
       if (nio == NULL) {
            pthread_mutex_unlock(&global_lock);
            continue;
       }
       if (bridge->port_table[port].packet_filters != NULL) {
            packet_filter_t *filter = bridge->port_table[port].packet_filters;
            packet_filter_t *next;
            while (filter != NULL) {
                if (!filter->enabled) {   /* paused: bypass this filter */
                    filter = filter->next;
                    continue;
                }
                if (filter->handler(&pkt[IOL_HDR_SIZE], bytes_received, filter->data, PKT_DIR_TX) == FILTER_ACTION_DROP) {
                    if (debug_level > 0)
                       printf("Packet dropped by packet filter '%s' from IOL instance on IOL bridge '%s'\n", filter->name, bridge->name);
                    drop_packet = TRUE;
                    break;
                }
                next = filter->next;
                filter = next;
            }
       }
       have_delay = packet_filter_get_delay(bridge->port_table[port].packet_filters, &lat_ms, &jit_ms);
       pthread_mutex_unlock(&global_lock);

       if (drop_packet == TRUE)
          continue;

       /* Dump the packet to a PCAP file if capture is activated */
       pcap_capture_packet(bridge->port_table[port].capture, &pkt[IOL_HDR_SIZE], bytes_received);

       /* Destination NIO hasn't been created yet */
       if (nio == NULL)
          continue;

       /* route through the IOL->NIO delay line if a delay filter is set */
       if (iol_delay_route(&bridge->port_table[port].delay_line_iol, have_delay, lat_ms, jit_ms,
                           iol_nio_send_cb, nio,
                           &pkt[IOL_HDR_SIZE], bytes_received, bridge->name))
          continue;

       bytes_sent = nio->send(nio->dptr, &pkt[IOL_HDR_SIZE], bytes_received);
       nio->packets_out++;
       nio->bytes_out += bytes_sent;
       if (bytes_sent == -1) {
          perror("send");

          /* EINVAL can be caused by sending to a blackhole route, this happens if a NIC link status changes */
          if (errno == ECONNREFUSED || errno == ENETDOWN || errno == EINVAL)
             continue;

          exit(EXIT_FAILURE);
       }
    }

  printf("IOL bridge listener thread for %s with ID %d has stopped\n", bridge->name, bridge->application_id);
  pthread_exit(NULL);
}

static pid_t get_unix_socket_lock(const char *name)
{
   char semaphore[FILENAME_MAX];
   int fd;
   struct flock fl;
   int e;

   if (strlen(name) < 1) {
      errno = EINVAL;
      return -1;
   }

   snprintf(semaphore, sizeof semaphore, "%s.lck", name);
   if ((fd = open(semaphore, O_RDONLY)) < 0)
      return -1;

   fl.l_type = F_WRLCK;
   fl.l_whence = SEEK_SET;
   fl.l_start = 0;
   fl.l_len = 0;
   fl.l_pid = getpid ();

   if (fcntl (fd, F_GETLK, &fl) < 0) {
      e = errno;
      close (fd);
      errno = e;
      return -1;
   }

   close (fd);
   return fl.l_pid;
}

static int lock_unix_socket(const char *name)
{
   char semaphore[FILENAME_MAX];
   int fd;
   char pid[12];
   int pid_len;
   struct flock fl;
   int e;

   if (strlen(name) < 1) {
      errno = EINVAL;
      return -1;
   }

   snprintf(semaphore, sizeof semaphore, "%s.lck", name);

    // Either find a lock-file or create a new one
   if ((fd = open(semaphore, O_WRONLY)) < 0 && errno == ENOENT)
     fd = open(semaphore, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
   if (fd < 0)
     return -1;

   fl.l_type = F_WRLCK;
   fl.l_whence = SEEK_SET;
   fl.l_start = 0;
   fl.l_len = 0;

   if (fcntl (fd, F_SETLK, &fl) < 0) {
      close (fd);
      errno = EADDRINUSE;
      return -1;
   }

   // We have the lock. Wipe out the file and put our PID in it.
   if (ftruncate (fd, 0) == -1)
      return -1;
   pid_len = snprintf(pid, sizeof(pid), "%ld\n", (long) getpid ());
   if (write(fd, pid, pid_len) == -1) {
      e = errno;
      // Something is wrong. Roll back.
      unlock_unix_socket(fd, name);
      errno = e;
      return -1;
   }

   return (fd);
}

int unlock_unix_socket(int fd, const char *name)
{
   char semaphore[FILENAME_MAX];
   int result;
   int e;

   if (fd < 0) {
      errno = EINVAL;
      return -1;
   }

   snprintf (semaphore, sizeof semaphore, "%s.lck", name);

   /* Unlinking before close avoids a race condition where we
    * could accidentally delete the next lock file.
    */
   result = unlink(semaphore);
   e = errno;
   close(fd);
   errno = e;

   return (result);
}

static int create_iol_unix_socket(iol_bridge_t *bridge)
{
   int fd = -1;

   if ((fd = socket (AF_UNIX, SOCK_DGRAM, 0)) < 0) {
      perror("create_iol_unix_socket: socket");
      return (-1);
   }

   unlink(bridge->bridge_sockaddr.sun_path);
   if (bind(fd, (struct sockaddr *)&(bridge->bridge_sockaddr), sizeof(bridge->bridge_sockaddr))) {
      perror("create_iol_unix_socket: bind");
      return (-1);
   }

   if (getuid() != geteuid())
     if (chown(bridge->bridge_sockaddr.sun_path, getuid (), -1)) {
        perror("create_iol_unix_socket: chown");
        return (-1);
     }

   return (fd);
}

static int cmd_create_bridge(hypervisor_conn_t *conn, int argc, char *argv[])
{
   int i;
   pid_t lock_pid;
   iol_bridge_t *new_bridge;
   iol_bridge_t **head;
   char netio_path[108];
   struct stat st;

   if (find_bridge(argv[0]) != NULL) {
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "IOL bridge '%s' already exist", argv[0]);
      return (-1);
   }

   head = &iol_bridge_list;
   if ((new_bridge = malloc(sizeof(*new_bridge))) == NULL)
      goto memory_error;
   memset(new_bridge, 0, sizeof(*new_bridge));
   if ((new_bridge->name = strdup(argv[0])) == NULL)
      goto memory_error;
   new_bridge->running = FALSE;
   new_bridge->application_id = atoi(argv[1]);
   memset(&(new_bridge->bridge_sockaddr), 0, sizeof(new_bridge->bridge_sockaddr));
   new_bridge->bridge_sockaddr.sun_family = AF_UNIX;


   snprintf(netio_path, sizeof(netio_path), "/tmp/netio%u", getuid());
   if (stat(netio_path, &st) == -1) {
       mkdir(netio_path, 0700);
   }

   snprintf(new_bridge->bridge_sockaddr.sun_path, sizeof(new_bridge->bridge_sockaddr.sun_path), "/tmp/netio%u/%u", getuid(), new_bridge->application_id);

   if ((new_bridge->sock_lock = lock_unix_socket(new_bridge->bridge_sockaddr.sun_path)) < 0) {
       if ((lock_pid = get_unix_socket_lock(new_bridge->bridge_sockaddr.sun_path)) < 0) {
          hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not create IOL bridge '%s': could not get lock on %s", argv[0], new_bridge->bridge_sockaddr.sun_path);
          return (-1);
       }
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not create IOL bridge '%s': PID %u already has a lock on ID %u", argv[0], lock_pid, new_bridge->application_id);
      return (-1);
   }

   new_bridge->iol_bridge_sock = create_iol_unix_socket(new_bridge);
   if (new_bridge->iol_bridge_sock == -1) {
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not create IOL bridge '%s': cannot create UNIX domain socket", argv[0]);
      return (-1);
   }

   if (!(new_bridge->port_table = calloc(MAX_PORTS, sizeof *(new_bridge->port_table))))
      goto memory_error;
   for (i = 0; i < MAX_PORTS; i++)
   {
      new_bridge->port_table[i].iol_bridge_sock = new_bridge->iol_bridge_sock;
      new_bridge->port_table[i].parent_bridge_name = new_bridge->name;
      new_bridge->port_table[i].iol_id = 0;
      new_bridge->port_table[i].destination_nio = NULL;
      new_bridge->port_table[i].capture = NULL;
      new_bridge->port_table[i].packet_filters = NULL;
      new_bridge->port_table[i].delay_line_nio = NULL;
      new_bridge->port_table[i].delay_line_iol = NULL;
   }

   new_bridge->next = *head;
   *head = new_bridge;
   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "IOL bridge '%s' created", argv[0]);
   return (0);

   memory_error:
   hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not create IOL bridge '%s': insufficient memory", argv[0]);
   return (-1);
}

static int cmd_delete_bridge(hypervisor_conn_t *conn, int argc, char *argv[])
{
    iol_bridge_t **head;
    iol_bridge_t *bridge;
    iol_bridge_t *prev = NULL;
    int i;

    head = &iol_bridge_list;
    for (bridge = *head; bridge != NULL; prev = bridge, bridge = bridge->next) {
       if (!strcmp(bridge->name, argv[0])) {
          if (prev == NULL)
             *head = bridge->next;
          else
             prev->next = bridge->next;

          if (bridge->running) {
             pthread_cancel(bridge->bridge_tid);
             pthread_join(bridge->bridge_tid, NULL);
             bridge->bridge_tid = 0;

             for (i = 0; i < MAX_PORTS; i++) {
                if (bridge->port_table[i].destination_nio != NULL) {
                    pthread_cancel(bridge->port_table[i].tid);
                    pthread_join(bridge->port_table[i].tid, NULL);
                    bridge->port_table[i].tid = 0;
                    delay_line_destroy(bridge->port_table[i].delay_line_nio);
                    delay_line_destroy(bridge->port_table[i].delay_line_iol);
                    free_pcap_capture(bridge->port_table[i].capture);
                    free_packet_filters(bridge->port_table[i].packet_filters);
                    free_nio(bridge->port_table[i].destination_nio);
                }
             }
             free(bridge->port_table);
          }

          /* close after delay lines are torn down (their release threads
           * sendto this socket) */
          close(bridge->iol_bridge_sock);
          unlink(bridge->bridge_sockaddr.sun_path);
          if ((unlock_unix_socket(bridge->sock_lock, bridge->bridge_sockaddr.sun_path)) == -1)
              fprintf(stderr, "failed to unlock %s\n", bridge->bridge_sockaddr.sun_path);
          if (bridge->name)
             free(bridge->name);
          free(bridge);
          hypervisor_send_reply(conn, HSC_INFO_OK, 1, "IOL bridge '%s' deleted", argv[0]);
          return (0);
      }
   }
   hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "IOL bridge '%s' doesn't exist", argv[0]);
   return (-1);
}

static int cmd_start_bridge(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_bridge_t *bridge;
   int i;
   int s;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "IOL bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   if (bridge->running) {
      hypervisor_send_reply(conn, HSC_ERR_START, 1, "IOL bridge '%s' is already running", argv[0]);
      return (-1);
   }

   s = pthread_create(&(bridge->bridge_tid), NULL, &iol_bridge_listener, bridge);
   if (s != 0) {
      handle_error_en(s, "pthread_create");
      hypervisor_send_reply(conn, HSC_ERR_START, 1, "cannot create bridge NIO thread for IOL bridge '%s'", argv[0]);
      return (-1);
   }

   for (i = 0; i < MAX_PORTS; i++) {
      if (bridge->port_table[i].destination_nio != NULL) {
         s = pthread_create(&(bridge->port_table[i].tid), NULL, &iol_nio_listener, &(bridge->port_table[i]));
         if (s != 0) {
            handle_error_en(s, "pthread_create");
            hypervisor_send_reply(conn, HSC_ERR_START, 1, "cannot create destination NIO thread for IOL bridge '%s'", argv[0]);
            return (-1);
         }
      }
   }
   bridge->running = TRUE;
   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "IOL bridge '%s' started", argv[0]);
   return (0);
}

static int cmd_stop_bridge(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_bridge_t *bridge;
   int i;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "IOL bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   if (!bridge->running) {
      hypervisor_send_reply(conn, HSC_ERR_STOP, 1, "IOL bridge '%s' is not running", argv[0]);
      return (-1);
   }

   pthread_cancel(bridge->bridge_tid);
   pthread_join(bridge->bridge_tid, NULL);
   bridge->bridge_tid = 0;
   for (i = 0; i < MAX_PORTS; i++) {
      if (bridge->port_table[i].destination_nio != NULL) {
          pthread_cancel(bridge->port_table[i].tid);
          pthread_join(bridge->port_table[i].tid, NULL);
          bridge->port_table[i].tid = 0;
      }
   }
   bridge->running = FALSE;
   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "IOL bridge '%s' stopped", argv[0]);
   return (0);
}

static int cmd_rename_bridge(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_bridge_t *bridge;
   char *newname;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "IOL bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   if (find_bridge(argv[1]) != NULL) {
      hypervisor_send_reply(conn, HSC_ERR_RENAME, 1, "IOL bridge '%s' already exist", argv[0]);
      return (-1);
   }

   if(!(newname = strdup(argv[1]))) {
      hypervisor_send_reply(conn, HSC_ERR_RENAME, 1, "unable to rename IOL bridge '%s', out of memory", argv[0]);
      return(-1);
   }

   if (bridge->name)
       free(bridge->name);
   bridge->name = newname;
   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "IOL bridge '%s' renamed to '%s'", argv[0], argv[1]);
   return (0);
}

static int cmd_list_bridges(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_bridge_t *bridge;
   iol_bridge_t *next;
   int ports;
   int i;

   bridge = iol_bridge_list;
   while (bridge != NULL) {
     ports = 0;
     for (i = 0; i < MAX_PORTS; i++) {
        if (bridge->port_table[i].destination_nio != NULL)
           ports += 1;
     }
     hypervisor_send_reply(conn, HSC_INFO_MSG, 0, "%s (ports = %d)", bridge->name, ports);
     next = bridge->next;
     bridge = next;
   }

   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "OK");
   return (0);
}

static int cmd_get_stats_bridge(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_bridge_t *bridge;
   int i;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   for (i = 0; i < MAX_PORTS; i++) {
      if (bridge->port_table[i].destination_nio != NULL) {
         hypervisor_send_reply(conn, HSC_INFO_MSG, 0, "port %d/%d:      IN: %zd packets (%zd bytes) OUT: %zd packets (%zd bytes)",
         bridge->port_table[i].port.bay, bridge->port_table[i].port.unit,
         bridge->port_table[i].destination_nio->packets_in, bridge->port_table[i].destination_nio->bytes_in,
         bridge->port_table[i].destination_nio->packets_out, bridge->port_table[i].destination_nio->bytes_out);
      }

   }

   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "OK");
   return (0);
}

static int cmd_reset_stats_bridge(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_bridge_t *bridge;
   int i;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   for (i = 0; i < MAX_PORTS; i++) {
      if (bridge->port_table[i].destination_nio != NULL) {
         bridge->port_table[i].destination_nio->packets_in = bridge->port_table[i].destination_nio->bytes_in = 0;
         bridge->port_table[i].destination_nio->packets_out = bridge->port_table[i].destination_nio->bytes_out = 0;
      }
   }

   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "OK");
   return (0);
}

static int create_iol_port_entry(hypervisor_conn_t *conn, iol_bridge_t *bridge, int iol_id, unsigned char port_bay, unsigned char port_unit, nio_t *nio)
{
   iol_nio_t *iol_nio;
   unsigned char port_key;
   int s;

   port_key = port_bay + port_unit * 16;
   if (bridge->application_id == iol_id) {
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "IOU ID %d cannot be the same as bridge '%s' ID", iol_id, bridge->name);
      goto error;
   }

   if (port_key > MAX_PORTS) {
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Port number %d exceeding %d on bridge '%s'", port_key, MAX_PORTS, bridge->name);
      goto error;
   }

   iol_nio = &bridge->port_table[port_key];
   iol_nio->iol_id = iol_id;
   iol_nio->port.bay = port_bay;
   iol_nio->port.unit = port_unit;
   memset(&iol_nio->iol_sockaddr, 0, sizeof(iol_nio->iol_sockaddr));
   iol_nio->iol_sockaddr.sun_family = AF_UNIX;
   snprintf(iol_nio->iol_sockaddr.sun_path, sizeof(iol_nio->iol_sockaddr.sun_path), "/tmp/netio%u/%u", getuid(), iol_id);

   /* create the IOL header */

   /* destination id */
   iol_nio->header[IOL_DST_IDS] = iol_id >> 8;
   iol_nio->header[IOL_DST_IDS+1] = iol_id & 255;

   /* source id */
   iol_nio->header[IOL_SRC_IDS] = bridge->application_id >> 8;
   iol_nio->header[IOL_SRC_IDS+1] = bridge->application_id & 255;

   /* destination port */
   iol_nio->header[IOL_DST_PORT] = port_key;

   /* source port */
   iol_nio->header[IOL_SRC_PORT] = port_key;

   /* message type */
   iol_nio->header[IOL_MSG_TYPE] = IOL_MSG_TYPE_DATA;

   /* channel number */
   iol_nio->header[IOL_CHANNEL] = 0;

   /* stop any previous NIO thread. Guard the cancel on tid, not on
    * destination_nio: after iol_bridge stop (or if the port was never
    * started) the listener is joined and tid == 0, while destination_nio is
    * retained so the port can be restarted — pthread_cancel(0) segfaults. */
   if (iol_nio->destination_nio != NULL) {
      if (iol_nio->tid != 0) {
         pthread_cancel(iol_nio->tid);
         pthread_join(iol_nio->tid, NULL);
         iol_nio->tid = 0;
      }
      /* Tear down the delay lines under iol_delay_lock, serialized against the
       * listeners' iol_delay_route. The cancel+join above already stopped this
       * port's NIO listener, but the IOL bridge listener (bridge_tid) is still
       * live and may be in iol_delay_route on delay_line_iol. */
      pthread_mutex_lock(&iol_delay_lock);
      delay_line_t *old_nio = iol_nio->delay_line_nio;
      iol_nio->delay_line_nio = NULL;
      delay_line_t *old_iol = iol_nio->delay_line_iol;
      iol_nio->delay_line_iol = NULL;
      delay_line_destroy(old_nio);
      delay_line_destroy(old_iol);
      pthread_mutex_unlock(&iol_delay_lock);
      free_pcap_capture(iol_nio->capture);
      free_packet_filters(iol_nio->packet_filters);
      free_nio(iol_nio->destination_nio);
   }

   iol_nio->capture = NULL;
   iol_nio->packet_filters = NULL;
   iol_nio->destination_nio = nio;
   /* start the NIO thread if the bridge is already running */
   if (bridge->running) {
      s = pthread_create(&(iol_nio->tid), NULL, &iol_nio_listener, iol_nio);
      if (s != 0) {
         handle_error_en(s, "pthread_create");
         hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "cannot create destination NIO thread for IOL bridge '%s'", bridge->name);
         goto error;
      }
   }
   return (0);

error:
   free_nio(nio);
   return (-1);
}

static int cmd_add_nio_udp(hypervisor_conn_t *conn, int argc, char *argv[])
{
   nio_t *nio;
   iol_bridge_t *bridge;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   nio = create_nio_udp(atoi(argv[4]), argv[5], atoi(argv[6]));
   if (!nio) {
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "unable to create NIO UDP for IOL bridge '%s'", argv[0]);
      return (-1);
   }

   if (create_iol_port_entry(conn, bridge, atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), nio) == -1)
      return (-1);

   hypervisor_send_reply(conn, HSC_INFO_OK,1, "NIO UDP added to IOL bridge '%s'", argv[0]);
   return (0);
}

static int cmd_delete_nio_udp(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_nio_t *iol_nio;
   iol_bridge_t *bridge;
   unsigned char port_bay;
   unsigned char port_unit;
   unsigned char port_key;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   port_bay = atoi(argv[1]);
   port_unit = atoi(argv[2]);
   port_key = port_bay + port_unit * 16;
   if (port_key > MAX_PORTS) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "Port number %d exceeding %d on bridge '%s'", port_key, MAX_PORTS, bridge->name);
      return (-1);
   }

   iol_nio = &bridge->port_table[port_key];
   if (iol_nio == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "port %d/%d doesn't exist", port_bay, port_unit);
      return (-1);
   }

   /* stop any previous NIO thread. Guard the cancel on tid, not on
    * destination_nio: after iol_bridge stop (or if the port was never
    * started) the listener is joined and tid == 0, while destination_nio is
    * retained so the port can be restarted — pthread_cancel(0) segfaults. */
   if (iol_nio->destination_nio != NULL) {
      if (iol_nio->tid != 0) {
         pthread_cancel(iol_nio->tid);
         pthread_join(iol_nio->tid, NULL);
         iol_nio->tid = 0;
      }
      /* Tear down the delay lines under iol_delay_lock, serialized against the
       * listeners' iol_delay_route. The cancel+join above already stopped this
       * port's NIO listener, but the IOL bridge listener (bridge_tid) is still
       * live and may be in iol_delay_route on delay_line_iol. */
      pthread_mutex_lock(&iol_delay_lock);
      delay_line_t *old_nio = iol_nio->delay_line_nio;
      iol_nio->delay_line_nio = NULL;
      delay_line_t *old_iol = iol_nio->delay_line_iol;
      iol_nio->delay_line_iol = NULL;
      delay_line_destroy(old_nio);
      delay_line_destroy(old_iol);
      pthread_mutex_unlock(&iol_delay_lock);
      free_pcap_capture(iol_nio->capture);
      free_packet_filters(iol_nio->packet_filters);
      free_nio(iol_nio->destination_nio);
   }

   iol_nio->capture = NULL;
   iol_nio->packet_filters = NULL;
   iol_nio->destination_nio = NULL;
   hypervisor_send_reply(conn, HSC_INFO_OK,1, "NIO UDP deleted from IOL bridge '%s'", argv[0]);
   return (0);
}

static int cmd_start_capture_bridge(hypervisor_conn_t *conn, int argc, char *argv[])
{
   char *pcap_linktype = "EN10MB";
   iol_nio_t *iol_nio;
   iol_bridge_t *bridge;
   unsigned char port_bay;
   unsigned char port_unit;
   unsigned char port_key;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   port_bay = atoi(argv[1]);
   port_unit = atoi(argv[2]);
   port_key = port_bay + port_unit * 16;
   if (port_key > MAX_PORTS) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "Port number %d exceeding %d on bridge '%s'", port_key, MAX_PORTS, bridge->name);
      return (-1);
   }

   iol_nio = &bridge->port_table[port_key];
   if (iol_nio == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "port %d/%d doesn't exist", port_bay, port_unit);
      return (-1);
   }

   if (iol_nio->capture != NULL) {
      hypervisor_send_reply(conn, HSC_ERR_START, 1, "packet capture is already active on port %d/%d", port_bay, port_unit);
      return (-1);
   }

   if (argc == 5)
      pcap_linktype = argv[4];

   if (!(iol_nio->capture = create_pcap_capture(argv[3], pcap_linktype))) {
      hypervisor_send_reply(conn, HSC_ERR_START, 1, "packet capture could not be started on bridge '%s'", argv[0]);
      return (-1);
   }

   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "packet capture started on port %d/%d", port_bay, port_unit);
   return (0);
}

static int cmd_stop_capture_bridge(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_bridge_t *bridge;
   iol_nio_t *iol_nio;
   unsigned char port_bay;
   unsigned char port_unit;
   unsigned char port_key;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   port_bay = atoi(argv[1]);
   port_unit = atoi(argv[2]);
   port_key = port_bay + port_unit * 16;
   if (port_key > MAX_PORTS) {
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Port number %d exceeding %d on bridge '%s'", port_key, MAX_PORTS, bridge->name);
      return (-1);
   }

   iol_nio = &bridge->port_table[port_key];
   if (iol_nio == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "port %d/%d doesn't exist", port_bay, port_unit);
      return (-1);
   }

   if (iol_nio->capture == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "no packet capture active on port %d/%d", port_bay, port_unit);
      return (-1);
   }

   free_pcap_capture(iol_nio->capture);
   iol_nio->capture = NULL;
   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "packet capture stopped on port %d/%d", port_bay, port_unit);
   return (0);
}

static int cmd_add_packet_filter(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_bridge_t *bridge;
   iol_nio_t *iol_nio;
   unsigned char port_bay;
   unsigned char port_unit;
   unsigned char port_key;
   int res;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   port_bay = atoi(argv[1]);
   port_unit = atoi(argv[2]);
   port_key = port_bay + port_unit * 16;
   if (port_key > MAX_PORTS) {
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Port number %d exceeding %d on bridge '%s'", port_key, MAX_PORTS, bridge->name);
      return (-1);
   }

   iol_nio = &bridge->port_table[port_key];
   if (iol_nio == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "port %d/%d doesn't exist", port_bay, port_unit);
      return (-1);
   }

   res = add_packet_filter(&iol_nio->packet_filters, argv[3], argv[4], argc-5, &argv[5]);
   if (!res)
      hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Filter '%s' type '%s' added to bridge '%s'", argv[3], argv[4], argv[0]);
   else
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Failed to add filter '%s'", argv[3]);
   return (0);
}

static int cmd_delete_packet_filter(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_bridge_t *bridge;
   iol_nio_t *iol_nio;
   unsigned char port_bay;
   unsigned char port_unit;
   unsigned char port_key;
   int res;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   port_bay = atoi(argv[1]);
   port_unit = atoi(argv[2]);
   port_key = port_bay + port_unit * 16;
   if (port_key > MAX_PORTS) {
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Port number %d exceeding %d on bridge '%s'", port_key, MAX_PORTS, bridge->name);
      return (-1);
   }

   iol_nio = &bridge->port_table[port_key];
   if (iol_nio == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "port %d/%d doesn't exist", port_bay, port_unit);
      return (-1);
   }

   res = delete_packet_filter(&iol_nio->packet_filters, argv[3]);
   if (!res)
      hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Filter '%s' deleted from bridge '%s'", argv[3], argv[0]);
   else
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Failed to delete filter '%s'", argv[3]);
   return (0);
}

static int cmd_reset_packet_filters(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_bridge_t *bridge;
   iol_nio_t *iol_nio;
   unsigned char port_bay;
   unsigned char port_unit;
   unsigned char port_key;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   port_bay = atoi(argv[1]);
   port_unit = atoi(argv[2]);
   port_key = port_bay + port_unit * 16;
   if (port_key > MAX_PORTS) {
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Port number %d exceeding %d on bridge '%s'", port_key, MAX_PORTS, bridge->name);
      return (-1);
   }

   iol_nio = &bridge->port_table[port_key];
   if (iol_nio == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "port %d/%d doesn't exist", port_bay, port_unit);
      return (-1);
   }

   /* Dropping the filters also drops any in-flight delay. Tear down the lines
    * under iol_delay_lock (serialized against the listeners' iol_delay_route);
    * this handler stops neither listener, so both may be mid-route. The filter
    * list free below is covered by global_lock, which the dispatcher already
    * holds around this command. */
   pthread_mutex_lock(&iol_delay_lock);
   delay_line_t *old_nio = iol_nio->delay_line_nio;
   iol_nio->delay_line_nio = NULL;
   delay_line_t *old_iol = iol_nio->delay_line_iol;
   iol_nio->delay_line_iol = NULL;
   delay_line_destroy(old_nio);
   delay_line_destroy(old_iol);
   pthread_mutex_unlock(&iol_delay_lock);
   /* impairment reset: preserve any `mark` observability tap (open pcap); the
    * delay lines above are torn down regardless, since the delay filter is dropped. */
   reset_impairment_filters(&iol_nio->packet_filters);

   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "OK");
   return (0);
}

/* iol_bridge enable_packet_filter <bridge> <bay> <unit> <name> <on|off> —
 * pause/resume a filter on an IOL port. Runs under the dispatcher's global_lock,
 * which the IOL listeners also hold during their filter walk. */
static int cmd_enable_packet_filter(hypervisor_conn_t *conn, int argc, char *argv[])
{
   iol_bridge_t *bridge;
   iol_nio_t *iol_nio;
   unsigned char port_bay, port_unit, port_key;
   int enabled, res;

   bridge = find_bridge(argv[0]);
   if (bridge == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "bridge '%s' doesn't exist", argv[0]);
      return (-1);
   }

   port_bay = atoi(argv[1]);
   port_unit = atoi(argv[2]);
   port_key = port_bay + port_unit * 16;
   if (port_key > MAX_PORTS) {
      hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "Port number %d exceeding %d on bridge '%s'", port_key, MAX_PORTS, bridge->name);
      return (-1);
   }

   iol_nio = &bridge->port_table[port_key];
   if (iol_nio == NULL) {
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "port %d/%d doesn't exist", port_bay, port_unit);
      return (-1);
   }

   if (!strcmp(argv[4], "on"))
      enabled = TRUE;
   else if (!strcmp(argv[4], "off"))
      enabled = FALSE;
   else {
      hypervisor_send_reply(conn, HSC_ERR_INV_PARAM, 1, "expected 'on' or 'off', got '%s'", argv[4]);
      return (-1);
   }

   res = set_packet_filter_enabled(iol_nio->packet_filters, argv[3], enabled);
   if (res)
      hypervisor_send_reply(conn, HSC_INFO_OK, 1, "Filter '%s' %s on IOL bridge '%s' port %d/%d",
                            argv[3], enabled ? "enabled" : "paused", argv[0], port_bay, port_unit);
   else
      hypervisor_send_reply(conn, HSC_ERR_NOT_FOUND, 1, "Filter '%s' not found on IOL bridge '%s' port %d/%d",
                            argv[3], argv[0], port_bay, port_unit);
   return (0);
}

/* Bridge commands */
static hypervisor_cmd_t iol_bridge_cmd_array[] = {
   { "create", 2, 2, cmd_create_bridge, NULL },
   { "delete", 1, 1, cmd_delete_bridge, NULL },
   { "start", 1, 1, cmd_start_bridge, NULL },
   { "stop", 1, 1, cmd_stop_bridge, NULL },
   { "get_stats", 1, 1, cmd_get_stats_bridge, NULL },
   { "reset_stats", 1, 1, cmd_reset_stats_bridge, NULL },
   { "rename", 2, 2, cmd_rename_bridge, NULL },
   { "add_nio_udp", 7, 7, cmd_add_nio_udp, NULL },
   { "delete_nio_udp", 3, 3, cmd_delete_nio_udp, NULL },
   { "start_capture", 4, 5, cmd_start_capture_bridge, NULL },
   { "stop_capture", 3, 3, cmd_stop_capture_bridge, NULL },
   { "add_packet_filter", 4, 15, cmd_add_packet_filter, NULL },
   { "delete_packet_filter", 4, 4, cmd_delete_packet_filter, NULL },
   { "reset_packet_filters", 3, 3, cmd_reset_packet_filters, NULL },
   { "enable_packet_filter", 5, 5, cmd_enable_packet_filter, NULL },
   { "list", 0, 0, cmd_list_bridges, NULL },
   { NULL, -1, -1, NULL, NULL },
};

/* Hypervisor IOL initialization */
int hypervisor_iol_bridge_init(void)
{
   hypervisor_module_t *module;

   module = hypervisor_register_module("iol_bridge", NULL);
   assert(module != NULL);

   hypervisor_register_cmd_array(module, iol_bridge_cmd_array);
   return(0);
}
