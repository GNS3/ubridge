/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2017 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   ubridge is distributed in the hope that it will be useful, but
 *   WITHOUT ANY EVEN THE IMPLIED WARRANTY OF MERCHANTABILITY or
 *   FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "delay_line.h"

#define DL_MAX_PKT 65535   /* matches NIO_MAX_PKT_SIZE */

/* One queued packet. The list is kept ordered by release (earliest first). */
typedef struct dl_entry {
   struct timespec release;        /* absolute time the packet becomes due */
   size_t len;
   struct dl_entry *next;
   unsigned char pkt[];            /* flexible array member */
} dl_entry_t;

struct delay_line {
   int base_latency_ms;
   int jitter_ms;
   delay_send_fn send_fn;
   void *send_ctx;
   clockid_t clock;                /* clock used for release times + cond */
   pthread_mutex_t lock;
   pthread_cond_t cond;            /* signaled when head changes or on stop */
   dl_entry_t *head;               /* earliest-release entry, or NULL */
   int stop;                       /* set by delay_line_destroy */
   pthread_t release_tid;
};

/* now -> *ts on the delay line's clock */
static void dl_now(clockid_t clock, struct timespec *ts)
{
   clock_gettime(clock, ts);
}

/* *ts += ms (ms may be negative, but we clamp the caller's delay to >= 0) */
static void dl_add_ms(struct timespec *ts, int ms)
{
   ts->tv_sec += ms / 1000;
   ts->tv_nsec += (long)(ms % 1000) * 1000000L;
   if (ts->tv_nsec >= 1000000000L) {
      ts->tv_sec += ts->tv_nsec / 1000000000L;
      ts->tv_nsec %= 1000000000L;
   } else if (ts->tv_nsec < 0) {
      ts->tv_sec -= 1 + ((-ts->tv_nsec - 1) / 1000000000L);
      ts->tv_nsec += 1000000000L * (1 + ((-ts->tv_nsec - 1) / 1000000000L));
   }
}

/* a <= b ? */
static int dl_le(const struct timespec *a, const struct timespec *b)
{
   if (a->tv_sec != b->tv_sec)
      return a->tv_sec < b->tv_sec;
   return a->tv_nsec <= b->tv_nsec;
}

/* Release thread: send packets as their release time arrives, in order. */
static void *delay_release_thread(void *arg)
{
   delay_line_t *dl = arg;
   dl_entry_t *e;
   struct timespec now;

   pthread_mutex_lock(&dl->lock);
   while (!dl->stop) {
      if (dl->head == NULL) {
         /* nothing queued: wait for the producer to signal */
         pthread_cond_wait(&dl->cond, &dl->lock);
         continue;
      }
      dl_now(dl->clock, &now);
      if (dl_le(&dl->head->release, &now)) {
         /* due now: pop and send outside the lock so enqueue can proceed */
         e = dl->head;
         dl->head = e->next;
         pthread_mutex_unlock(&dl->lock);
         dl->send_fn(dl->send_ctx, e->pkt, e->len);
         free(e);
         pthread_mutex_lock(&dl->lock);
         continue;
      }
      /* wait until the head is due; an earlier head inserted meanwhile
       * signals the cond so we re-evaluate. */
      pthread_cond_timedwait(&dl->cond, &dl->lock, &dl->head->release);
   }
   pthread_mutex_unlock(&dl->lock);
   return NULL;
}

delay_line_t *delay_line_create(int base_latency_ms, int jitter_ms,
                                delay_send_fn send_fn, void *send_ctx)
{
   delay_line_t *dl;
   pthread_condattr_t attr;
   int s;

   if (!(dl = malloc(sizeof(*dl))))
      return NULL;
   memset(dl, 0, sizeof(*dl));
   dl->base_latency_ms = base_latency_ms;
   dl->jitter_ms = jitter_ms;
   dl->send_fn = send_fn;
   dl->send_ctx = send_ctx;
   dl->head = NULL;
   dl->stop = 0;

   pthread_mutex_init(&dl->lock, NULL);

   /* Prefer CLOCK_MONOTONIC so wall-clock jumps (NTP, settimeofday) can't
    * stretch or shrink the delay. Fall back to CLOCK_REALTIME where the
    * cond clock can't be set (e.g. macOS) and match clock_gettime to it. */
   dl->clock = CLOCK_MONOTONIC;
   pthread_condattr_init(&attr);
   if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0)
      dl->clock = CLOCK_REALTIME;
   pthread_cond_init(&dl->cond, &attr);
   pthread_condattr_destroy(&attr);

   s = pthread_create(&dl->release_tid, NULL, delay_release_thread, dl);
   if (s != 0) {
      pthread_cond_destroy(&dl->cond);
      pthread_mutex_destroy(&dl->lock);
      free(dl);
      return NULL;
   }
   return dl;
}

int delay_line_enqueue(delay_line_t *dl, const void *pkt, size_t len)
{
   dl_entry_t *e, *prev;
   struct timespec t;
   int delay;
   int became_head = 0;

   if (!dl)
      return -1;

   if (len > DL_MAX_PKT)
      len = DL_MAX_PKT;
   if (!(e = malloc(sizeof(*e) + len)))
      return -1;
   memcpy(e->pkt, pkt, len);
   e->len = len;
   e->next = NULL;

   /* per-packet delay with jitter — same formula as the old delay_handler */
   delay = dl->base_latency_ms;
   if (dl->jitter_ms)
      delay = (delay - dl->jitter_ms)
              + random() % ((delay + dl->jitter_ms + 1) - (delay - dl->jitter_ms));
   if (delay < 0)
      delay = 0;

   dl_now(dl->clock, &t);
   dl_add_ms(&t, delay);
   e->release = t;

   pthread_mutex_lock(&dl->lock);
   if (dl->stop) {
      pthread_mutex_unlock(&dl->lock);
      free(e);
      return -1;
   }
   if (dl->head == NULL || dl_le(&e->release, &dl->head->release)) {
      e->next = dl->head;
      dl->head = e;
      became_head = 1;
   } else {
      prev = dl->head;
      while (prev->next && !dl_le(&e->release, &prev->next->release))
         prev = prev->next;
      e->next = prev->next;
      prev->next = e;
   }
   pthread_mutex_unlock(&dl->lock);

   /* wake the release thread only when the earliest deadline moved up */
   if (became_head)
      pthread_cond_signal(&dl->cond);
   return 0;
}

void delay_line_destroy(delay_line_t *dl)
{
   dl_entry_t *e, *next;
   int oldstate;

   if (!dl)
      return;

   /* delay_line_destroy runs from a pthread cleanup handler when the recv
    * thread is canceled — keep cancellation off while we join our thread. */
   pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

   pthread_mutex_lock(&dl->lock);
   dl->stop = 1;
   pthread_cond_broadcast(&dl->cond);
   pthread_mutex_unlock(&dl->lock);

   pthread_join(dl->release_tid, NULL);

   pthread_setcancelstate(oldstate, NULL);

   /* drop anything still queued (link is going down) */
   e = dl->head;
   while (e) {
      next = e->next;
      free(e);
      e = next;
   }

   pthread_cond_destroy(&dl->cond);
   pthread_mutex_destroy(&dl->lock);
   free(dl);
}
