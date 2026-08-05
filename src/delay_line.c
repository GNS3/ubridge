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

/*
 * A user-space port of the Linux netem qdisc's delay path (net/sched/sch_netem.c):
 *
 *   - dl_tabledist()      ~ netem's tabledist()    — draw delay = latency +/- jitter
 *   - tfifo-style enqueue ~ netem's tfifo_enqueue() — time-ordered queue with an
 *                          O(1) tail fast path (packets normally arrive in order)
 *                          and a sorted-insert fallback for jitter reordering
 *   - release thread      ~ netem's qdisc watchdog  — wakes at the head's
 *                          time_to_send and sends everything already due
 *
 * Two things differ from in-kernel netem, both forced by ubridge being
 * user-space and filter-driven:
 *   - the watchdog is a pthread + cond_timedwait (no kernel qdisc scheduler);
 *   - the queue is depth-bounded with tail-drop, default 1000 packets
 *     (NETEM_LIMIT_DEFAULT), overridable via UBRIDGE_DELAY_LIMIT.
 *
 * One delay_line serves one direction of one bridge (created and destroyed
 * inside a single bridge_nios() call): single-producer (the recv thread) /
 * single-consumer (the release thread).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <pthread.h>

#include "delay_line.h"

#define DL_MAX_PKT 65535   /* matches NIO_MAX_PKT_SIZE */

/* Maximum packets buffered per direction before tail-drop. Mirrors the kernel
 * netem default (NETEM_LIMIT_DEFAULT = 1000) so the user-space delay line, like
 * netem, bounds memory and sheds excess load instead of buffering it without
 * limit. Every delivered packet transits this queue, so delivery is capped at
 * DL_LIMIT_DEFAULT packets under overload. */
#define DL_LIMIT_DEFAULT 1000

/* Gaussian (normal) jitter. table[i] = round(standard-normal quantile at
 * (i+0.5)/DL_DIST_SIZE) * DL_DIST_SCALE, so a uniform index lookup scaled by
 * sigma/DL_DIST_SCALE yields a normal sample with std ~sigma — the same idea
 * as the distribution table tc passes to kernel netem for `distribution normal`
 * (net/sched/sch_netem.c tabledist(), the dist!=NULL path). Generated once. */
#define DL_DIST_SIZE  1024
#define DL_DIST_SCALE 4096

static int16_t g_dist_table[DL_DIST_SIZE];
static pthread_once_t g_dist_once = PTHREAD_ONCE_INIT;

/* One queued packet. The queue is kept ordered by time_to_send (earliest first),
 * with a tail pointer for netem's tfifo O(1) fast path. */
typedef struct dl_entry {
   struct timespec time_to_send;    /* absolute time the packet becomes due */
   size_t len;
   struct dl_entry *next;
   unsigned char pkt[];             /* flexible array member */
} dl_entry_t;

struct delay_line {
   int base_latency_ms;             /* mu  — netem latency */
   int jitter_ms;                   /* sigma — netem jitter */
   const int16_t *dist_table;       /* normal-distribution table (shared) */
   int dist_size;
   delay_send_fn send_fn;
   void *send_ctx;
   clockid_t clock;                 /* clock used for time_to_send + cond */
   pthread_mutex_t lock;
   pthread_cond_t cond;             /* signaled when head changes or on stop */
   dl_entry_t *head;                /* earliest time_to_send, or NULL */
   dl_entry_t *tail;                /* latest time_to_send, or NULL (tfifo) */
   int count;                       /* packets currently queued */
   int limit;                       /* max queued before tail-drop (netem-like) */
   int stop;                        /* set by delay_line_destroy */
   pthread_t release_tid;
};

/* now -> *ts on the delay line's clock */
static void dl_now(clockid_t clock, struct timespec *ts)
{
   clock_gettime(clock, ts);
}

/* *ts += ms */
static void dl_add_ms(struct timespec *ts, long ms)
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

/* a < b ? (used by the tfifo tail fast path) */
static int dl_lt(const struct timespec *a, const struct timespec *b)
{
   if (a->tv_sec != b->tv_sec)
      return a->tv_sec < b->tv_sec;
   return a->tv_nsec < b->tv_nsec;
}

/* a <= b ? (used by the sorted-insert fallback and the due-time check) */
static int dl_le(const struct timespec *a, const struct timespec *b)
{
   if (a->tv_sec != b->tv_sec)
      return a->tv_sec < b->tv_sec;
   return a->tv_nsec <= b->tv_nsec;
}

/* Peter Acklam's rational approximation of the standard-normal quantile
 * (inverse CDF); accurate to ~1e-9 across (0,1). */
static double dl_norm_quantile(double p)
{
   static const double a[] = { -3.969683028665376e+01, 2.209460984245205e+02,
      -2.759285104469687e+02, 1.383577518672690e+02, -3.066479806614716e+01,
      2.506628277459239e+00 };
   static const double b[] = { -5.447609879822406e+01, 1.615858368580409e+02,
      -1.556989798598866e+02, 6.680131188771972e+01, -1.328068155288572e+01 };
   static const double c[] = { -7.784894002430293e-03, -3.223964580411365e-01,
      -2.400758277161838e+00, -2.549732539343734e+00, 4.374664141464968e+00,
      2.938163982698783e+00 };
   static const double d[] = { 7.784695709041462e-03, 3.224671290700398e-01,
      2.445134137142996e+00, 3.754408661907416e+00 };
   const double plow = 0.02425, phigh = 1.0 - plow;
   double q, r;

   if (p < plow) {
      q = sqrt(-2.0 * log(p));
      return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) /
             ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1.0);
   } else if (p <= phigh) {
      q = p - 0.5;
      r = q*q;
      return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q /
             (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1.0);
   } else {
      q = sqrt(-2.0 * log(1.0 - p));
      return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) /
              ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1.0);
   }
}

/* Fill the shared normal-distribution table once (inverse-CDF sampling). */
static void dl_init_dist(void)
{
   int i;
   for (i = 0; i < DL_DIST_SIZE; i++) {
      double q = dl_norm_quantile((i + 0.5) / (double)DL_DIST_SIZE);
      long v = (long)(q * DL_DIST_SCALE + (q >= 0 ? 0.5 : -0.5));  /* round */
      if (v > 32767) v = 32767;
      if (v < -32768) v = -32768;
      g_dist_table[i] = (int16_t)v;
   }
}

/* tabledist — netem's delay+jitter draw. With a distribution table (the default
 * here) it is Gaussian (normal), matching `tc netem delay Xms Yms`; without one
 * it falls back to kernel netem's uniform [mu-sigma, mu+sigma] (dist==NULL). */
static long dl_tabledist(long mu, long sigma, const int16_t *dist, int dist_size)
{
   if (sigma == 0)
      return mu;
   if (dist != NULL && dist_size > 0) {
      /* (table[idx]/scale) is a standard-normal sample, so sigma*that has
       * std ~sigma and the result is N(mu, sigma^2). */
      long t = dist[(unsigned)random() % dist_size];
      return mu + (sigma * t) / DL_DIST_SCALE;
   }
   return (long)(random() % (2 * (unsigned long)sigma)) + mu - sigma;
}

/* Release thread (netem's watchdog): send packets as their time_to_send
 * arrives, in order. */
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
      if (dl_le(&dl->head->time_to_send, &now)) {
         /* due now: pop and send outside the lock so enqueue can proceed */
         e = dl->head;
         dl->head = e->next;
         if (dl->head == NULL)
            dl->tail = NULL;
         dl->count--;
         pthread_mutex_unlock(&dl->lock);
         dl->send_fn(dl->send_ctx, e->pkt, e->len);
         free(e);
         pthread_mutex_lock(&dl->lock);
         continue;
      }
      /* wait until the head is due; an earlier head inserted meanwhile
       * signals the cond so we re-evaluate. */
      pthread_cond_timedwait(&dl->cond, &dl->lock, &dl->head->time_to_send);
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
   pthread_once(&g_dist_once, dl_init_dist);
   dl->dist_table = g_dist_table;
   dl->dist_size = DL_DIST_SIZE;
   dl->send_fn = send_fn;
   dl->send_ctx = send_ctx;
   dl->head = dl->tail = NULL;
   dl->count = 0;
   dl->limit = DL_LIMIT_DEFAULT;

   /* Optional override (UBRIDGE_DELAY_LIMIT packets). Mirrors netem's
    * configurable limit without needing a protocol/filter-arg change. */
   {
      const char *s = getenv("UBRIDGE_DELAY_LIMIT");
      if (s != NULL) {
         long v = strtol(s, NULL, 10);
         if (v > 0)
            dl->limit = (int)v;
      }
   }

   dl->stop = 0;

   pthread_mutex_init(&dl->lock, NULL);

   /* Use CLOCK_MONOTONIC so wall-clock jumps (NTP, settimeofday) can't
    * stretch or shrink the delay. */
   dl->clock = CLOCK_MONOTONIC;
   pthread_condattr_init(&attr);
   pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
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
   long delay;
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

   /* time_to_send = now + tabledist(latency, jitter) — netem's enqueue */
   delay = dl_tabledist(dl->base_latency_ms, dl->jitter_ms, dl->dist_table, dl->dist_size);
   if (delay < 0)
      delay = 0;
   dl_now(dl->clock, &t);
   dl_add_ms(&t, (int)delay);
   e->time_to_send = t;

   pthread_mutex_lock(&dl->lock);
   if (dl->stop) {
      pthread_mutex_unlock(&dl->lock);
      free(e);
      return -1;
   }
   if (dl->count >= dl->limit) {
      /* queue full: tail-drop the newest packet so excess load is shed (like
       * netem's limit) instead of buffering it without bound. */
      pthread_mutex_unlock(&dl->lock);
      free(e);
      return -1;
   }

   /* tfifo-style insert: O(1) tail append when in time order (the common case
    * with constant delay), sorted insert from the head on jitter reordering. */
   if (dl->tail == NULL || !dl_lt(&e->time_to_send, &dl->tail->time_to_send)) {
      e->next = NULL;
      if (dl->tail)
         dl->tail->next = e;
      else
         dl->head = e;
      dl->tail = e;
      became_head = (dl->head == e);   /* only the first packet wakes the thread */
   } else {
      if (dl_le(&e->time_to_send, &dl->head->time_to_send)) {
         e->next = dl->head;
         dl->head = e;
         became_head = 1;
      } else {
         prev = dl->head;
         while (prev->next && !dl_le(&e->time_to_send, &prev->next->time_to_send))
            prev = prev->next;
         e->next = prev->next;
         prev->next = e;
      }
   }
   dl->count++;
   pthread_mutex_unlock(&dl->lock);

   /* wake the release thread only when the earliest deadline moved up */
   if (became_head)
      pthread_cond_signal(&dl->cond);
   return 0;
}

int delay_line_config(delay_line_t *dl, int *latency_ms, int *jitter_ms)
{
   if (dl == NULL)
      return 0;
   *latency_ms = dl->base_latency_ms;
   *jitter_ms = dl->jitter_ms;
   return 1;
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
