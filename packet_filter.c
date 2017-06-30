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
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <time.h>
#include "packet_filter.h"
#include "ubridge.h"


/* ======================================================================== */
/* Frequency Dropping                                                       */
/* ======================================================================== */

struct frequency_drop_data {
   int frequency;
   int current;
};

/* Setup filter */
static int frequency_drop_setup(void **opt, int argc, char *argv[])
{
   struct frequency_drop_data *data = *opt;

   if (argc != 1)
      return (-1);

   if (!data) {
      if (!(data = malloc(sizeof(*data))))
         return (-1);
      *opt = data;
   }

   data->current = 0;
   data->frequency = atoi(argv[0]);
   return (0);
}

/* Packet handler: drop 1 out of n packets */
static int frequency_drop_handler(void *pkt, size_t len, void *opt)
{
   struct frequency_drop_data *data = opt;

   if (data != NULL) {
      switch (data->frequency) {
         case -1:
            return (FILTER_ACTION_DROP);
         case 0:
            return (FILTER_ACTION_PASS);
         default:
            data->current++;
            if (data->current == data->frequency) {
               data->current = 0;
               return(FILTER_ACTION_DROP);
            }
      }
   }
   return (FILTER_ACTION_PASS);
}

/* Free resources used by filter */
static void frequency_drop_free(void **opt)
{
   if (*opt)
      free(*opt);
   *opt = NULL;
}

static void create_frequency_drop_filter(packet_filter_t *filter)
{
    filter->type = FILTER_TYPE_FREQUENCY_DROP;
    filter->setup = (void *)frequency_drop_setup;
    filter->handler = (void *)frequency_drop_handler;
    filter->free = (void *)frequency_drop_free;
}

/* ======================================================================== */
/* Latency                                                                  */
/* ======================================================================== */

struct latency_data {
   int ms;
};

/* Setup filter */
static int latency_setup(void **opt, int argc, char *argv[])
{
   struct latency_data *data = *opt;

   if (argc != 1)
      return (-1);

   if (!data) {
      if (!(data = malloc(sizeof(*data))))
         return (-1);
      *opt = data;
   }

   data->ms = atoi(argv[0]);
   return (0);
}

/* Packet handler: add latency */
static int latency_handler(void *pkt, size_t len, void *opt)
{
   struct latency_data *data = opt;
   struct timespec ts;

   if (data != NULL) {
      ts.tv_sec = data->ms / 1000;
      ts.tv_nsec = (data->ms % 1000) * 1000000;
      nanosleep(&ts, NULL);
   }
   return (FILTER_ACTION_PASS);
}

/* Free resources used by filter */
static void latency_free(void **opt)
{
   if (*opt)
      free(*opt);
   *opt = NULL;
}

static void create_latency_filter(packet_filter_t *filter)
{
    filter->type = FILTER_TYPE_LATENCY;
    filter->setup = (void *)latency_setup;
    filter->handler = (void *)latency_handler;
    filter->free = (void *)latency_free;
}

/* ======================================================================== */
/* Generic functions for filter management                                  */
/* ======================================================================== */


typedef struct {
     char *type;
     void (*func)(packet_filter_t *filter);
} filter_table_t;

static filter_table_t lookup_table[] = {
    { "frequency_drop", create_frequency_drop_filter },
    { "latency", create_latency_filter },
};

static int create_filter(packet_filter_t *filter, char *filter_type)
{
   for (filter_table_t *plookup = lookup_table;
   plookup != lookup_table + sizeof(lookup_table) / sizeof(lookup_table[0]);
   plookup++) {
       if (!strcmp(plookup->type, filter_type)) {
           (*plookup->func)(filter);
           return (TRUE);
       }
   }
   return (FALSE);
}

packet_filter_t *find_packet_filter(packet_filter_t *packet_filters, char *filter_name)
{
   packet_filter_t *filter;
   packet_filter_t *next;

   filter = packet_filters;
   while (filter != NULL) {
     if (!strcmp(filter->name, filter_name))
         return filter;
     next = filter->next;
     filter = next;
   }
   return (NULL);
}

int add_packet_filter(packet_filter_t **packet_filters, char *filter_name, char *filter_type, int argc, char *argv[])
{
   packet_filter_t *new_filter;
   void **opt;

   if (find_packet_filter(*packet_filters, filter_name) != NULL)
      return (-1);

   if ((new_filter = malloc(sizeof(*new_filter))) == NULL)
      return (-1);
   memset(new_filter, 0, sizeof(*new_filter));
   new_filter->name = strdup(filter_name);
   if ((new_filter->name = strdup(filter_name)) == NULL)
      return (-1);
   opt = &new_filter->data;
   new_filter->next = NULL;

   if ((create_filter(new_filter, filter_type)) == FALSE) {
      fprintf(stderr,"Filter type '%s' doesn't exist\n", filter_type);
      if (new_filter->name)
         free(new_filter->name);
      free(new_filter);
      return (-1);
   }

   if (*packet_filters == NULL) {
      *packet_filters = new_filter;
   }
   else {
      packet_filter_t *current = *packet_filters;
      while (current->next != NULL)
            current = current->next;
      current->next = new_filter;
   }

   return (new_filter->setup(opt, argc, argv));
}

void free_packet_filters(packet_filter_t *filter)
{
  packet_filter_t *next;

  while (filter != NULL) {
    if (filter->name)
       free(filter->name);
    next = filter->next;
    free(filter);
    filter = next;
  }
}

int delete_packet_filter(packet_filter_t **packet_filters, char *filter_name)
{
   packet_filter_t **head;
   packet_filter_t *filter;
   packet_filter_t *prev = NULL;

   head = packet_filters;
   for (filter = *head; filter != NULL; prev = filter, filter = filter->next) {
      if (!strcmp(filter->name, filter_name)) {
         if (prev == NULL)
            *head = filter->next;
         else
            prev->next = filter->next;
         if (filter->name)
            free(filter->name);
         filter->free(&filter->data);
         free(filter);
         return (0);
      }
   }
   return (-1);
}
