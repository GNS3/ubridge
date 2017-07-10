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
#include <pcap.h>
#include "packet_filter.h"
#include "pcap_filter.h"
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
      memset(data, 0, sizeof(*data));
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
               return (FILTER_ACTION_DROP);
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
/* Packet Loss                                                              */
/* ======================================================================== */

struct packet_loss_data {
   int percentage;
};

/* Setup filter */
static int packet_loss_setup(void **opt, int argc, char *argv[])
{
   struct packet_loss_data *data = *opt;

   if (argc != 1)
      return (-1);

   if (!data) {
      if (!(data = malloc(sizeof(*data))))
         return (-1);
      memset(data, 0, sizeof(*data));
      *opt = data;
   }

   data->percentage = atoi(argv[0]);
   if (data->percentage < 0 || data->percentage > 100)
      return (-1);

   return (0);
}

/* Packet handler: randomly drop packet */
static int packet_loss_handler(void *pkt, size_t len, void *opt)
{
   struct packet_loss_data *data = opt;

   if (data != NULL) {
      if (random() % 100 <= data->percentage)
         return (FILTER_ACTION_DROP);
   }
   return (FILTER_ACTION_PASS);
}

/* Free resources used by filter */
static void packet_loss_free(void **opt)
{
   if (*opt)
      free(*opt);
   *opt = NULL;
}

static void create_packet_loss_filter(packet_filter_t *filter)
{
    filter->type = FILTER_TYPE_PACKET_LOSS;
    filter->setup = (void *)packet_loss_setup;
    filter->handler = (void *)packet_loss_handler;
    filter->free = (void *)packet_loss_free;
}

/* ======================================================================== */
/* Delay                                                                    */
/* ======================================================================== */

struct delay_data {
   int latency;
   int jitter;
};

/* Setup filter */
static int delay_setup(void **opt, int argc, char *argv[])
{
   struct delay_data *data = *opt;

   if (argc != 1 && argc != 2)
      return (-1);

   if (!data) {
      if (!(data = malloc(sizeof(*data))))
         return (-1);
      memset(data, 0, sizeof(*data));
      *opt = data;
   }

   data->latency = atoi(argv[0]);
   data->jitter = 0;
   if (argc == 2)
      data->jitter = atoi(argv[1]);
   if (data->latency <= 0 || data->jitter < 0)
      return (-1);
   return (0);
}

/* Packet handler: add delay (latency and optionally jitter) */
static int delay_handler(void *pkt, size_t len, void *opt)
{
   struct delay_data *data = opt;
   struct timespec ts;
   int delay;

   if (data != NULL) {
      delay = data->latency;
      if (data->jitter)
         delay = (delay - data->jitter) + random() % ((delay + data->jitter + 1) - (delay - data->jitter));
      if (delay < 0)
          delay = 0;
      ts.tv_sec = delay / 1000;
      ts.tv_nsec = (delay % 1000) * 1000000;
      nanosleep(&ts, NULL);
   }
   return (FILTER_ACTION_PASS);
}

/* Free resources used by filter */
static void delay_free(void **opt)
{
   if (*opt)
      free(*opt);
   *opt = NULL;
}

static void create_delay_filter(packet_filter_t *filter)
{
    filter->type = FILTER_TYPE_DELAY;
    filter->setup = (void *)delay_setup;
    filter->handler = (void *)delay_handler;
    filter->free = (void *)delay_free;
}

/* ======================================================================== */
/* Corrupt                                                                  */
/* ======================================================================== */

struct corrupt_data {
   int percentage;
   int index;
};

static char patterns[] = {
   0x64,
   0x13,
   0x88,
   0x40,
   0x1F,
   0xA0,
   0xAA,
   0x55
};

/* Setup filter */
static int corrupt_setup(void **opt, int argc, char *argv[])
{
   struct corrupt_data *data = *opt;

   if (argc != 1)
      return (-1);

   if (!data) {
      if (!(data = malloc(sizeof(*data))))
         return (-1);
      memset(data, 0, sizeof(*data));
      *opt = data;
   }

   data->percentage = atoi(argv[0]);
   data->index = 0;
   if (data->percentage < 0 || data->percentage > 100)
      return (-1);
   return (0);
}

static void corrupt_packet(char *pkt, size_t len, void *opt)
{
   struct corrupt_data *data = opt;
   int i;

   for (i = 0; i < len; ++i) {
       pkt[i] ^= patterns[data->index++ & 0x7];
   }
}

/* Packet handler: randomly corrupt packets */
static int corrupt_handler(void *pkt, size_t len, void *opt)
{
   struct corrupt_data *data = opt;
   int length;

   if (data != NULL && random() % 100 <= data->percentage) {
      length = len / 4;
      corrupt_packet(pkt + len / 2 - length / 2 + 1, length, opt);
   }
   return (FILTER_ACTION_PASS);
}

/* Free resources used by filter */
static void corrupt_free(void **opt)
{
   if (*opt)
      free(*opt);
   *opt = NULL;
}

static void create_corrupt_filter(packet_filter_t *filter)
{
    filter->type = FILTER_TYPE_CORRUPT;
    filter->setup = (void *)corrupt_setup;
    filter->handler = (void *)corrupt_handler;
    filter->free = (void *)corrupt_free;
}

/* ======================================================================== */
/* BPF                                                                      */
/* ======================================================================== */

struct bpf_data {
   struct bpf_program fp;
};

/* Setup filter */
static int bpf_setup(void **opt, int argc, char *argv[])
{
   struct bpf_data *data = *opt;
   int link_type;
   pcap_t *pcap_dev;
   char *filter;

   if (argc != 1 && argc != 2)
      return (-1);

   if (!data) {
      if (!(data = malloc(sizeof(*data))))
         return (-1);
      memset(data, 0, sizeof(*data));
      *opt = data;
   }

   filter = argv[0];
   link_type = DLT_EN10MB;
   if (argc == 2)
      if ((link_type = pcap_datalink_name_to_val(argv[1])) == -1) {
         fprintf(stderr,"Unknown link type %s\n", argv[1]);
         return (-1);
      }
   pcap_dev = pcap_open_dead(link_type, 65535);
   if (pcap_compile(pcap_dev, &data->fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
       fprintf(stderr, "Cannot compile filter '%s': %s\n", filter, pcap_geterr(pcap_dev));
       return (-1);
   }
   pcap_close(pcap_dev);
   return (0);
}

/* Packet handler: apply BPF filter */
static int bpf_handler(void *pkt, size_t len, void *opt)
{
   struct bpf_data *data = opt;
   struct pcap_pkthdr pkthdr;

   memset(&pkthdr, 0, sizeof(pkthdr));
   pkthdr.caplen = len;
   pkthdr.len = len;
   if (data != NULL) {
       if (pcap_offline_filter(&data->fp, &pkthdr, pkt))
         return (FILTER_ACTION_DROP);
   }
   return (FILTER_ACTION_PASS);
}

/* Free resources used by filter */
static void bpf_free(void **opt)
{
   if (*opt)
      free(*opt);
   *opt = NULL;
}

static void create_bpf_filter(packet_filter_t *filter)
{
    filter->type = FILTER_TYPE_BPF;
    filter->setup = (void *)bpf_setup;
    filter->handler = (void *)bpf_handler;
    filter->free = (void *)bpf_free;
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
    { "packet_loss", create_packet_loss_filter },
    { "delay", create_delay_filter },
    { "corrupt", create_corrupt_filter },
    { "bpf", create_bpf_filter},
};

static int create_filter(packet_filter_t *filter, char *filter_type)
{
   filter_table_t *plookup;

   for (plookup = lookup_table; plookup != lookup_table + sizeof(lookup_table) / sizeof(lookup_table[0]); plookup++) {
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
