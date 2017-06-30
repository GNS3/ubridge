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

#ifndef HYPERVISOR_H_
#define HYPERVISOR_H_

/* Default TCP port */
#define HYPERVISOR_TCP_PORT 4242

/* Maximum listening socket number */
#define HYPERVISOR_MAX_FD   10

/* Maximum tokens per line */
#define HYPERVISOR_MAX_TOKENS  16

/* Hypervisor status codes */
#define HSC_INFO_OK         100  /* ok */
#define HSC_INFO_MSG        101  /* informative message */
#define HSC_INFO_DEBUG      102  /* debugging message */
#define HSC_ERR_PARSING     200  /* parse error */
#define HSC_ERR_UNK_MODULE  201  /* unknown module */
#define HSC_ERR_UNK_CMD     202  /* unknown command */
#define HSC_ERR_BAD_PARAM   203  /* bad number of parameters */
#define HSC_ERR_INV_PARAM   204  /* invalid parameter */
#define HSC_ERR_BINDING     205  /* binding error */
#define HSC_ERR_CREATE      206  /* unable to create object */
#define HSC_ERR_DELETE      207  /* unable to delete object */
#define HSC_ERR_UNK_OBJ     208  /* unknown object */
#define HSC_ERR_START       209  /* unable to start object */
#define HSC_ERR_STOP        210  /* unable to stop object */
#define HSC_ERR_FILE        211  /* file error */
#define HSC_ERR_BAD_OBJ     212  /* Bad object */
#define HSC_ERR_RENAME      213  /* unable to rename object */
#define HSC_ERR_NOT_FOUND   214  /* not found (generic) */
#define HSC_ERR_UNSPECIFIED 215  /* unspecified error (generic) */

/* By default, Cygwin supports only 64 FDs with select()! */
#if defined(CYGWIN) && !defined(FD_SETSIZE)
  #define FD_SETSIZE 1024
#endif

typedef struct hypervisor_conn hypervisor_conn_t;
typedef struct hypervisor_cmd hypervisor_cmd_t;
typedef struct hypervisor_module hypervisor_module_t;

/* Hypervisor connection */
struct hypervisor_conn {
   pthread_t tid;                    /* Thread identifier */
   volatile int active;              /* Connection is active ? */
   int client_fd;                    /* Client FD */
   FILE *in,*out;                    /* I/O buffered streams */
   hypervisor_module_t *cur_module;  /* Module of current command */
   hypervisor_conn_t *next,**pprev;
};

/* Hypervisor command handler */
typedef int (*hypervisor_cmd_handler)(hypervisor_conn_t *conn, int argc, char *argv[]);

/* Hypervisor command */
struct hypervisor_cmd {
   char *name;
   int min_param,max_param;
   hypervisor_cmd_handler handler;
   hypervisor_cmd_t *next;
};

/* Hypervisor module */
struct hypervisor_module {
   char *name;
   void *opt;
   hypervisor_cmd_t *cmd_list;
   hypervisor_module_t *next;
};

int hypervisor_stopsig(void);
hypervisor_module_t *hypervisor_register_module(char *name, void *opt);
int hypervisor_register_cmd_list(hypervisor_module_t *module, hypervisor_cmd_t *cmd_list);
int hypervisor_send_reply(hypervisor_conn_t *conn, int code, int done, char *format,...);
int hypervisor_register_cmd_array(hypervisor_module_t *module, hypervisor_cmd_t *cmd_array);
int run_hypervisor(char *ip_addr, int tcp_port);

#endif /* !HYPERVISOR_H_ */
