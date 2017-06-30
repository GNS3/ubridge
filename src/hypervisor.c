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

/* Hypervisor code mostly borrowed from Dynamips. */

#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>

#include "hypervisor.h"
#include "hypervisor_parser.h"
#include "hypervisor_bridge.h"
#ifdef __linux__
#include "hypervisor_docker.h"
#include "hypervisor_iol_bridge.h"
#include "hypervisor_brctl.h"
#endif
#include "ubridge.h"

static hypervisor_module_t *module_list = NULL;
static volatile int hypervisor_running = 0;

/* Hypervisor connection list */
static hypervisor_conn_t *hypervisor_conn_list = NULL;

/* Listen on the specified port */
static int ip_listen(char *ip_addr, int port, int sock_type, int max_fd, int fd_array[])
{
   struct addrinfo hints, *res, *res0;
   char port_str[20], *addr;
   int nsock, error, i;
   int reuse = 1;

   for(i = 0; i < max_fd; i++)
      fd_array[i] = -1;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = PF_UNSPEC;
   hints.ai_socktype = sock_type;
   hints.ai_flags = AI_PASSIVE;

   snprintf(port_str, sizeof(port_str), "%d", port);
   addr = (ip_addr && strlen(ip_addr)) ? ip_addr : NULL;

   if ((error = getaddrinfo(addr, port_str, &hints, &res0)) != 0) {
      fprintf(stderr, "ip_listen: %s", gai_strerror(error));
      return(-1);
   }

   nsock = 0;
   for(res = res0; (res && (nsock < max_fd)); res = res->ai_next)
   {
      if ((res->ai_family != PF_INET) && (res->ai_family != PF_INET6))
         continue;

      fd_array[nsock] = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

      if (fd_array[nsock] < 0)
         continue;

      setsockopt(fd_array[nsock], SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

      if ((bind(fd_array[nsock], res->ai_addr, res->ai_addrlen) < 0) ||
          ((sock_type == SOCK_STREAM) && (listen(fd_array[nsock],5) < 0)))
      {
         close(fd_array[nsock]);
         fd_array[nsock] = -1;
         continue;
      }

      nsock++;
   }
   freeaddrinfo(res0);
   return(nsock);
}

/* Send a reply */
int hypervisor_send_reply(hypervisor_conn_t *conn, int code, int done, char *format,...)
{
   va_list ap;
   size_t n = 0;

   if (conn != NULL) {
      va_start(ap,format);
      n += fprintf(conn->out,"%3d%s",code,(done)?"-":" ");
      n += vfprintf(conn->out,format,ap);
      n += fprintf(conn->out,"\r\n");
      fflush(conn->out);
      va_end(ap);
   }
   return(n);
}

/* Find a module */
static hypervisor_module_t *hypervisor_find_module(char *name)
{
   hypervisor_module_t *m;

   for(m = module_list; m; m = m->next)
      if (!strcmp(m->name, name))
         return m;
   return NULL;
}

/* Find a command in a module */
static hypervisor_cmd_t *hypervisor_find_cmd(hypervisor_module_t *module, char *name)
{
   hypervisor_cmd_t *cmd;

   for(cmd = module->cmd_list; cmd; cmd = cmd->next)
      if (!strcmp(cmd->name, name))
         return cmd;
   return NULL;
}


/* Show hypervisor version */
static int cmd_version(hypervisor_conn_t *conn, int argc, char *argv[])
{
   hypervisor_send_reply(conn,HSC_INFO_OK,1, "%s", VERSION);
   return (0);
}


/* Show hypervisor module list */
static int cmd_mod_list(hypervisor_conn_t *conn, int argc, char *argv[])
{
   hypervisor_module_t *m;

   for(m = module_list; m; m = m->next)
      hypervisor_send_reply(conn, HSC_INFO_MSG, 0, "%s", m->name);

   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "OK");
   return (0);
}

/* Show module command list */
static int cmd_modcmd_list(hypervisor_conn_t *conn, int argc, char *argv[])
{
   hypervisor_module_t *m;
   hypervisor_cmd_t *cmd;

   if (!(m = hypervisor_find_module(argv[0]))) {
      hypervisor_send_reply(conn, HSC_ERR_UNK_MODULE, 1, "unknown module '%s'", argv[0]);
      return (-1);
   }

   for(cmd = m->cmd_list; cmd; cmd = cmd->next)
      hypervisor_send_reply(conn, HSC_INFO_MSG, 0, "%s (min/max args: %d/%d)", cmd->name, cmd->min_param, cmd->max_param);

   hypervisor_send_reply(conn,  HSC_INFO_OK, 1, "OK");
   return (0);
}


/* Reset hypervisor (delete all objects) */
static int cmd_reset(hypervisor_conn_t *conn, int argc, char *argv[])
{
   ubridge_reset();
   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "OK");
   return (0);
}


/* Close connection */
static int cmd_close(hypervisor_conn_t *conn, int argc, char *argv[])
{
   hypervisor_send_reply(conn, HSC_INFO_OK, 1, "OK");
   conn->active = FALSE;
   return (0);
}

/* Stop hypervisor */
static int cmd_stop(hypervisor_conn_t *conn,int argc,char *argv[])
{
   hypervisor_send_reply(conn,HSC_INFO_OK, 1, "OK");
   hypervisor_running = FALSE;
   return (0);
}

/* Hypervisor commands */
static hypervisor_cmd_t hypervisor_cmd_array[] = {
   { "version", 0, 0, cmd_version, NULL },
   { "module_list", 0, 0, cmd_mod_list, NULL },
   { "cmd_list", 1, 1, cmd_modcmd_list, NULL },
   { "reset", 0, 0, cmd_reset, NULL },
   { "close", 0, 0, cmd_close, NULL },
   { "stop", 0, 0, cmd_stop, NULL },
   { NULL, -1, -1, NULL, NULL },
};

/* Destroy module_list */
static void destroy_module_list(void)
{
   hypervisor_module_t *m, *next;

   for (m = module_list; m; m = next) {
      next = m->next;
      free(m);
   }
   module_list = NULL;
}

/* Register a module */
hypervisor_module_t *hypervisor_register_module(char *name, void *opt)
{
   hypervisor_module_t *m;

   if (hypervisor_find_module(name) != NULL) {
      fprintf(stderr, "Hypervisor: module '%s' already exists.\n", name);
      return NULL;
   }

   if (!(m = malloc(sizeof(*m)))) {
      fprintf(stderr, "Hypervisor: unable to register new module.\n");
      return NULL;
   }

   if (!module_list)
      atexit(destroy_module_list);

   m->name = name;
   m->opt  = opt;
   m->cmd_list = NULL;

   m->next = module_list;
   module_list = m;
   return m;
}

/* Register a list of commands */
int hypervisor_register_cmd_list(hypervisor_module_t *module, hypervisor_cmd_t *cmd_list)
{
   hypervisor_cmd_t *cmd = cmd_list;

   while(cmd->next != NULL)
      cmd = cmd->next;

   cmd->next = module->cmd_list;
   module->cmd_list = cmd_list;
   return(0);
}

/* Register an array of commands */
int hypervisor_register_cmd_array(hypervisor_module_t *module, hypervisor_cmd_t *cmd_array)
{
   hypervisor_cmd_t *cmd;

   for(cmd = cmd_array; cmd->name!=NULL; cmd++) {
      cmd->next = module->cmd_list;
      module->cmd_list = cmd;
   }
   return(0);
}

/* Locate the module and execute command */
static int hypervisor_exec_cmd(hypervisor_conn_t *conn, char *mod_name, char *cmd_name, int argc, char *argv[])
{
   hypervisor_module_t *module;
   hypervisor_cmd_t *cmd;

   if (!(module = hypervisor_find_module(mod_name))) {
      hypervisor_send_reply(conn, HSC_ERR_UNK_MODULE, 1, "Unknown module '%s'", mod_name);
      return(-1);
   }

   if (!(cmd = hypervisor_find_cmd(module,cmd_name))) {
      hypervisor_send_reply(conn, HSC_ERR_UNK_CMD, 1, "Unknown command '%s'", cmd_name);
      return(-1);
   }

   if ((argc < cmd->min_param) || (argc > cmd->max_param))  {
      hypervisor_send_reply(conn, HSC_ERR_BAD_PARAM, 1, "Bad number of parameters (%d with min/max=%d/%d)",
                            argc, cmd->min_param, cmd->max_param);
      return(-1);
   }

   conn->cur_module = module;
   return(cmd->handler(conn, argc, argv));
}

/* Thread for servicing connections */
static void *hypervisor_thread(void *arg)
{
   hypervisor_conn_t  *conn = arg;
   char buffer[512], **tokens;
   parser_context_t ctx;
   int res;

   tokens = NULL;
   parser_context_init(&ctx);

   while(conn->active) {
      if (!fgets(buffer, sizeof(buffer), conn->in))
         break;

      if (!*buffer)
         continue;

      /* Tokenize command line */
      res = parser_scan_buffer(&ctx, buffer, strlen(buffer));

      if (res != 0) {
         tokens = NULL;

         if (ctx.error != 0) {
            hypervisor_send_reply(conn, HSC_ERR_PARSING, 1, "Parse error: %s", parser_strerror(&ctx));
            goto free_tokens;
         }

         if (ctx.tok_count < 2) {
            hypervisor_send_reply(conn,HSC_ERR_PARSING,1, "At least a module and a command must be specified");
            goto free_tokens;
         }

         /* Map token list to an array */
         tokens = parser_map_array(&ctx);

         if (!tokens) {
            hypervisor_send_reply(conn, HSC_ERR_PARSING, 1, "No memory");
            goto free_tokens;
         }

         /* Execute command */
         pthread_mutex_lock(&global_lock);
         hypervisor_exec_cmd(conn, tokens[0], tokens[1], ctx.tok_count - 2, &tokens[2]);
         pthread_mutex_unlock(&global_lock);

      free_tokens:
         free(tokens);
         tokens = NULL;
         parser_context_free(&ctx);
      }
   }

   free(tokens);
   parser_context_free(&ctx);
   return NULL;
}

/* Initialize hypervisor */
int hypervisor_init(void)
{
   hypervisor_module_t *module;

   module = hypervisor_register_module("hypervisor", NULL);
   assert(module != NULL);

   hypervisor_register_cmd_array(module, hypervisor_cmd_array);
   return(0);
}

/* Remove a connection from the list */
static void hypervisor_remove_conn(hypervisor_conn_t *conn)
{
   if (conn->pprev != NULL) {
      if (conn->next)
         conn->next->pprev = conn->pprev;
      *(conn->pprev) = conn->next;
   }
}

/* Close a connection */
static void hypervisor_close_conn(hypervisor_conn_t *conn)
{
   if (conn != NULL) {
      conn->active = FALSE;
      shutdown(conn->client_fd,2);
      pthread_join(conn->tid,NULL);

      fclose(conn->in);
      fclose(conn->out);

      shutdown(conn->client_fd,2);
      close(conn->client_fd);

      hypervisor_remove_conn(conn);
      free(conn);
   }
}

/* Close connections (dead or all) */
static void hypervisor_close_conn_list(int dead_status)
{
   hypervisor_conn_t *conn,*next;

   for(conn = hypervisor_conn_list; conn; conn=next) {
      next = conn->next;

      if (dead_status && conn->active)
         continue;

      hypervisor_close_conn(conn);
   }
}

/* Add a new connection to the list */
static void hypervisor_add_conn(hypervisor_conn_t *conn)
{
   conn->next = hypervisor_conn_list;
   conn->pprev = &hypervisor_conn_list;

   if (hypervisor_conn_list != NULL)
      hypervisor_conn_list->pprev = &conn->next;

   hypervisor_conn_list = conn;
}

/* Create a new connection */
static hypervisor_conn_t *hypervisor_create_conn(int client_fd)
{
   hypervisor_conn_t *conn;

   if (!(conn = malloc(sizeof(*conn))))
      goto err_malloc;

   memset(conn,0,sizeof(*conn));
   conn->active = TRUE;
   conn->client_fd = client_fd;

   /* Open input buffered stream */
   if (!(conn->in = fdopen(client_fd, "r"))) {
      perror("hypervisor_create_conn: fdopen/in");
      goto err_fd_in;
   }

   /* Open output buffered stream */
   if (!(conn->out = fdopen(client_fd, "w"))) {
      perror("hypervisor_create_conn: fdopen/out");
      goto err_fd_out;
   }

   /* Set line buffering */
   setlinebuf(conn->in);
   setlinebuf(conn->out);

   /* Create the managing thread */
   if (pthread_create(&conn->tid, NULL, hypervisor_thread, conn) != 0)
      goto err_thread;

   /* Add it to the connection list */
   hypervisor_add_conn(conn);
   return conn;

 err_thread:
   fclose(conn->out);
 err_fd_out:
   fclose(conn->in);
 err_fd_in:
   free(conn);
 err_malloc:
   return NULL;
}

/* Stop hypervisor from sighandler */
int hypervisor_stopsig(void)
{
   hypervisor_running = FALSE;
   return(0);
}

int run_hypervisor(char *ip_addr, int tcp_port)
{
   int fd_array[HYPERVISOR_MAX_FD];
   struct sockaddr_storage remote_addr;
   socklen_t remote_len;
   struct timeval tv;
   int i,res,clnt,fd_count,fd_max;
   fd_set fds;

   hypervisor_init();
   hypervisor_bridge_init();
#ifdef __linux__
   hypervisor_docker_init();
   hypervisor_iol_bridge_init();
   hypervisor_brctl_init();
#endif

   signal(SIGPIPE, SIG_IGN);

   if (!tcp_port)
      tcp_port = HYPERVISOR_TCP_PORT;

   fd_count = ip_listen(ip_addr, tcp_port, SOCK_STREAM, HYPERVISOR_MAX_FD, fd_array);

   if (fd_count <= 0) {
      fprintf(stderr,"Hypervisor: unable to create TCP sockets.\n");
      return (-1);
   }

   if (ip_addr != NULL)
       printf("Hypervisor TCP control server started (IP %s port %d).\n", ip_addr, tcp_port);
   else
       printf("Hypervisor TCP control server started (port %d).\n", tcp_port);

   hypervisor_running = TRUE;
   while (hypervisor_running) {

      FD_ZERO(&fds);
      fd_max = -1;

      for(i = 0; i < fd_count; i++)
         if (fd_array[i] != -1) {
            FD_SET(fd_array[i],&fds);
            if (fd_array[i] > fd_max)
               fd_max = fd_array[i];
         }

      /* Wait for incoming connections */
      tv.tv_sec  = 0;
      tv.tv_usec = 500 * 1000;  /* 500 ms */
      res = select(fd_max + 1, &fds, NULL, NULL, &tv);

      if (res == -1) {
         if (errno == EINTR)
            continue;
         else
            perror("hypervisor_tcp_server: select");
      }

      /* Accept connections on signaled sockets */
      for(i = 0; i < fd_count; i++) {
         if (fd_array[i] == -1)
            continue;

         if (!FD_ISSET(fd_array[i], &fds))
            continue;

         remote_len = sizeof(remote_addr);
         clnt = accept(fd_array[i], (struct sockaddr *)&remote_addr, &remote_len);

         if (clnt < 0) {
            perror("hypervisor_tcp_server: accept");
            continue;
         }

         /* create a new connection and start a thread to handle it */
         if (!hypervisor_create_conn(clnt)) {
            fprintf(stderr, "hypervisor_tcp_server: unable to create new connection for FD %d\n", clnt);
            close(clnt);
         }
      }

      /* Walk through the connection list to eliminate dead connections */
      hypervisor_close_conn_list(TRUE);
   }

   /* Close all control sockets */
   printf("Hypervisor: closing control sockets.\n");
   for (i=0; i < fd_count; i++) {
      if (fd_array[i] != -1) {
         shutdown(fd_array[i],2);
         close(fd_array[i]);
      }
   }

   /* Close all remote client connections */
   printf("Hypervisor: closing remote client connections.\n");
   hypervisor_close_conn_list(FALSE);
   printf("Hypervisor: stopped.\n");
   return (0);
}
