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

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include <string.h>
#include <sys/socket.h>
#include <netdb.h>

#include "ubridge.h"

foreign_port_t *port_table = NULL;

int udp_connect(int local_port,char *remote_host,int remote_port)
{
   struct addrinfo hints,*res,*res0;
   struct sockaddr_storage st;
   int error, sck = -1;
   char port_str[20];

   memset(&hints,0,sizeof(hints));
   hints.ai_family = PF_UNSPEC;
   hints.ai_socktype = SOCK_DGRAM;

   snprintf(port_str,sizeof(port_str),"%d",remote_port);

   if ((error = getaddrinfo(remote_host,port_str,&hints,&res0)) != 0) {
      fprintf(stderr,"%s\n",gai_strerror(error));
      return(-1);
   }

   for(res = res0; res; res = res->ai_next)
   {
      /* We want only IPv4 or IPv6 */
      if ((res->ai_family != PF_INET) && (res->ai_family != PF_INET6))
         continue;

      /* create new socket */
      if ((sck = socket(res->ai_family,SOCK_DGRAM,res->ai_protocol)) < 0) {
         perror("udp_connect: socket");
         continue;
      }

      /* bind to the local port */
      memset(&st,0,sizeof(st));
      
      switch(res->ai_family) {
         case PF_INET: {
            struct sockaddr_in *sin = (struct sockaddr_in *)&st;
            sin->sin_family = PF_INET;
            sin->sin_port = htons(local_port);
            break;
         }

         case PF_INET6: {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&st;
#ifdef SIN6_LEN
            sin6->sin6_len = res->ai_addrlen;
#endif
            sin6->sin6_family = PF_INET6;
            sin6->sin6_port = htons(local_port);
            break;
         }

         default:
            /* shouldn't happen */
            close(sck);
            sck = -1;
            continue;
      }

      /* try to connect to remote host */
      if (!bind(sck,(struct sockaddr *)&st,res->ai_addrlen) &&
          !connect(sck,res->ai_addr,res->ai_addrlen))
         break;

      close(sck);
      sck = -1;
   }

   freeaddrinfo(res0);
   return(sck);
}

static void create_threads(void)
{
  int s;
  sigset_t sigset;
  pthread_attr_t attrs;

  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGTERM);  
  sigaddset(&sigset, SIGHUP);
  pthread_sigmask(SIG_BLOCK, &sigset, NULL);

  s = pthread_attr_init(&attrs);
  if (s != 0)
    handle_error_en(s, "pthread_attr_init");
  s = pthread_attr_setdetachstate (&attrs, PTHREAD_CREATE_DETACHED);
  if (s != 0)
    handle_error_en(s, "pthread_attr_setdetachstate");

  while (1)
    {
      printf("toto\n");
    }
}

int main(int argc, char **argv)
{
  char opt;

  while ((opt = getopt(argc, argv, "v")) != -1)
    {
      switch (opt)
	{
	  case 'v':
	    printf("%s version %s\n", NAME, VERSION);
	    exit (EXIT_SUCCESS);
	}
    }

  create_threads();
  return (EXIT_SUCCESS);
}
