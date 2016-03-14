#!/usr/bin/make -f
#
#   This file is part of ubridge, a program to bridge network interfaces
#   to UDP tunnels.
#
#   Copyright (C) 2015 GNS3 Technologies Inc.
#
#   ubridge is free software: you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   ubridge is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

NAME    =   ubridge

SRC     =   ubridge.c               \
            nio.c                   \
            nio_udp.c               \
            nio_ethernet.c          \
            nio_tap.c               \
            iniparser/iniparser.c   \
            iniparser/dictionary.c  \
            parse.c                 \
            pcap_capture.c          \
            pcap_filter.c           \
            hypervisor.c            \
            hypervisor_parser.c     \
            hypervisor_bridge.c

OBJ     =   $(SRC:.c=.o)

CC      =   gcc

CFLAGS  =   -O3 -Wall

BINDIR  =   /usr/local/bin

ifeq ($(shell uname), Darwin)
   LIBS =   -lpthread -lpcap
   SRC +=   nio_fusion_vmnet.c    \

else ifeq ($(shell uname -o), Cygwin)
   CFLAGS += -DCYGWIN
   LIBS =   -lpthread -lwpcap
else
   LIBS =   -lpthread -lpcap
endif

# RAW Ethernet support for Linux
ifeq ($(shell uname), Linux)
    CFLAGS += -DLINUX_RAW
    SRC += nio_linux_raw.c      \
           hypervisor_docker.c  \
           netlink/nl.c
endif

##############################

$(NAME)	: $(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(LIBS)

.PHONY: clean

clean:
	-rm -f $(OBJ)
	-rm -f *~
	-rm -f $(NAME)

all	: $(NAME)

install : $(NAME)
	chmod +x $(NAME)
	cp $(NAME) $(BINDIR)
	setcap cap_net_admin,cap_net_raw=ep $(BINDIR)/$(NAME)
