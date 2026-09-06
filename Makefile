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
BUILDDIR    = build
NAME        = ubridge
DEBUG_TARGET = $(BUILDDIR)/$(NAME)
UNIT_TEST_TARGET = $(BUILDDIR)/unit_tests
UNIT_TEST_SRC = $(wildcard tests/unit/*.c)

SRC     =   src/main.c                  \
            src/ubridge_options.c       \
            src/ubridge.c               \
            src/nio.c                   \
            src/nio_udp.c               \
            src/nio_unix.c              \
            src/nio_ethernet.c          \
            src/nio_tap.c               \
            src/parse.c                 \
            src/packet_filter.c         \
            src/delay_line.c            \
            src/pcap_capture.c          \
            src/pcap_filter.c           \
            src/hypervisor.c            \
            src/hypervisor_parser.c     \
            src/hypervisor_bridge.c


OBJ       = $(SRC:.c=.o)
DEBUG_OBJ = $(SRC:%.c=$(BUILDDIR)/%.o)

CC      ?=  gcc

CFLAGS  +=  -Wall

BINDIR  =   /usr/local/bin

LIBS    =   -lpthread -lpcap -lm

# Linux-only: RAW Ethernet + netlink-backed hypervisor modules
SRC += src/nio_linux_raw.c             \
       src/hypervisor_docker.c         \
       src/hypervisor_iol_bridge.c     \
       src/hypervisor_brctl.c          \
       src/hypervisor_link.c           \
       src/hypervisor_tap.c            \
       src/hypervisor_tc.c             \
       src/hypervisor_capture.c        \
       src/hypervisor_marker.c         \
       src/netlink/nl.c

ifeq ($(SYSTEM_INIPARSER),1)
    CFLAGS += -DUSE_SYSTEM_INIPARSER
    LIBS += -liniparser
else
    SRC += src/iniparser/iniparser.c   \
	   src/iniparser/dictionary.c
endif

# debug options
SANITIZERS = address,undefined
DEBUG_CFLAGS = -O1 -g -fsanitize=$(SANITIZERS) -fno-omit-frame-pointer
DEBUG_LDFLAGS = -fsanitize=$(SANITIZERS)

##############################
.PHONY: clean debug all install test

$(BUILDDIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -c $< -o $@

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(NAME) $(OBJ) $(LIBS)

$(DEBUG_TARGET): $(DEBUG_OBJ)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) $(LDFLAGS) $(DEBUG_LDFLAGS) -o $(DEBUG_TARGET) $(DEBUG_OBJ) $(LIBS)

all: $(NAME)

debug: $(DEBUG_TARGET)

clean:
	-rm -f $(OBJ)
	-rm -f $(NAME)
	-rm -f *~
	-rm -rf $(BUILDDIR)

install: $(NAME)
	chmod +x $(NAME)
	cp -p $(NAME) $(BINDIR)
	setcap cap_net_admin,cap_net_raw=ep $(BINDIR)/$(NAME)

$(UNIT_TEST_TARGET): $(UNIT_TEST_SRC) $(filter-out src/main.c,$(SRC))
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -Isrc $^ -o $@ \
		$(DEBUG_LDFLAGS) $(shell pkg-config --cflags --libs criterion) $(LIBS)

test: $(UNIT_TEST_TARGET)
	./$(UNIT_TEST_TARGET)
