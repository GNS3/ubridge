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

#ifndef PCAP_FILTER_H_
#define PCAP_FILTER_H_

#include "nio.h"

int set_pcap_filter(nio_ethernet_t *nio_ethernet, const char *filter);

#if !defined(PCAP_NETMASK_UNKNOWN)
/*
 *  Value to pass to pcap_compile() as the netmask if you don't know what
 *  the netmask is.
 *
 *  Not defined by WinPcap
 */
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

#endif /* !PCAP_FILTER_H_ */
