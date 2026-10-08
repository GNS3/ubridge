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

#ifndef UBRIDGE_TC_NETEM_DIST_H
#define UBRIDGE_TC_NETEM_DIST_H

/* Number of s16 samples per distribution table (see tc_netem_dist.c). */
#define NETEM_DIST_SIZE 4096

extern const short netem_dist_normal[NETEM_DIST_SIZE];
extern const short netem_dist_pareto[NETEM_DIST_SIZE];
extern const short netem_dist_paretonormal[NETEM_DIST_SIZE];

#endif
