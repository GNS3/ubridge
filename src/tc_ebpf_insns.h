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

/*
 * GENERATED FILE — the eBPF impairment program's instructions, extracted
 * from the object `make bpf` compiles from src/tc_impair.bpf.c
 * (freestanding: no CO-RE, no BTF-typed pointers; the object itself is a
 * transient build artifact, not committed).
 * Regenerate with `make bpf` (needs clang + binutils); the normal build
 * just compiles this file, so no clang/libbpf at build or run time.
 *
 * The two map-fd pseudo loads are at TC_IMPAIR_CFG_LD_IDX /
 * TC_IMPAIR_CNT_LD_IDX (verified ld_imm64 pairs with imm 0 by the
 * generator); the loader patches the run-time map fds there (and sets
 * src_reg = BPF_PSEUDO_MAP_FD) before BPF_PROG_LOAD.
 */

#ifndef TC_EBPF_INSNS_H
#define TC_EBPF_INSNS_H

#include <linux/bpf.h>

#define TC_IMPAIR_INSNS 427
#define TC_IMPAIR_CFG_LD_IDX 5
#define TC_IMPAIR_CNT_LD_IDX 13

extern const struct bpf_insn tc_impair_insns[TC_IMPAIR_INSNS];

#endif /* TC_EBPF_INSNS_H */
