#!/usr/bin/env python3
"""Regenerate src/tc_ebpf_insns.c from src/tc_impair.bpf.o.

The compiled object is committed; this script materialises its tc_impair
section as a plain instruction array the build compiles without any clang
or libbpf dependency (same pattern as the embedded netem distribution
tables in src/tc_netem_dist.c). Only needed when tc_impair.bpf.c changes:

    make bpf        # compiles the object AND regenerates the array

Uses binutils (objcopy/readelf) only. The two BPF_PSEUDO_MAP_FD loads are
located via the .reltc_impair relocations and exported as
TC_IMPAIR_CFG_LD_IDX / TC_IMPAIR_CNT_LD_IDX — the loader patches the
run-time map fds into them before BPF_PROG_LOAD.
"""
import re
import struct
import subprocess
import sys
import tempfile
import os

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OBJ = os.path.join(SRC, "src", "tc_impair.bpf.o")
OUT_C = os.path.join(SRC, "src", "tc_ebpf_insns.c")
OUT_H = os.path.join(SRC, "src", "tc_ebpf_insns.h")
SECTION = "tc_impair"

BPF_LD_IMM64 = 0x18
BPF_PSEUDO_MAP_FD = 1


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("command failed: %s\n%s" % (" ".join(cmd), r.stderr))
    return r.stdout


def insns_and_relocs():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        binpath = tf.name
    try:
        run(["objcopy", "--dump-section", "%s=%s" % (SECTION, binpath), OBJ])
        data = open(binpath, "rb").read()
        if len(data) == 0 or len(data) % 8 != 0:
            sys.exit("section %s has bogus size %d" % (SECTION, len(data)))
        relocs = {}
        sect = None
        for line in run(["readelf", "-rW", OBJ]).splitlines():
            m = re.match(r"^Relocation section '([^']+)'", line)
            if m:
                sect = m.group(1)
                continue
            if sect != ".rel" + SECTION:
                continue
            m = re.match(r"^([0-9a-f]+)\s+\S+\s+(\S+)\s+\S+\s+(\S+)\s*$", line)
            if not m:
                continue
            off, rtype, sym = int(m.group(1), 16), m.group(2), m.group(3)
            # Everything the object asks us to patch must be a map-fd load we
            # understand — e.g. an outlined helper yields an R_BPF_64_32
            # pseudo-call this array cannot carry (helpers stay inline_always)
            if rtype != "R_BPF_64_64" or sym not in ("cfg_map", "cnt_map"):
                sys.exit("unsupported relocation %s against '%s' at 0x%x — the "
                         "program must stay self-contained (mark helpers "
                         "inline_always; only the two map-fd loads may relocate)"
                         % (rtype, sym, off))
            relocs.setdefault(off, sym)
        return data, relocs
    finally:
        os.unlink(binpath)


def decode(data, i):
    code = data[i * 8]
    # struct bpf_insn: dst_reg:4 (low nibble), src_reg:4 (high nibble)
    dst = data[i * 8 + 1] & 0xF
    src = (data[i * 8 + 1] >> 4) & 0xF
    off = struct.unpack_from("<h", data, i * 8 + 2)[0]
    imm = struct.unpack_from("<i", data, i * 8 + 4)[0]
    return code, dst, src, off, imm


def main():
    data, relocs = insns_and_relocs()
    n = len(data) // 8
    idx = {}
    for off, sym in relocs.items():
        i = off // 8
        code, dst, src, off_f, imm = decode(data, i)
        code2, _, _, _, _ = decode(data, i + 1)
        if code != BPF_LD_IMM64 or imm != 0 or code2 != 0:
            sys.exit("%s relocation at insn %d is not a map fd ld_imm64 pair" % (sym, i))
        # clang leaves src_reg 0 in the object (the pseudo-fd bit is set by
        # whoever patches the fd — the loader does, like libbpf)
        idx[sym] = i
    if sorted(idx) != ["cfg_map", "cnt_map"]:
        sys.exit("expected exactly cfg_map/cnt_map relocations, got %s" % sorted(idx))

    lines = []
    for i in range(n):
        code, dst, src, off, imm = decode(data, i)
        lines.append("    { .code = 0x%02x, .dst_reg = %d, .src_reg = %d, .off = %d, .imm = %d }," % (code, dst, src, off, imm))
    body = "\n".join(lines)

    banner = """/*
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
 * from the committed object src/tc_impair.bpf.o (built from
 * src/tc_impair.bpf.c, freestanding: no CO-RE, no BTF-typed pointers).
 * Regenerate with `make bpf` (needs clang + binutils); the normal build
 * just compiles this file, so no clang/libbpf at build or run time.
 *
 * The two map-fd pseudo loads are at TC_IMPAIR_CFG_LD_IDX /
 * TC_IMPAIR_CNT_LD_IDX (verified ld_imm64 pairs with imm 0 by the
 * generator); the loader patches the run-time map fds there (and sets
 * src_reg = BPF_PSEUDO_MAP_FD) before BPF_PROG_LOAD.
 */
"""

    outh = """%s
#ifndef TC_EBPF_INSNS_H
#define TC_EBPF_INSNS_H

#include <linux/bpf.h>

#define TC_IMPAIR_INSNS %d
#define TC_IMPAIR_CFG_LD_IDX %d
#define TC_IMPAIR_CNT_LD_IDX %d

extern const struct bpf_insn tc_impair_insns[TC_IMPAIR_INSNS];

#endif /* TC_EBPF_INSNS_H */
""" % (banner, n, idx["cfg_map"], idx["cnt_map"])

    outc = """%s
#include "tc_ebpf_insns.h"

const struct bpf_insn tc_impair_insns[TC_IMPAIR_INSNS] = {
%s
};
""" % (banner, body)

    with open(OUT_H, "w") as f:
        f.write(outh)
    with open(OUT_C, "w") as f:
        f.write(outc)
    print("wrote %s + %s: %d insns (cfg_map ld at %d, cnt_map ld at %d)"
          % (OUT_C, OUT_H, n, idx["cfg_map"], idx["cnt_map"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
