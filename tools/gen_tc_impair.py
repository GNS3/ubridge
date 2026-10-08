#!/usr/bin/env python3
"""Regenerate src/tc_ebpf_insns.h from the tc_impair BPF object.

The object is a transient build artifact (git-ignored, compiled by the
`bpf` target under $(BUILDDIR)); the committed artifact is the instruction
array this script writes into the header — plain C the build compiles
without any clang or libbpf dependency (same pattern as the embedded netem
distribution tables in src/tc_netem_dist.c). Only needed when
tc_impair.bpf.c changes:

    make bpf        # compiles the object AND regenerates the header

The object is parsed in pure Python (section bytes, relocation entries and
symbol names straight off the ELF structures) — deliberately no binutils
dependency: Debian/Ubuntu ship binutils whose libbfd is built without the
BPF target, so objcopy there cannot even read the object ("Unable to
recognise the format of the input file"). The two BPF_PSEUDO_MAP_FD loads
are located via the .reltc_impair relocations and exported as
TC_IMPAIR_CFG_LD_IDX / TC_IMPAIR_CNT_LD_IDX — the loader patches the
run-time map fds into them before BPF_PROG_LOAD.
"""
import os
import struct
import sys

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
# the transient object `make bpf` compiles under $(BUILDDIR); overridable
# as argv[1] so the Makefile owns the path
OBJ = os.path.join(SRC, "build", "tc_impair.bpf.o")
OUT_H = os.path.join(SRC, "src", "tc_ebpf_insns.h")
SECTION = "tc_impair"

BPF_LD_IMM64 = 0x18
BPF_PSEUDO_MAP_FD = 1

EM_BPF = 247
SHT_SYMTAB = 2
SHT_REL = 4
# llvm's BPF relocation types (include/llvm/BinaryFormat/ELFRelocs/BPF.def)
R_BPF_64_64 = 1
R_BPF_NAMES = {1: "R_BPF_64_64", 2: "R_BPF_64_ABS64", 3: "R_BPF_64_ABS32",
               4: "R_BPF_64_NODYLD32", 10: "R_BPF_64_32"}


def insns_and_relocs():
    """(section bytes, {offset: symbol}) for the tc_impair section."""
    data = open(OBJ, "rb").read()

    # --- ELF header (64-bit little-endian) ---
    if data[:4] != b"\x7fELF":
        sys.exit("%s is not an ELF object" % OBJ)
    if data[4] != 2 or data[5] != 1:
        sys.exit("%s: expected ELFCLASS64, little-endian" % OBJ)
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != EM_BPF:
        sys.exit("%s: e_machine %d is not EM_BPF (%d)" % (OBJ, machine, EM_BPF))
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize = struct.unpack_from("<H", data, 58)[0]
    shnum = struct.unpack_from("<H", data, 60)[0]
    shstrndx = struct.unpack_from("<H", data, 62)[0]

    # --- section headers ---
    shs = []
    for i in range(shnum):
        (sh_name, sh_type, _flg, _addr, sh_offset, sh_size,
         sh_link, _info, _align, _entsize) = struct.unpack_from(
            "<IIQQQQIIQQ", data, shoff + i * shentsize)
        shs.append({"name_off": sh_name, "type": sh_type, "offset": sh_offset,
                    "size": sh_size, "link": sh_link})

    def cstr(blob, off):
        return blob[off:blob.find(b"\x00", off)].decode("ascii", "replace")

    shstr = shs[shstrndx]
    shstrdata = data[shstr["offset"]:shstr["offset"] + shstr["size"]]
    for s in shs:
        s["name"] = cstr(shstrdata, s["name_off"])

    sec = next((s for s in shs if s["name"] == SECTION), None)
    if sec is None:
        sys.exit("%s: no '%s' section" % (OBJ, SECTION))
    sect = data[sec["offset"]:sec["offset"] + sec["size"]]
    if len(sect) == 0 or len(sect) % 8 != 0:
        sys.exit("section %s has bogus size %d" % (SECTION, len(sect)))

    # --- symbol table (names for the relocation targets) ---
    symtab = next((s for s in shs if s["type"] == SHT_SYMTAB), None)
    symbols = []
    if symtab is not None:
        strtab = shs[symtab["link"]]
        strdata = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
        for off in range(0, symtab["size"], 24):        # Elf64_Sym
            st_name = struct.unpack_from("<I", data, symtab["offset"] + off)[0]
            symbols.append(cstr(strdata, st_name))

    # --- relocations against our section (Elf64_Rel: offset, info) ---
    relsec = next((s for s in shs if s["name"] == ".rel" + SECTION), None)
    relocs = {}
    if relsec is not None:
        for off in range(0, relsec["size"], 16):
            r_offset, r_info = struct.unpack_from(
                "<QQ", data, relsec["offset"] + off)
            rtype = r_info & 0xFFFFFFFF
            sym = symbols[r_info >> 32] if (r_info >> 32) < len(symbols) else "?"
            # Everything the object asks us to patch must be a map-fd load we
            # understand — e.g. an outlined helper yields an R_BPF_64_32
            # pseudo-call this array cannot carry (helpers stay inline_always)
            if rtype != R_BPF_64_64 or sym not in ("cfg_map", "cnt_map"):
                sys.exit("unsupported relocation %s against '%s' at 0x%x — the "
                         "program must stay self-contained (mark helpers "
                         "inline_always; only the two map-fd loads may relocate)"
                         % (R_BPF_NAMES.get(rtype, str(rtype)), sym, r_offset))
            relocs.setdefault(r_offset, sym)
    return sect, relocs


def decode(data, i):
    code = data[i * 8]
    # struct bpf_insn: dst_reg:4 (low nibble), src_reg:4 (high nibble)
    dst = data[i * 8 + 1] & 0xF
    src = (data[i * 8 + 1] >> 4) & 0xF
    off = struct.unpack_from("<h", data, i * 8 + 2)[0]
    imm = struct.unpack_from("<i", data, i * 8 + 4)[0]
    return code, dst, src, off, imm


def main():
    global OBJ
    if len(sys.argv) > 1:
        OBJ = sys.argv[1]
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
 * from the object `make bpf` compiles from src/tc_impair.bpf.c
 * (freestanding: no CO-RE, no BTF-typed pointers; the object itself is a
 * transient build artifact, not committed).
 * Regenerate with `make bpf` (needs clang + python3); the normal build
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

/* static: exactly one translation unit (src/tc_ebpf.c) includes this
 * generated header; nothing else links against the array */
static const struct bpf_insn tc_impair_insns[TC_IMPAIR_INSNS] = {
%s
};

#endif /* TC_EBPF_INSNS_H */
""" % (banner, n, idx["cfg_map"], idx["cnt_map"], body)

    with open(OUT_H, "w") as f:
        f.write(outh)
    print("wrote %s: %d insns (cfg_map ld at %d, cnt_map ld at %d)"
          % (OUT_H, n, idx["cfg_map"], idx["cnt_map"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
