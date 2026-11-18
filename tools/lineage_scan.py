#!/usr/bin/env python3
# Lineage scan: does the `<read label>` dead-bound overflow exist in another
# firehose programmer?
#
# The vulnerable sequence in the PLZ110 (SM8850) programmer is:
#
#   bl   strlen            ; strlen(host_label)        (x0 = host ptr)
#   cbz  x0, err
#   adrp/add x0, "label"   ; x0 = &"label"  (the literal)
#   bl   strlen            ; strlen("label") == 5
#   cmp  x0, #0x47         ; <-- dead check: compares 5, never fires
#   b.hi over_long
#   mov  x0, x2N           ; host pointer restored
#   bl   strlen            ; n = strlen(host_label)
#   add  x1, x0, #1        ; size = n + 1   (host controlled)
#   ...
#   sub  x0, x29, #0x50    ; dst = fixed stack buffer
#   mov  x3, x2N
#   bl   vsnprintf-wrapper
#
# We scan for the two load-bearing encodings, `cmp x0,#0x47` (1f 1c 01 f1)
# followed within 0x30 bytes by `add x1,x0,#1` (01 04 00 91) and
# `sub x0,x29,#0x50` (a0 43 01 d1), then disassemble the window.
#
# Supports raw ELF64/ELF32 and MELF containers (concatenated ELF images,
# as shipped in the OPPO/Chimera loader packs).
#
# Usage:
#   python tools/lineage_scan.py PROG1.elf PROG2.melf ...
#   python tools/lineage_scan.py --strings PROG.elf   # OPPO auth-layer markers

USAGE = """\
lineage_scan.py — byte-pattern scanner for the `<read label>` dead-bound overflow.

Scans one or more firehose programmers (raw ELF or MELF containers) for the
load-bearing sequence: cmp x0,#0x47 over strlen("label"), followed within 0x30
bytes by `add x1,x0,#1` and `sub x0,x29,#0x50`.

Usage:
  python tools/lineage_scan.py PROG1.elf PROG2.melf ...
  python tools/lineage_scan.py --strings PROG.elf   # OPPO auth-layer markers
"""

import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
except ImportError:
    md = None

OPPO_MARKERS = [
    b"oplus get AUTH_INTRANET",
    b"oplus get AUTH_INTERNET",
    b"firehose work in %s mode",
    b"Secure Boot is not enabled on the HW",
    b"download is not allowed",
    b"getsigndata",
]


def parse_elf_at(data, base):
    """Return [(file_off, vaddr, filesz)] PT_LOAD segments for an ELF at `base`."""
    segs = []
    if data[base : base + 4] != b"\x7fELF":
        return segs
    ei_class = data[base + 4]
    try:
        if ei_class == 2:
            e_phoff = struct.unpack_from("<Q", data, base + 0x20)[0]
            e_phentsize = struct.unpack_from("<H", data, base + 0x36)[0]
            e_phnum = struct.unpack_from("<H", data, base + 0x38)[0]
            if not (0 < e_phnum <= 64) or e_phoff > len(data):
                return segs
            for k in range(e_phnum):
                off = base + e_phoff + k * e_phentsize
                p_type = struct.unpack_from("<I", data, off)[0]
                p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from(
                    "<QQQQQ", data, off + 8
                )
                if p_type == 1 and p_filesz:
                    segs.append((base + p_offset, p_vaddr, p_filesz))
        else:
            e_phoff = struct.unpack_from("<I", data, base + 0x1C)[0]
            e_phentsize = struct.unpack_from("<H", data, base + 0x2A)[0]
            e_phnum = struct.unpack_from("<H", data, base + 0x2C)[0]
            if not (0 < e_phnum <= 64) or e_phoff > len(data):
                return segs
            for k in range(e_phnum):
                off = base + e_phoff + k * e_phentsize
                p_type = struct.unpack_from("<I", data, off)[0]
                p_offset, p_vaddr = struct.unpack_from("<II", data, off + 4)
                p_filesz = struct.unpack_from("<I", data, off + 16)[0]
                if p_type == 1 and p_filesz:
                    segs.append((base + p_offset, p_vaddr, p_filesz))
    except struct.error:
        pass
    return segs


def load_segments(data):
    """All PT_LOAD segments: the file is either one ELF or a MELF chain."""
    segs = []
    segs += parse_elf_at(data, 0)
    i = 4
    while True:
        i = data.find(b"\x7fELF", i)
        if i < 0 or i + 0x40 > len(data):
            break
        segs += parse_elf_at(data, i)
        i += 4
    return sorted(set(segs))


def off_to_va(segs, off):
    for o, base, sz in segs:
        if o <= off < o + sz:
            return base + (off - o)
    return None


def scan_vulnerable_copy(data, segs):
    """Yield (file_off, va, disasm_lines) for every dead-bound copy site."""
    hits = []
    i = 0
    while True:
        i = data.find(b"\x1f\x1c\x01\xf1", i)  # cmp x0, #0x47
        if i < 0:
            break
        window = data[i : i + 0x30]
        if (
            b"\x01\x04\x00\x91" in window  # add x1, x0, #1
            and b"\xa0\x43\x01\xd1" in window  # sub x0, x29, #0x50
        ):
            va = off_to_va(segs, i)
            if va is None:
                i += 1
                continue
            lines = []
            if md:
                code = data[i - 0x14 : i + 0x44]
                for ins in md.disasm(code, va - 0x14):
                    lines.append(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
            hits.append((i, va, lines))
        i += 1
    return hits


def main(argv):
    if "--strings" in argv:
        argv = [a for a in argv if a != "--strings"]
        strings_mode = True
    else:
        strings_mode = False

    files = argv[1:]
    if not files or any(a in ("-h", "--help") for a in files):
        print(__doc__ or USAGE)
        return 0 if not files else 1

    for fn in files:
        data = open(fn, "rb").read()
        segs = load_segments(data)
        big = [s for s in segs if s[2] > 0x10000]
        print(f"\n===== {fn}")
        print(
            "  PT_LOAD (>64K): "
            + " ".join(f"(off {o:#x}, va {b:#x}, sz {s:#x})" for o, b, s in big)
        )
        if strings_mode:
            for p in OPPO_MARKERS:
                idx = data.find(p)
                print(f"  {p.decode():45s} -> {hex(idx) if idx >= 0 else '-'}")
        hits = scan_vulnerable_copy(data, segs)
        for off, va, lines in hits:
            print(f"  -- dead-bound copy candidate at va {va:#x} (file {off:#x})")
            for line in lines:
                print(line)
        print(f"  total vulnerable-copy sites: {len(hits)}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
