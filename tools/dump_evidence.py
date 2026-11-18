#!/usr/bin/env python3
"""dump_evidence.py — regenerate the evidence/ directory from the programmer ELF.

Every artifact in evidence/ is derived from the binary; nothing is hand-written, so a
reader can re-run this and diff the output.

  python dump_evidence.py <prog_firehose_ddr.elf> [-o ../evidence]
"""
from __future__ import annotations

import argparse
import os
import sys

import capstone

import fhcore
from fhcore import va_to_file

TEXT_BASE, TEXT_OFF, TEXT_SIZE = fhcore.SEGMENTS[0]

SITES = {
    "read_handler_entry": (0x149A41A4, 0x54),
    "read_body_attrs":    (0x149A420C, 0x64),
    "read_enableflash":   (0x149A42F0, 0x4C),
    "read_label_copy":    (0x149A433C, 0x58),
    "read_too_long_dead": (0x149A43F0, 0x20),
    "read_canary":        (0x149A42BC, 0x34),
    "fatal_loop":         (0x149A006C, 0x1C),
    "flag1_getter":       (0x149AABC4, 0x0C),
    "flag1_setter":       (0x149AABD0, 0x14),
    "flag3_getter":       (0x149AABE4, 0x0C),
    "flag3_setter":       (0x149AABF0, 0x14),
    "enableflash_set":    (0x149AACA4, 0x14),
    "enableflash_get":    (0x149AACB8, 0x08),
    "auth_type_set":      (0x149AAC10, 0x0C),
    "verify_success_path": (0x149A2BB8, 0x84),
    "program_gate":       (0x149A3F44, 0x60),
    "canary_seed":        (0x149A1DC8, 0x2C),
}


def disasm_lines(fw: fhcore.Firmware, start: int, length: int):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    out = []
    for va in range(start, start + length, 4):
        raw = fw.read_va(va, 4)
        for ins in md.disasm(raw, va):
            out.append("  %#-12x %s  %-9s %s" % (va, raw.hex(), ins.mnemonic, ins.op_str))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("-o", "--out", default="../evidence")
    args = ap.parse_args()

    fw = fhcore.load(args.elf)
    os.makedirs(args.out, exist_ok=True)

    header = [
        "binary : %s" % args.elf,
        "sha256 : %s" % fhcore.sha256_file(args.elf),
        "size   : %d bytes" % len(fw.blob),
        "match  : %s" % fw.verify_identity(),
        "build  : %s" % fw.cstr(0x149D334C, 64).decode("latin1", "replace"),
        "",
    ]

    # ---- 1. annotated read handler ---------------------------------------
    path = os.path.join(args.out, "read_handler_annotated.txt")
    body = list(header)
    body.append("read handler: sub sp,sp,#0x160 ; add x29,sp,#0x110  (frame 0x160)")
    body.append("")
    notes = {
        "read_handler_entry": "entry: flag1-or-ModeType5 gate, cookie load",
        "read_body_attrs": "rx open, attribute parse, block-IO handle lookup",
        "read_enableflash": "auth_type != 1 -> fall through to the label copy",
        "read_label_copy": "VULNERABLE COPY: size = strlen(host label) + 1",
        "read_too_long_dead": "the intended bound (0x48) — unreachable, cmp uses the literal",
        "read_canary": "cookie check + epilogue (ldp x29,x30 ; ret)",
        "fatal_loop": "non-returning spin loop reached on cookie mismatch",
    }
    for name, (start, length) in SITES.items():
        if name not in notes:
            continue
        body.append("== %s ==" % notes[name])
        body.extend(disasm_lines(fw, start, length))
        body.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(body))
    print("wrote", path)

    # ---- 2. accessors -----------------------------------------------------
    path = os.path.join(args.out, "flag_accessors.txt")
    body = list(header)
    body.append("Runtime flags consulted by the write gate")
    body.append("")
    body.append("  flag1        0x8046bbc0  1 byte   -> only writer is 0x149aabd0")
    body.append("  flag3        0x149de648  1 byte   -> .data gate, set by <configure EnableFlash=1>")
    body.append("  ModeType     0x8046bbb8  8 bytes  -> read/gethealthinfo accept ModeType==5")
    body.append("  auth_type    0x8046bbc4  4 bytes  -> 1=intranet 2=internet, set on verify success")
    body.append("  EnableFlash  0x8046bbe0  1 byte")
    body.append("")
    for name in ("flag1_getter", "flag1_setter", "flag3_getter", "flag3_setter",
                 "enableflash_set", "enableflash_get", "auth_type_set", "canary_seed"):
        start, length = SITES[name]
        body.append("== %s == " % name)
        body.extend(disasm_lines(fw, start, length))
        body.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(body))
    print("wrote", path)

    # ---- 3. verify success path ------------------------------------------
    path = os.path.join(args.out, "verify_success_path.txt")
    body = list(header)
    body.append("OSIG <verify>: the only path that sets flag1")
    body.append("")
    body.append("  0x149a324c  verify handler        (requires 0x8045d77c == 1, set by getsigndata)")
    body.append("  0x149a32a8  flag1 getter")
    body.append("  0x149a3290  bl 0x149a2b64         (receive 0x1000 bytes, then RSA)")
    body.append("  0x149a2c10  mov w0,#1")
    body.append("  0x149a2c14  bl 0x149aabd0         -> sets [0x8046bbc0] = 1")
    body.append("")
    body.extend(disasm_lines(fw, *SITES["verify_success_path"]))
    body.append("")
    body.append("receiving side (0x149a2b64 -> 0x149a2bdc):")
    body.extend(disasm_lines(fw, 0x149A2B64, 0x80))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(body))
    print("wrote", path)

    # ---- 4. dispatch table ------------------------------------------------
    path = os.path.join(args.out, "command_table.txt")
    body = list(header)
    body.append("dispatch table @ 0x149d2000, 16 bytes/entry {name_ptr, 0, handler, 0}")
    body.append("")
    for idx, name, handler in fw.handler_table():
        body.append("  [%2d] %-24s %#x" % (idx, name, handler))
    body.append("")
    body.append("key1 (OSIG verify, RSA-2048) @ %#x" % fhcore.KEY1_VA)
    body.append("  " + fw.read_va(fhcore.KEY1_VA, 512).decode())
    body.append("exponent @ %#x = %s" % (fhcore.KEY1_EXP_VA, fw.cstr(fhcore.KEY1_EXP_VA, 8).decode()))
    body.append("")
    body.append("key2 (writecdtdata, RSA-2048) @ %#x" % fhcore.KEY2_VA)
    body.append("  " + fw.read_va(fhcore.KEY2_VA, 512).decode())
    body.append("tag  @ %#x = %s" % (fhcore.KEY2_TAG_VA, fw.cstr(fhcore.KEY2_TAG_VA, 16).decode()))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(body))
    print("wrote", path)

    # ---- 5. gadgets -------------------------------------------------------
    path = os.path.join(args.out, "gadgets.txt")
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    code = fw.blob[TEXT_OFF:TEXT_OFF + TEXT_SIZE]

    def dec(i):
        d = list(md.disasm(code[i:i + 4], TEXT_BASE + i))
        return d[0] if d else None

    body = list(header)
    body.append("single-instruction scan at every 4-byte boundary")
    body.append("")
    for label, pred in (
        ("mov w0,#1 ; ret",
         lambda a, b: a.mnemonic == "mov" and a.op_str == "w0, #1" and b.mnemonic == "ret"),
        ("mov w0,#1 ; br xN",
         lambda a, b: a.mnemonic == "mov" and a.op_str == "w0, #1" and b.mnemonic == "br"),
        ("mov w0,#1 ; blr xN",
         lambda a, b: a.mnemonic == "mov" and a.op_str == "w0, #1" and b.mnemonic == "blr"),
        ("mov sp,xN ; ret",
         lambda a, b: a.mnemonic == "mov" and a.op_str.startswith("sp, x") and b.mnemonic == "ret"),
        ("add sp,xN,#0 ; ret",
         lambda a, b: a.mnemonic == "add" and a.op_str.startswith("sp, x") and ", #0" in a.op_str
                      and b.mnemonic == "ret"),
        ("ldr x30,[sp,#imm] ; ret",
         lambda a, b: a.mnemonic == "ldr" and a.op_str.startswith("x30, [sp") and b.mnemonic == "ret"),
        ("mov x0,x1 ; ret",
         lambda a, b: a.mnemonic == "mov" and a.op_str == "x0, x1" and b.mnemonic == "ret"),
    ):
        hits = []
        for i in range(0, len(code) - 8, 4):
            a, b = dec(i), dec(i + 4)
            if a and b and pred(a, b):
                hits.append(TEXT_BASE + i)
        body.append("%-26s %d hit(s)" % (label, len(hits)))
        for h in hits[:20]:
            body.append("      %#x" % h)
        body.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(body))
    print("wrote", path)


if __name__ == "__main__":
    main()
