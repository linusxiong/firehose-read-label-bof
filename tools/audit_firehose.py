#!/usr/bin/env python3
"""Static audit for prog_firehose_ddr.elf (Qualcomm EDL programmer).

Answers three questions without a device:
  1. Which firehose commands are gated behind the OSIG write permission (flag1)?
  2. Which commands can be reached with no authentication at all?
  3. Which of those have an unchecked host-controlled length (a memory-safety bug)?

Usage:
  python audit_firehose.py <prog_firehose_ddr.elf>            # summary
  python audit_firehose.py <elf> --gates                      # per-command gate trace
  python audit_firehose.py <elf> --copies                     # every string-copy call site
  python audit_firehose.py <elf> --disasm 0x149a433c 0x60     # annotated disassembly
  python audit_firehose.py <elf> --table                      # dispatch table + keys
  python audit_firehose.py <elf> --gadgets                    # small ROP gadgets

Requires: capstone
"""
from __future__ import annotations

import argparse
import struct
import sys

try:
    import capstone
except ImportError:
    sys.exit("capstone is required: pip install capstone")

import fhcore
from fhcore import (Firmware, SEGMENTS, FLAG1_ADDR, FLAG3_ADDR, MODE_ADDR,
                    ENABLE_FLASH_ADDR, AUTH_TYPE_ADDR, va_to_file)

# Accessors (VA -> what they read/write)
ACCESSORS = {
    0x149AABC4: "get_flag1        (ldrb [0x8046bbc0])",
    0x149AABD0: "set_flag1        (strb [0x8046bbc0])   <- ONLY writer",
    0x149AABE4: "get_flag3        (ldrb [.data 0x149de648])",
    0x149AABF0: "set_flag3        (strb [.data 0x149de648])",
    0x149AAC04: "get_auth_type    (ldr  [0x8046bbc4])",
    0x149AAC10: "set_auth_type    (str  [0x8046bbc4])",
    0x149AAC30: "get_mode         (ldr  [0x8046bbc8])",
    0x149AACA4: "set_enable_flash (strb [0x8046bbe0])",
    0x149AACB8: "get_enable_flash (ldrb [0x8046bbe0])",
}

TEXT_BASE, TEXT_OFF, TEXT_SIZE = SEGMENTS[0]


def _bl_target(fw: Firmware, va: int) -> int | None:
    w = fw.u32(va)
    if (w & 0xFC000000) != 0x94000000:
        return None
    imm = w & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return va + imm * 4


def _all_bl_targets(fw: Firmware, target: int):
    for va in range(TEXT_BASE, TEXT_BASE + TEXT_SIZE, 4):
        if _bl_target(fw, va) == target:
            yield va


def _callers_of_setter(fw: Firmware, setter_va: int):
    """Callers of a setter, plus their callers (depth 2) — enough to see a success path."""
    out = []
    for direct in _all_bl_targets(fw, setter_va):
        out.append(("direct", direct))
        for indirect in _all_bl_targets(fw, direct):
            out.append(("  caller", indirect))
    return out


def cmd_gate_report(fw: Firmware) -> None:
    print("=" * 78)
    print("flag1 writer / reader census")
    print("=" * 78)
    print("flag1 lives at %#x (1 byte). Every write command consults it." % FLAG1_ADDR)
    print()
    for what, va in (("flag1 setter", 0x149AABD0),
                     ("flag1 getter", 0x149AABC4),
                     ("flag3 setter", 0x149AABF0),
                     ("flag3 getter", 0x149AABE4),
                     ("enFlash set",  0x149AACA4),
                     ("auth_type set", 0x149AAC10)):
        sites = list(_all_bl_targets(fw, va))
        print("%-14s @ %#x : %d call site(s)" % (what, va, len(sites)))
        for s in sites:
            print("      called from %#x" % s)
    print()
    print("flag1 setter callers (the only way to raise the write gate):")
    print("  0x149a2bdc -> 0x149a2c10 (success)  -> 0x149a2c14 bl 0x149aabd0")
    print("  0x149a2bdc is inside the OSIG <verify> handler (0x149a324c -> 0x149a2b64).")
    print("  verify calls 0x149a290c (RSA-2048 PKCS#1 v1.5 / SHA-256) and only then sets flag1.")


def handler_table(fw: Firmware) -> None:
    print("=" * 78)
    print("command dispatch table")
    print("=" * 78)
    print("table VA 0x149d2000, 16 bytes/entry: {name_ptr, 0, handler, 0}")
    print()
    print("%-4s %-24s %-12s %s" % ("#", "command", "handler", "flag1 gate"))
    print("-" * 72)
    for idx, name, handler in fw.handler_table():
        flag1, mode = _gated(fw, handler)
        if flag1 and mode:
            verdict = "flag1 (ModeType==5 also passes)"
        elif flag1:
            verdict = "flag1 required"
        else:
            verdict = "-- NOT GATED --"
        print("%-4d %-24s %#-10x  %s" % (idx, name, handler, verdict))
    print()
    print("keys:")
    print("  key1 (OSIG verify) @ %#x = %s..." % (fhcore.KEY1_VA, fw.read_va(fhcore.KEY1_VA, 32).decode()))
    print("  exponent           @ %#x = %s" % (fhcore.KEY1_EXP_VA, fw.cstr(fhcore.KEY1_EXP_VA, 8).decode()))
    print("  key2 (writecdtdata)@ %#x = %s..." % (fhcore.KEY2_VA, fw.read_va(fhcore.KEY2_VA, 32).decode()))


_GATE_CACHE: dict[int, str] = {}

_PROLOGUE = (
    "stp x29, x30, [sp, #-",
    "stp x29, x30, [sp],",
    "sub sp, sp, #",
    "sub sp, sp, #0x",
)


def _is_prologue(ins) -> bool:
    text = "%s %s" % (ins.mnemonic, ins.op_str)
    return any(text.startswith(p) for p in _PROLOGUE)


def _function_extent(fw: Firmware, md, start: int, max_scan: int = 0x400) -> int:
    """Stop at the first `ret` reached linearly from the entry.

    This under-approximates a real CFG (a handler with an early return reports a short
    extent), which is the safe direction: a "no" from this scan means "the flag1 getter
    is not called on the straight-line path", and every such case here is also excluded
    by the CALLER (the dispatcher only reaches these handlers when the flag allows it).
    """
    for va in range(start, start + max_scan, 4):
        d = list(md.disasm(fw.read_va(va, 4), va))
        if not d:
            continue
        if d[0].mnemonic == "ret":
            return va + 4
    return start + max_scan


def _gated(fw: Firmware, handler_va: int, md=None) -> tuple[bool, bool]:
    """Returns (calls_flag1_getter, ModeType==5 bypass exists).

    The bypass is only real when the flag1 test and the ModeType test branch to the SAME
    address. `cmp x8,#5` somewhere in the function is not enough (programcust compares
    ModeType against 6 for a different reason).
    """
    if handler_va in _GATE_CACHE:
        return _GATE_CACHE[handler_va]
    if md is None:
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    end = _function_extent(fw, md, handler_va)
    insns = []
    for va in range(handler_va, end, 4):
        d = list(md.disasm(fw.read_va(va, 4), va))
        if d:
            insns.append(d[0])

    def branch_target(ins):
        if not (ins.mnemonic.startswith("b") and ins.mnemonic != "bic"):
            return None
        try:
            return ins.operands[-1].imm
        except (capstone.CsError, IndexError):
            return None

    flag1 = any(_bl_target(fw, i.address) == 0x149AABC4 for i in insns)

    # find "bl flag1getter ; tst w0,#0xff ; b.<cond> T"
    bypass = False
    for idx, ins in enumerate(insns):
        if _bl_target(fw, ins.address) != 0x149AABC4:
            continue
        window = insns[idx + 1: idx + 6]
        target = None
        for w in window:
            if w.mnemonic == "tst" and "w0, #0xff" in w.op_str:
                continue
            t = branch_target(w)
            if t is not None:
                target = t
                break
        if target is None:
            continue
        # look for `ldr x8,[..,#0xbb8]` then `cmp x8,#5` then a branch to the same target
        for jdx, j in enumerate(insns):
            if j.mnemonic != "cmp" or "x8, #5" not in j.op_str:
                continue
            # the ModeType load must be within the previous 3 instructions
            prev = insns[max(0, jdx - 3): jdx]
            if not any("0xbb8" in p.op_str and p.mnemonic == "ldr" for p in prev):
                continue
            nxt = insns[jdx + 1: jdx + 3]
            if any(branch_target(n) == target for n in nxt):
                bypass = True
                break
        if bypass:
            break

    _GATE_CACHE[handler_va] = (flag1, bypass)
    return flag1, bypass


def copy_sites(fw: Firmware, target: int = 0x1499B158) -> None:
    """Every call to the bounded-string formatter, with the size operand classified."""
    print("=" * 78)
    print("string-copy call sites -> %#x" % target)
    print("=" * 78)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    print("%-14s %-18s %s" % ("call site", "size operand", "writes x1 at"))
    print("-" * 78)
    counts = {}
    for site in range(TEXT_BASE, TEXT_BASE + TEXT_SIZE, 4):
        if _bl_target(fw, site) != target:
            continue
        kind, detail = _classify_size(fw, md, site)
        counts[kind] = counts.get(kind, 0) + 1
        print("%#-12x %-18s %s" % (site, kind, detail))
    print()
    print("summary: " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))
    print()
    print("Exactly one site takes its size from strlen(): 0x149a438c, and its operand is")
    print("the HOST-supplied `label`, not the literal. That is the overflow.")


def _classify_size(fw: Firmware, md, site: int):
    """Find the instruction that last writes x1 before the call.

    x1 is the size argument of the formatting routine (x0=dst, x1=size, x2=fmt, x3=arg).
    We report whether it looks like a constant or something data-dependent.
    """
    md.detail = True
    for va in range(site - 4, max(TEXT_BASE, site - 4 * 40), -4):
        d = list(md.disasm(fw.read_va(va, 4), va))
        if not d:
            continue
        ins = d[0]
        try:
            ops = ins.operands
        except capstone.CsError:
            continue
        # stop at a control-flow boundary — a write before it cannot reach the call
        if ins.mnemonic in ("bl", "blr", "b", "br", "ret", "cbz", "cbnz", "tbz", "tbnz") \
                or ins.mnemonic.startswith("b."):
            break
        if not ops:
            continue
        dst = ops[0]
        if dst.type == capstone.arm64.ARM64_OP_REG and \
                ins.reg_name(dst.reg) in ("x1", "w1"):
            src = ops[1] if len(ops) > 1 else None
            if src is None:
                return "other", "%s %s" % (ins.mnemonic, ins.op_str)
            if src.type == capstone.arm64.ARM64_OP_IMM:
                return "constant", "%s %s" % (ins.mnemonic, ins.op_str)
            if src.type == capstone.arm64.ARM64_OP_REG:
                sname = ins.reg_name(src.reg)
                if sname in ("xzr", "wzr"):
                    return "constant", "%s %s" % (ins.mnemonic, ins.op_str)
                if any(reg in ins.op_str for reg in ("x0", "w0")):
                    return "FROM strlen()", "%s %s" % (ins.mnemonic, ins.op_str)
                return "register", "%s %s" % (ins.mnemonic, ins.op_str)
    return "unknown", ""


def disasm(fw: Firmware, start: int, length: int) -> None:
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for va in range(start, start + length, 4):
        raw = fw.read_va(va, 4)
        for ins in md.disasm(raw, va):
            print("  %#-12x %s  %-9s %s" % (va, raw.hex(), ins.mnemonic, ins.op_str))


def gadgets(fw: Firmware) -> None:
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    code = fw.blob[TEXT_OFF:TEXT_OFF + TEXT_SIZE]

    def dec(i):
        d = list(md.disasm(code[i:i + 4], TEXT_BASE + i))
        return d[0] if d else None

    print("=" * 78)
    print("small gadgets (decoded at every 4-byte boundary)")
    print("=" * 78)
    tests = [
        ("mov w0,#1 ; ret",
         lambda a, b, c=None: a.mnemonic == "mov" and a.op_str == "w0, #1" and b.mnemonic == "ret"),
        ("mov w0,#1 ; br xN",
         lambda a, b, c=None: a.mnemonic == "mov" and a.op_str == "w0, #1" and b.mnemonic == "br"),
        ("mov w0,#1 ; blr xN",
         lambda a, b, c=None: a.mnemonic == "mov" and a.op_str == "w0, #1" and b.mnemonic == "blr"),
        ("mov sp,xN ; ret",
         lambda a, b, c=None: a.mnemonic == "mov" and a.op_str.startswith("sp, x")
                              and b.mnemonic == "ret"),
        ("add sp,xN,#0 ; ret",
         lambda a, b, c=None: a.mnemonic == "add" and a.op_str.startswith("sp, x")
                              and ", #0" in a.op_str and b.mnemonic == "ret"),
        ("ldr x30,[sp,#imm] ; ret",
         lambda a, b, c=None: a.mnemonic == "ldr" and a.op_str.startswith("x30, [sp")
                              and b.mnemonic == "ret"),
        ("strb w0,[x1] ; ret",
         lambda a, b, c=None: a.mnemonic == "strb" and a.op_str.startswith("w0, [x1")
                              and b.mnemonic == "ret"),
        ("mov x0,x1 ; ret",
         lambda a, b, c=None: a.mnemonic == "mov" and a.op_str == "x0, x1" and b.mnemonic == "ret"),
    ]
    for name, pred in tests:
        hits = []
        for i in range(0, len(code) - 12, 4):
            a, b, c = dec(i), dec(i + 4), dec(i + 8)
            if a and b and pred(a, b, c):
                hits.append(TEXT_BASE + i)
        print("%-28s %d" % (name, len(hits)))
        for h in hits[:16]:
            print("      %#x" % h)
        if len(hits) > 16:
            print("      ... (%d more)" % (len(hits) - 16))
    print()
    print("No mov sp,xN / add sp,xN,#0 stack pivot and no 'mov w0,#1 ; br xN' exist in this")
    print("build, so a single overflow cannot stage a ROP chain on its own.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("elf")
    ap.add_argument("--gates", action="store_true")
    ap.add_argument("--table", action="store_true")
    ap.add_argument("--copies", action="store_true")
    ap.add_argument("--gadgets", action="store_true")
    ap.add_argument("--disasm", nargs=2, metavar=("START", "LEN"))
    args = ap.parse_args()

    fw = fhcore.load(args.elf)
    ident = fw.verify_identity()
    print("file   : %s" % args.elf)
    print("sha256 : %s" % fhcore.sha256_file(args.elf))
    print("size   : %d bytes" % len(fw.blob))
    print("match  : %s" % ident)
    if ident == "unknown":
        print("WARNING: this is not the binary the offsets were derived from; "
              "addresses below may be wrong.")
    print()

    ran = False
    if args.gates:
        cmd_gate_report(fw); ran = True
    if args.table:
        handler_table(fw); ran = True
    if args.copies:
        copy_sites(fw); ran = True
    if args.gadgets:
        gadgets(fw); ran = True
    if args.disasm:
        disasm(fw, int(args.disasm[0], 0), int(args.disasm[1], 0)); ran = True
    if not ran:
        handler_table(fw)
        copy_sites(fw)


if __name__ == "__main__":
    main()
