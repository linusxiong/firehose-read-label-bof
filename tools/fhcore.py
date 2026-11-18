#!/usr/bin/env python3
# fhcore.py — shared plumbing for the prog_firehose_ddr.elf (SM8850 / PLZ110) research tools
#
# No external deps besides `pyserial` (live mode only) and `capstone` (static mode only).
#
# Segment map (ELF64 AArch64, PH names below):
#   text   : file 0x01000 <-> VA 0x14999000   size 0x39000
#   rodata : file 0x3a000 <-> VA 0x149d2000   size 0x09000
#   data   : file 0x43000 <-> VA 0x149de000   size 0x04000
#
# Binary identity this file was built against:
#   sha256  31ad5664023af3f9022913272e2c180fde5f658f31c9094ae9ec57c128c59086
#   build   Jul 22 2025 - 15:41:08
#   size    295,636 bytes

from __future__ import annotations

import os
import re
import struct
import subprocess
import sys
import time
from dataclasses import dataclass

# --------------------------------------------------------------------------- identity

KNOWN_SHA256 = "31ad5664023af3f9022913272e2c180fde5f658f31c9094ae9ec57c128c59086"
KNOWN_SIZE = 295636
KNOWN_BUILD = b"Jul 22 2025 - 15:41:08"

# (va_base, file_off, size)
SEGMENTS = (
    (0x14999000, 0x01000, 0x39000),   # .text
    (0x149d2000, 0x3A000, 0x09000),   # .rodata
    (0x149DE000, 0x43000, 0x04000),   # .data
)

# Runtime globals touched by the command handlers (absolute RAM addresses).
FLAG1_ADDR = 0x8046BBC0       # 1 byte  — write permission, set only by a successful OSIG <verify>
FLAG3_ADDR = 0x149DE648       # 1 byte  — .data gate consulted by program/move/erase*
MODE_ADDR = 0x8046BBB8        # 8 bytes — ModeType
AUTH_TYPE_ADDR = 0x8046BBC4   # 4 bytes — 1 = intranet, 2 = internet (both imply flag1 set)
ENABLE_FLASH_ADDR = 0x8046BBE0  # 1 byte (bit used by read)
VIP_TABLE_ADDR = 0x8046BBE8
TRANSFERCFG_ADDR = 0x804767B8
SIGNDATA_PENDING_ADDR = 0x8045D77C  # set to 1 by getsigndata

# Key material in .rodata (ASCII hex strings)
KEY1_VA = 0x149D3641          # OSIG <verify> RSA-2048 modulus, 512 hex chars
KEY1_EXP_VA = 0x149D3842      # "10001"
KEY2_VA = 0x149D38E7          # writecdtdata RSA-2048 modulus
KEY2_TAG_VA = 0x149D38DE      # "SM8850_C"


class BinaryError(RuntimeError):
    pass


def va_to_file(va: int) -> int:
    for base, off, size in SEGMENTS:
        if base <= va < base + size:
            return off + (va - base)
    raise BinaryError("VA %#x is outside the mapped segments" % va)


def load(path: str) -> "Firmware":
    with open(path, "rb") as fh:
        blob = fh.read()
    return Firmware(blob, path)


class Firmware:
    def __init__(self, blob: bytes, path: str = "<memory>"):
        self.blob = blob
        self.path = path
        if len(blob) < 0x47000:
            raise BinaryError("%s is too small to be prog_firehose_ddr.elf" % path)

    # -- identity -----------------------------------------------------------
    def verify_identity(self) -> str:
        import hashlib
        digest = hashlib.sha256(self.blob).hexdigest()
        if digest == KNOWN_SHA256:
            return "exact"
        if KNOWN_BUILD in self.blob:
            return "build-match"      # same build string, probably a different packaging
        return "unknown"

    # -- bytes --------------------------------------------------------------
    def read_va(self, va: int, n: int) -> bytes:
        off = va_to_file(va)
        return self.blob[off:off + n]

    def u32(self, va: int) -> int:
        return struct.unpack("<I", self.read_va(va, 4))[0]

    def cstr(self, va: int, limit: int = 256) -> bytes:
        off = va_to_file(va)
        end = self.blob.find(b"\x00", off, off + limit)
        if end < 0:
            end = off + limit
        return self.blob[off:end]

    # -- keys ---------------------------------------------------------------
    def key1_modulus(self) -> int:
        hexstr = self.read_va(KEY1_VA, 512)
        if not re.fullmatch(rb"[0-9A-Fa-f]{512}", hexstr):
            raise BinaryError("key1 is not a 512-nibble hex string")
        return int(hexstr, 16)

    def key2_modulus(self) -> int:
        hexstr = self.read_va(KEY2_VA, 512)
        return int(hexstr, 16)

    def key1_exponent(self) -> int:
        return int(self.cstr(KEY1_EXP_VA, 16), 16)

    # -- tables -------------------------------------------------------------
    def handler_table(self):
        """Yields (index, name, handler_va) for the dispatch table at 0x149d2000."""
        out = []
        table_va = 0x149D2000
        for i in range(64):
            entry = self.read_va(table_va + i * 16, 16)
            name_ptr, handler = struct.unpack("<QQ", entry)
            if not (0x149D2000 <= name_ptr < 0x149DA000):
                break
            if not (0x14999000 <= handler < 0x149D2000):
                break
            out.append((i, self.cstr(name_ptr).decode("latin1"), handler))
        return out


# --------------------------------------------------------------------------- logging

def log(msg: str) -> None:
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def log_raw(prefix: str, data: bytes) -> None:
    for line in re.split(rb"(?=<\?xml)", data):
        if line.strip():
            print("   %s %s" % (prefix, line[:300].decode("utf-8", "replace")))


# --------------------------------------------------------------------------- live serial

SAHARA_IMAGES = (
    ("13", "prog_firehose_ddr.elf"),
    ("59", "sequencer_ram.elf"),
    ("21", "xbl_sc.elf"),
    ("36", "multi_image_qti.mbn"),
    ("37", "multi_image.mbn"),
    ("38", "xbl_config_devprg.elf"),
    ("60", "signed_firmware_soc_view.elf"),
    ("61", "tme_config.elf"),
)

# Point these at your own EDL package layout, or pass --images / --elf on the CLI.
# The image set below is the PLZ110 (OnePlus 15T) 16.0.4.603CN01 QFIL package.
DEFAULT_IMAGE_DIR = os.environ.get("EDL_IMAGE_DIR", "./IMAGES/")
DEFAULT_QSAMARA = os.environ.get(
    "QSaharaServer",
    os.path.join(DEFAULT_IMAGE_DIR, "..", "bin", "QSaharaServer.exe"),
)


@dataclass
class LiveConfig:
    port: str | None = None
    image_dir: str = DEFAULT_IMAGE_DIR
    qsahara: str = DEFAULT_QSAMARA
    digest: str | None = None


def find_edl_port(wait_seconds: int = 25) -> str | None:
    try:
        import serial.tools.list_ports
    except ImportError:
        raise BinaryError("pyserial is required for live mode (pip install pyserial)")
    for _ in range(wait_seconds):
        for p in serial.tools.list_ports.comports():
            if p.pid == 0x9008:
                return p.device
        time.sleep(1.5)
    return None


def kill_stale_tools() -> None:
    for proc in ("QPSTConfig.exe", "QPSTServer.exe", "fh_loader.exe", "QSaharaServer.exe"):
        subprocess.run(["taskkill", "/F", "/IM", proc], capture_output=True)


def upload_programmer(cfg: LiveConfig, portname: str, timeout: int = 180):
    cmd = [cfg.qsahara, "-p", r"\\.\%s" % portname]
    for image_id, name in SAHARA_IMAGES:
        cmd += ["-s", "%s:%s" % (image_id, os.path.join(cfg.image_dir, name))]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           cwd=os.path.dirname(cfg.qsahara))
    except subprocess.TimeoutExpired:
        return False, "timeout"
    out = (r.stdout or b"").decode("gbk", "replace")
    ok = ("Sahara protocol completed" in out) or ("Firehose" in out)
    return ok, out


class Session:
    """Thin XML command wrapper around the firehose serial port."""

    def __init__(self, portname: str):
        import serial
        self.port = serial.Serial(portname, timeout=3, write_timeout=4)
        self.port.setDTR(True)
        time.sleep(0.3)
        self.port.read(0x10000)

    def send(self, payload, wait: float = 0.8) -> bytes:
        if isinstance(payload, str):
            payload = payload.encode()
        self.port.write(payload)
        return self.drain(wait)

    def drain(self, seconds: float = 1.0) -> bytes:
        t0 = time.time()
        buf = b""
        while time.time() - t0 < seconds:
            data = self.port.read(0x100000)
            if data:
                buf += data
            else:
                time.sleep(0.02)
        return buf

    def configure(self, mode_type: int = 5, enable_flash: int = 1, extra: str = "") -> bytes:
        xml = (
            '<?xml version="1.0" ?><data><configure MemoryName="ufs" ModeType="%d" '
            'Verbose="0" AlwaysValidate="0" EnableFlash="%d" '
            'MaxDigestTableSizeInBytes="8192" MaxPayloadSizeToTargetInBytes="1048576" '
            'ZlpAwareHost="1" SkipStorageInit="0" %s/></data>'
        ) % (mode_type, enable_flash, extra)
        return self.send(xml)

    def close(self) -> None:
        try:
            self.port.close()
        except Exception:
            pass


def open_live_session(cfg: LiveConfig, send_digest: bool = True, mode_type: int = 5,
                      enable_flash: int = 1, attach: bool = False) -> tuple[Session, str]:
    """QSahara upload -> raw VIP digest -> configure. Returns (session, portname)."""
    kill_stale_tools()
    time.sleep(1)
    portname = cfg.port or find_edl_port()
    if not portname:
        raise BinaryError("no 9008 device — power-cycle / replug the phone")

    if not attach:
        ok, out = upload_programmer(cfg, portname)
        if not ok:
            raise BinaryError("QSahara failed:\n%s" % out[-600:])
        log("programmer uploaded (%s)" % portname)

    if attach:
        import serial
        session = Session.__new__(Session)
        session.port = serial.Serial(portname, timeout=3, write_timeout=4)
        session.port.setDTR(True)
        time.sleep(0.2)
        session.port.read(0x20000)
    else:
        session = Session(portname)
    if send_digest:
        digest_path = cfg.digest or os.path.join(
            cfg.image_dir, "DigestsToSign_nv10010111.bin.mbn")
        with open(digest_path, "rb") as fh:
            resp = session.send(fh.read(), 1.0)
        log("VIP digest ACK=%s" % (b"ACK" in resp))
    resp = session.configure(mode_type, enable_flash)
    if b"ACK" not in resp:
        raise BinaryError("configure rejected: %r" % resp[:300])
    log("configured ModeType=%d EnableFlash=%d" % (mode_type, enable_flash))
    return session, portname


def probe_flag1(session: Session) -> bool | None:
    """getbasicdata is flag1-gated: an ACK means flag1 != 0."""
    resp = session.send('<?xml version="1.0" ?><data><getbasicdata /></data>', 1.0)
    if b"ACK" in resp:
        return True
    if b"NAK" in resp or b"not allowed" in resp:
        return False
    return None


# --------------------------------------------------------------------------- misc

def sha256_file(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
