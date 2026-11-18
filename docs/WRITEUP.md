Qualcomm EDL (Firehose) — Programmer Stack Overflow via `<read label=...>`
===========================================================================

Advisory / research write-up
Author:  (see git history)
Date:    2026-11-07
Target:  Qualcomm `prog_firehose_ddr.elf` shipped with the OnePlus 15T (PLZ110),
         Snapdragon 8 Gen 5 (SM8850 "kaanapali"), ColorOS/ OxygenOS 16.0.4.603
Binary:  sha256 31ad5664023af3f9022913272e2c180fde5f658f31c9094ae9ec57c128c59086
         295,636 bytes, ELF64 AArch64, build string `Jul 22 2025 - 15:41:08`
Class:   CWE-787 / CWE-121 — stack-based buffer overflow, host-controlled length
Impact:  memory corruption in the EDL programmer from an unauthenticated USB session
Status:  no public CVE found for this exact defect; the vendor advisory list for
         SM8850 (NVD keyword `firehose`, `devprg`, `sahara`) does not contain it


0. TL;DR
--------
`<read label="...">` copies the host-supplied `label` attribute into a fixed 0xD8-byte
stack buffer with a size computed from `strlen(label)`. The length check above the copy
compares the length of the *literal* `"label"` (always 5) against `0x47`, so it never
fires. The copy is bounded only by the XML attribute limit.

The overwrite reaches, in order:
  * the stack cookie slot at dst+0x48 (bytes 72..79 of the label)
  * saved x29 at dst+0x50
  * saved x30 / LR at dst+0x58 (bytes 88..95)
  * the rest of the callee-saved register spill area up to dst+0xA0

Reaching the copy requires no OSIG signature and no write permission: `<configure
ModeType="5" .../>` is an unauthenticated command, and `read` accepts
`ModeType == 5` in place of the `flag1` write flag. The one condition the caller chain
adds on top of that is `auth_type != 1` (the "intranet" branch skips the copy).

This is a memory-safety bug in the *programmer*, not a bypass of the OSIG write gate.
`flag1` (0x8046bbc0) has exactly one writer in the whole image, and it is reached only
from the successful RSA path in `<verify>`. See §7 for why the two must not be confused.


1. Background: what the EDL programmer is and why this matters
-------------------------------------------------------------
A retail Qualcomm device in EDL mode (USB PID 9008) receives a small firmware blob —
the "programmer" — over the Sahara protocol, executes it on the application
processor, and then exposes the Firehose protocol: a stream of small XML documents
that the programmer interprets as storage commands (`program`, `erase`, `read`,
`patch`, `configure`, …).

On OPPO/OnePlus hardware the write commands are gated by an OPPO-specific signature
step. In this build the gate is a single byte at 0x8046bbc0 (call it `flag1`), set to 1
only when `<verify>` receives a 4096-byte blob whose first 256 bytes are a valid
RSA-2048 PKCS#1 v1.5 / SHA-256 signature over the device's challenge:

    0x149a2bb8  ldr  x0,[sp]           ; rx buffer
    0x149a2bbc  mov  w1,#0x1000
    0x149a2bc0  bl   0x149a62c0        ; receive exactly 0x1000 bytes
    0x149a2bc4  cmp  x0,#1,lsl#12
    0x149a2bc8  b.ne 0x149a2bf0        ; not 4096 -> "Error while receiving bytes"
    0x149a2bd0  mov  w1,#0x100
    0x149a2bd4  bl   0x149a290c        ; RSA-2048 verify, 256-byte signature
    0x149a2bdc  cbz  w0,0x149a2c10     ; 0 = success
    0x149a2c10  mov  w0,#1
    0x149a2c14  bl   0x149aabd0        ; writes flag1 = 1

    flag1 setter, 0x149aabd0:
      cmp  w0,#0
      adrp x8,#0x8046b000
      cset w9,ne
      strb w9,[x8,#0xbc0]              ; *the* only store to 0x8046bbc0

The public modulus lives in .rodata as an ASCII hex string:

    0x149d3641  EBCC0AA7AA6523BD3D49AF3AA6FF3908...   (512 nibbles = 2048 bit)
    0x149d3842  10001                                (public exponent)

Because the flag is raised only on that path, a bug *inside* a handler that needs no
flag is interesting in a different way than a bug that fakes the flag: it gives an
attacker code execution in the programmer process without ever clearing the OSIG gate.
That is what §3 describes, and §7 is explicit about the limits of that.


2. Reverse-engineering setup
----------------------------
The image is ELF64 AArch64 with three PT_LOAD segments. All addresses in this document
are virtual addresses inside the loaded image; `file = va - segment_base + file_offset`:

    +----------+-----------+----------+---------+
    | segment  | file off  | VA base  | size    |
    +----------+-----------+----------+---------+
    | .text    | 0x01000   | 0x14999000 | 0x39000 |
    | .rodata  | 0x3a000   | 0x149d2000 | 0x09000 |
    | .data    | 0x43000   | 0x149de000 | 0x04000 |
    +----------+-----------+----------+---------+

    file = VA - 0x14999000 + 0x01000     (text)
    file = VA - 0x149d2000 + 0x3a000     (rodata)
    file = VA - 0x149de000 + 0x43000     (data)

Runtime globals referenced below:

    +----------+-----------+-----------------------------------------------------+
    | address  | size      | meaning                                             |
    +----------+-----------+-----------------------------------------------------+
    | 0x8046bbb8 | 8       | ModeType (set by <configure ModeType=...>)          |
    | 0x8046bbc0 | 1       | flag1 — write permission                            |
    | 0x8046bbc4 | 4       | auth_type: 1 = intranet, 2 = internet               |
    | 0x8046bbe0 | 1       | EnableFlash (consulted by program/sha256*, not read) |
    | 0x8046bbe8 | 8       | VIP digest table pointer                            |
    | 0x804767b8 | 8       | transfercfg action / timeout                        |
    | 0x149de648 | 1       | flag3 — second gate used by `program`/`move`/…      |
    | 0x149de358 | 8       | stack cookie seed (ships as 0xC0C0C0C0)             |
    +----------+-----------+-----------------------------------------------------+

The dispatch table sits at 0x149d2000, 16 bytes per entry, `{name_ptr, 0, handler, 0}`.
It has 30 entries (`evidence/command_table.txt`).

Everything below came from static analysis of that file; the tooling in `tools/`
reproduces every claim. No device was needed to find the bug. The reachability proof
(§5) is also static; the only thing that needs hardware is running the probe (§6).


3. The bug
----------
### 3.1 Where it is

Handler `read`, entry 0x149a41a4:

    0x149a41a4  sub  sp, sp, #0x160
    0x149a41a8  stp  x29, x30, [sp, #0x110]
    ...
    0x149a41bc  add  x29, sp, #0x110        ; x29 = frame+0x110, frame is 0x160 bytes

The attribute-copy sequence, reached through the `auth_type != 1` branch:

    0x149a433c  adrp x1,#0x149d4000
    0x149a4340  add  x1,x1,#0x73            ; "label"
    0x149a4344  mov  x0,x21
    0x149a4348  bl   0x149a983c            ; attr_lookup(cmd,"label") -> x0
    0x149a434c  cbz  x0,0x149a43d0          ; NULL -> "label cannot be null"
    0x149a4350  mov  x21,x0                 ; x21 = host label pointer
    0x149a4354  bl   0x1499b1c0            ; strlen(host label)
    0x149a4358  cbz  x0,0x149a43d0          ; empty -> same error
    0x149a435c  adrp x0,#0x149d4000
    0x149a4360  add  x0,x0,#0x73            ; x0 = &"label"  (the literal)
    0x149a4364  bl   0x1499b1c0            ; strlen("label") == 5
    0x149a4368  cmp  x0,#0x47
    0x149a436c  b.hi 0x149a43f0            ; dead: 5 <= 0x47, never taken
    0x149a4370  mov  x0,x21                 ; <-- x0 reloaded with the HOST pointer
    0x149a4374  bl   0x1499b1c0            ; n = strlen(host label)
    0x149a4378  add  x1,x0,#1               ; size = n + 1
    0x149a437c  adrp x2,#0x149d3000
    0x149a4380  add  x2,x2,#0x40d            ; "%s"
    0x149a4384  sub  x0,x29,#0x50           ; dst = frame+0xC0  (0xD8-byte buffer)
    0x149a4388  mov  x3,x21                 ; src = host label
    0x149a438c  bl   0x1499b158             ; bounded formatter(dst, n+1, "%s", src)

The intent is visible in the unreachable error path, which formats the over-long value
with the *constant* maximum:

    0x149a43f0  adrp x1,#0x149d4000
    0x149a43f4  add  x1,x1,#0x4a3            ; "partitionName: %s > %d"
    0x149a43f8  mov  w0,#2
    0x149a43fc  mov  x2,x21
    0x149a4400  mov  w3,#0x48                ; the intended cap is 0x48 bytes
    0x149a4404  bl   0x149a7748
    0x149a4408  add  w22,w20,#0x13
    0x149a440c  b    0x149a427c

So the author did write a 0x48-byte bound, and then let the bound-check operand be
clobbered by the value it was meant to check. `strlen("label")` is 5, `0x47` is 71, so
`b.hi` is always false and the guard is dead code. This is a classic
compiler/author confusion between a constant length and a runtime length, and it is
exactly the shape of the old Qualcomm devprg CVEs (CVE-2018-11267 described a malformed
XML command filling memory with 0x20; CVE-2018-11996 described an out-of-bounds access
from a malformed device-programmer command) — except those are pre-SM8450 glass.

### 3.2 What the formatter does with that size

0x1499b158 is a thin wrapper that builds the register save area and jumps to the
formatter core at 0x1499b964. The core copies `min(n, remaining)` bytes and writes a
terminating NUL; it takes the size operand at face value. With `n = strlen(label)` the
copy is exactly as long as the attacker asks, and the NUL goes one byte past it.

Because the destination is `x29-0x50` and the frame is `x29-0x50 … x29+0x50`, the
mapping from label length to overwritten slots is:

    label len   bytes written   reaches
    ---------   -------------   -------------------------------------------
    0x00..0x47  1..0x48         in-bounds only (dst+0x00..0x47)
    0x48        0x49            cookie byte 0
    0x4F        0x50            cookie bytes 0..7  (full 8-byte cookie)
    0x50        0x51            cookie + saved x29 low byte (harmless: ret uses x30)
    0x58        0x59            + saved x30 byte 0
    0x5F        0x60            + saved x30 bytes 0..7  (full LR)
    0x9F        0xA0            LR + saved x28,x24,x23,x22,x21,x20,x19
    0xA0+       0xA1+           past the frame (caller's frame)

Cookie slot: `x29-0x08` = dst+0x48. Saved LR: `x29+0x08` = dst+0x58.

### 3.3 The cookie

    0x149a41c0  adrp x8,#0x149de000
    0x149a41c4  mov  w20,#0x16
    0x149a41cc  movk w20,#0x900,lsl#16
    0x149a41d0  ldr  x8,[x8,#0x358]     ; .data 0x149de358
    0x149a41d4  stur x8,[x29,#-8]       ; frame cookie = seed
    ...
    0x149a42bc  adrp x9,#0x149de000
    0x149a42c0  ldur x8,[x29,#-8]
    0x149a42c4  ldr  x9,[x9,#0x358]
    0x149a42c8  cmp  x9,x8
    0x149a42cc  b.ne 0x149a4608         ; -> 0x149a006c
    0x149a42d0  mov  w0,w20
    0x149a42d4  ldr  x28,[sp,#0x120]
    0x149a42d8  ldp  x20,x19,[sp,#0x150]
    0x149a42dc  ldp  x22,x21,[sp,#0x140]
    0x149a42e0  ldp  x24,x23,[sp,#0x130]
    0x149a42e4  ldp  x29,x30,[sp,#0x110]
    0x149a42e8  add  sp,sp,#0x160
    0x149a42ec  ret

`0x149a006c` is a spin loop, not a panic handler:

    0x149a006c  sub  sp,sp,#0x10
    0x149a0070  mov  w8,#1
    0x149a0074  str  w8,[sp,#0xc]
    0x149a0078  ldr  w8,[sp,#0xc]
    0x149a007c  cbnz w8,0x149a0078      ; ldr/cbnz forever
    0x149a0080  add  sp,sp,#0x10
    0x149a0084  ret

So a cookie mismatch does not reboot the device; it hangs the programmer's command
loop. The USB endpoint stays enumerated and the host sees a silent timeout. Recovery
is a physical power cycle (long-press), which is why the tooling in `tools/` stages the
probe and does not chain it.

Where the seed comes from:

    0x149a1dc8  sub  sp,sp,#0x30
    0x149a1dd8  add  x1,sp,#8
    0x149a1ddc  mov  w0,#0xe              ; service index 0xe
    0x149a1de0  str  xzr,[x29,#0x18]
    0x149a1de4  bl   0x1499db18          ; service table lookup
    0x149a1dec  ldr  x8,[sp,#8]
    0x149a1df0  ldp  x8,x19,[x8]
    0x149a1df8  add  x1,x29,#0x18
    0x149a1dfc  mov  w2,#8
    0x149a1e00  blr  x19                 ; call the provider
    0x149a1e04  cmp  x0,#8
    0x149a1e08  b.ne 0x149a1e28          ; short read -> leave the seeded value
    0x149a1e0c  ldr  x8,[x29,#0x18]
    0x149a1e10  adrp x9,#0x149de000
    0x149a1e14  str  x8,[x9,#0x358]      ; overwrite the .data seed

Service 0xe is provided by the boot chain (XBL / TZ) through the table the EDL
programmer is handed at 0x80404630 (0x41 slots, 8 bytes each). If that call fails or
returns fewer than 8 bytes, the .data value stays at its factory default, which is in
the image:

    .data 0x149de358: c0 c0 c0 c0 00 00 00 00   => 0x00000000c0c0c0c0

That is the pivot for exploitation: on a unit where the TZ call does not happen, the
cookie is a *constant that ships in the firmware*. On a unit where it does happen, the
cookie is 8 bytes of entropy the attacker has not observed, and this overflow is a
denial-of-service primitive, not a control-flow primitive — unless a leak is found
first. §6 describes how to tell which kind of unit you are on without guessing.


4. Reaching the copy
--------------------
### 4.1 The gate on `read`

    0x149a41dc  bl   0x149aabc4        ; flag1 getter
    0x149a41e4  tst  w0,#0xff
    0x149a41e8  b.ne 0x149a420c        ; flag1 != 0 -> proceed
    0x149a41ec  ldr  x8,[x24,#0xbb8]   ; ModeType
    0x149a41f0  cmp  x8,#5
    0x149a41f4  b.eq 0x149a420c        ; ModeType == 5 -> proceed
    0x149a41f8  ...                    ; "in read back mode, can not write"
    0x149a4208  b    0x149a42bc

So `read` is reachable with `flag1 == 0` as long as `ModeType == 5`. `<configure>` is in
the "not gated" column of the dispatch table and writes ModeType without touching any
permission byte:

    0x149aa2d0  str  w3,[x21]          ; ModeType parse -> caller's slot
    ...
    ModeType is stored to 0x8046bbb8 by the configure path

### 4.2 The gate on the copy

After the block-IO lookup succeeds, control lands on 0x149a42f0:

    0x149a42f0  stp  xzr,xzr,[sp,#0x40]
    0x149a42f4  bl   0x149aac04        ; auth_type  (0x8046bbc4)
    0x149a42f8  cmp  w0,#1
    0x149a42fc  b.ne 0x149a433c        ; auth_type != 1 -> label copy
    0x149a4300  ...                    ; auth_type == 1: "in oplus", different path
    0x149a430c  bl   0x149a7748
    0x149a4310  ...
    0x149a4338  b    0x149a4270

`auth_type` is set in exactly one place, the verify success path (0x149a28e8), and it
holds 1 for an intranet (service-centre) authorization and 2 for an internet one. On a
retail device with no verify performed, it is 0, so the `b.ne` is taken and the copy
runs. This is the one precondition that runs *backwards* from the usual intuition:
holding a real OSIG signature would send you down the OTHER branch and skip the
overflow entirely.

The remaining precondition is the block-IO setup itself. `read` calls 0x149a52d8, which
validates `SECTOR_SIZE_IN_BYTES` (0x149d6c0c), `num_partition_sectors` (0x149d6c48) and
`start_sector` (0x149d66c0), resolves the LUN to a block handle, and only returns 0 (the
value the `cbz` at 0x149a426c needs) when that handle opens. In practice LUN 0 on UFS
satisfies it. Note that `EnableFlash` (0x8046bbe0) is consulted by `program` and by
`sha256final`/`sha256init` (call sites 0x149a4060 and 0x149a3c70/0x149a3ca0, all inside
other handlers) — **not** by `read`; the copy path has no EnableFlash dependency.

### 4.3 Minimal unauthenticated trigger

    <?xml version="1.0" ?>
    <data>
      <configure MemoryName="ufs" ModeType="5" Verbose="0" AlwaysValidate="0"
                 EnableFlash="1" MaxDigestTableSizeInBytes="8192"
                 MaxPayloadSizeToTargetInBytes="1048576" ZlpAwareHost="1"
                 SkipStorageInit="0" />
      <read SECTOR_SIZE_IN_BYTES="512" num_partition_sectors="1"
            physical_partition_number="0" start_sector="0" label="AAAA…" />
    </data>

No digest file, no `<verify>`, no `getsigndata` is required for the copy. `read` needs a
`physical_partition_number` that resolves to an openable block device — LUN 0 works on
UFS, and a failed lookup at 0x149a4254 exits before the copy. `EnableFlash="1"` in the
configure above is harmless but not required for this path (§4.2).

Sector attributes are validated before the copy:

    0x149abb6c  ... "SECTOR_SIZE_IN_BYTES"   (0x149d6c0c)
    ...         "num_partition_sectors"      (0x149d6c48)
    ...         "start_sector"               (0x149d66c0)

so the copy itself does not depend on a sector-sized overflow; the payload is the
`label` string and only the `label` string.

### 4.4 Call graph summary

    dispatch loop (0x149a1fc0)
      -> strcmp against table name
      -> blr handler            (0x149a2024)
         read handler 0x149a41a4
           flag1 OR ModeType==5
           -> blk io open/lookup
           -> auth_type != 1
           -> label copy  <-- 0x149a438c

The whole chain is unauthenticated on a retail device.


5. Everything else that was checked (negative results)
------------------------------------------------------
The write gate itself cannot be reached by any of the following:

| Candidate | Location | Result |
|---|---|---|
| `transfercfg timeout_in_sec` 32-bit multiply wrap | 0x149acef0 `mul w4,w8,#0x3e8` | arithmetic only; a wrapped watchdog deadline, no memory write |
| `configure` MaxPayloadSize/MaxXMLSize/Verbose truncation | 0x149aa2a8 `lsr x8,x3,#0x20; cbz` | stores 32 bits; `0x80000000` makes the XML-size comparison go negative and skips a NAK, but the transport buffers are a fixed 0x1000 (0x149a68e8/0x149a6900) and 0x9000 (0x149a6918), and no size is derived from the attribute |
| `program` 1 MiB path | 0x149a58ec..0x149a59e0 | allocation is followed by `cmp x0,#0x100000; b.ne` and `cmp x8,#0x1000,lsl#12; b.lo` before the memcpy; double-checked |
| `program` / `erase` / `patch` / `move` / `fixgpt` / `firmwarewrite` / `programcust` / `erase*` | each entry | every one calls 0x149aabc4 and returns `download is not allowed.` when flag1 is 0. `program`, `move` and `erasebackupgpt` additionally require flag3 (0x149de648), which `<configure EnableFlash="1">` sets |
| `gethealthinfo` | 0x149a5124 | same flag1-or-ModeType5 shape as `read` (0x149a5140 → 0x149a5148 `b.ne`, 0x149a5154 `cmp x8,#5`, 0x149a5158 `b.eq`, both to 0x149a5170). It only returns health data |
| `getsha256digest` / `sha256init` / `sha256final` | 0x149a3a88 etc. | ungated, but every copy length is a literal (0x100, 0x20); no overflow |
| `getstorageinfo` | 0x149a497c | ungated info leak (storage geometry + raw block), no write |
| XML parser | 0x149a9524 / 0x149a973c | tag scan bounded to len-6; attribute table to 0x80 entries × 16 bytes; no overflow |
| log / format strings | ~340 calls to 0x149a7748 | all formats are literals; `%s` arguments are constants or a `csel` between literals; no format-string bug |
| `move` / `fixgpt` GPT arithmetic | 0x149a5b20 | LUN, entry count and LBA are validated before I/O |
| `emmc` / `ufs` provisioning | 0x149a4944 | LUN index bounded (≤ 7) |
| the formatter wrapper itself | 0x1499b158 → 0x1499b964 | honours the size operand; the bug is the operand, not the routine |

The only host-length string copy in the entire image is the `read` label. A scan of all
80 call sites of the formatter (`tools/audit_firehose.py --copies`) shows 4 immediate
sizes, 28 register sizes, and the rest data-dependent but derived from internal state;
`0x149a4378` is the only `strlen(...)+1` in the binary.


6. Diagnostic harness
---------------------
`tools/exploit_label_oob.py` is deliberately staged, because the outcome of the first
two stages decides whether a chain is even worth building.

**Update (2026-11-09):** the chain question is now settled — see
[CHAIN_NOTES.md](CHAIN_NOTES.md) and `tools/flag1_chain.py`. Two hard facts found by
pushing the primitive to its limit:

  * **The one-slot theorem.** The copy is a `%s` copy: its length is `strlen(label)+1`,
    so every byte of the label must be NUL-free, and the formatter contributes exactly
    one extra byte — the NUL terminator at `dst[strlen(label)]`. A 64-bit code pointer
    (`0x00000000_149xxxxx`) therefore cannot appear in the label at all; at most ONE
    slot (saved x30) can be crafted, as `[low 4 bytes][auto NUL][3 original zero
    bytes]` — using the fact that the original saved-x30's high bytes are already zero.
    A chain of gadgets is impossible: every hop needs a full pointer per step.
  * **The canary either kills it or must be bought.** If the cookie is the shipped
    `0x00000000C0C0C0C0`, its high 4 bytes are NULs sitting mid-path: a label can only
    match it by ending inside the canary, so saved x30 is unreachable — on that unit
    the overflow is a crash primitive, full stop. If the cookie is live entropy and
    all-nonzero (P≈96.9%), it is recoverable with the bytewise survive/die oracle in
    `flag1_chain.py --stage oracle` (~128 power cycles per byte on average).

The one construction that survives both facts enters `0x149a2c10`
(`mov w0,#1; bl set_flag1`) with the single crafted slot — the `bl` sets x30 itself, so
`flag1 := 1` without needing a second pointer. It is a one-shot: the verify-tail then
runs on original (unpaintable) stack state and faults within microseconds, and flag1
dies with the session, so no `<program>` can follow it. The full trace, the nine
alternative constructions that were tried and why each fails, and the staged tooling
are in [CHAIN_NOTES.md](CHAIN_NOTES.md).

  * `--stage fingerprint` — sends a label of 0x38 bytes, which stays below the cookie.
    If the session still answers `nop`, the copy path is confirmed reachable and the
    buffer layout assumption is right.

  * `--stage canary` — sends a 0x50-byte label. That writes 0x51 bytes: all eight
    cookie bytes become 0x41 and the NUL lands harmlessly on saved x29's low byte.
    - session answers `nop` afterwards
        => cookie is still 0x00000000c0c0c0c0: the TZ seed call did not run on this
           unit, the cookie is a firmware constant, and a controlled saved-x30 is
           meaningful.
    - session goes silent
        => cookie is live/random; the overflow is a crash primitive. Power-cycle and
           stop.

  * `--stage control --lr ADDR` — only when stage 2 says the cookie is constant.
    Packs `saved x29 = 0`, `saved x30 = ADDR`, and reports the result.

There is no automatic ROP chain. A scan of the whole .text for pivots and useful
sequences (`evidence/gadgets.txt`) finds:

    mov w0,#1 ; ret           22 hits
    mov w0,#1 ; br xN          0 hits
    mov w0,#1 ; blr xN         0 hits
    mov sp,xN ; ret            0 hits
    add sp,xN,#0 ; ret         0 hits
    ldr x30,[sp,#imm] ; ret    0 hits
    mov x0,x1 ; ret            2 hits  (0x149a97ac, 0x149a97dc)

Without a stack pivot, a single overflow cannot stage a chain: the attacker controls
x30, x29 and x19..x28, but not SP, and there is no `mov w0,#1; br xN` to return a
"permission granted" value from a handler and keep the session alive. Any realistic chain
needs (a) the cookie, (b) a stack address, and (c) a pivot that this build does not
contain — i.e. it needs a second, unrelated primitive. The 22 `mov w0,#1 ; ret` gadgets
are still relevant to a different idea (making a *helper* return success), but a helper
return does not raise flag1: that byte has one writer and one caller, and neither is on
a path a return value can steer.

Practical cautions:

  * A wrong cookie or a bad LR hangs the command loop (0x149a006c) — the device stays
    enumerated and looks alive. Recover with a long power-press.
  * Do not run this on a device you cannot physically power-cycle, and do not run it
    during a flash: a hung programmer mid-`program` is exactly the failure mode this
    project is trying to repair on its own unit.


7. Why this is not an OSIG bypass
---------------------------------
It is worth stating plainly, because the two are easy to conflate:

  * `flag1` (0x8046bbc0) is written in exactly one place, 0x149aabd0, which has exactly
    one caller, 0x149a2c14, inside the `<verify>` success path after the RSA-2048 check.
    No XML command, no attribute, and no state reachable through `configure` touches it.
  * The overflow gives code execution in the programmer's own process (subject to §3.3
    and §6), not a forged flag. If it is chained, the natural target is the programmer's
    own globals — including `flag1` — which is what makes it interesting at all: a
    successful chain would set 0x8046bbc0 = 1 without the private key, and then
    `program` would work for the rest of the session.
  * But per §6 the chain needs a second primitive that this build does not appear to
    contain. So the honest summary is: a real, reachable, unauthenticated stack overflow
    in a security-critical component, one step short of the write gate, with the
    remaining distance documented rather than hand-waved.

If someone does finish the chain, the flash map from the bricked PLZ110 unit is:

    abl_a   LUN 4, start 98310,  256 sectors,  image = abl.elf + 0x00 pad
    abl_b   LUN 4, start 458038, 256 sectors,  same image (digest entry sha = 0)
    efisp   LUN 4, start 686694, 768 sectors,  BDS.efi is already correct


8. Vendor notes
---------------
The same programmer contains the OPPO authorization layer in cleartext:

    0x149d35be  "oplus get AUTH_INTRANET"
    0x149d35d8  "oplus get AUTH_INTERNET"
    0x149d3628  "firehose work in %s mode"
    0x149d34f0  "Version:%s; Platform1:%s; Platform2:%s; Mode:%s; Rand:%s; "
                "ProjectWrite:%s; ProjectRead:%s; DigestWrite:%s; DigestRead:%s;"
    0x149d3b5a  "Secure Boot is not enabled on the HW, so no need to check the sign data"

Two things follow from the strings and the code:

  * The `verify` step is an OPPO addition, not a Qualcomm one. Qualcomm's public
    secure-boot documentation describes OEM signatures inside MBN hash segments; the
    `OSIG` envelope, the `AUTH_INTRANET`/`AUTH_INTERNET` split, and the per-project
    `ProjectWrite/DigestWrite` rights are OPPO's own layer on top.
  * The "Secure Boot is not enabled" text corresponds to a code path that exists in the
    image; whether it is reachable is a property of the fuse state, not of the XML.
    On production silicon the RSA check is what runs.

There is no public advisory covering this exact defect. The nearest published issues are
CVE-2018-11267 (malformed XML → OOB buffer write in deviceprogrammer/firehose, SD845
era), CVE-2018-11996 (malformed device-programmer command → OOB access), and
CVE-2024-33016 (invalid firehose `patch` command → memory corruption, no SM8850 in the
CPE list). None of them describes a `read label` length bug, and none lists SM8850.


9. Conclusion
-------------
`<read label="…">` in this SM8850 EDL programmer has a stack buffer overflow with a
fully host-controlled length, reachable with two unauthenticated XML commands. The
bound that the author wrote is dead code because the length register is clobbered
between the check and the copy. The overflow reaches the stack cookie, saved x29 and
saved x30, and the cookie is either a firmware constant (0x00000000c0c0c0c0) or 8 bytes
of boot-chain entropy depending on whether the TZ seed call ran — a question that this
package's `--stage canary` answers in one command.

It does not, by itself, unlock flash writes: `flag1` remains a single-writer variable
behind a 2048-bit RSA check. It is nevertheless a genuine memory-corruption bug in a
component that is loaded before any authorization happens, on a chip family where the
public record currently shows no comparable firehose bug — and the writeup above is
deliberately precise about where the remaining distance is.

Report it. Fix it by loading the label length into a register once and comparing THAT
against 0x48, or by using a fixed-size local and rejecting over-long labels before the
copy.


Appendix A — file map
---------------------
    tools/fhcore.py              ELF mapping, key extraction, live-session plumbing
    tools/audit_firehose.py      gate census, dispatch table, copy-site scan, gadgets
    tools/exploit_label_oob.py   staged overflow harness (fingerprint / canary / control)
    tools/dump_evidence.py       regenerates evidence/ from the binary
    evidence/read_handler_annotated.txt   the overflow path, annotated
    evidence/flag_accessors.txt           every flag reader/writer
    evidence/verify_success_path.txt      the only path that sets flag1
    evidence/command_table.txt            the 30 commands + both RSA moduli
    evidence/gadgets.txt                  pivot/gadget scan results

Appendix B — reproducing the disassembly
----------------------------------------
    pip install capstone
    python tools/audit_firehose.py prog_firehose_ddr.elf --disasm 0x149a433c 0x60
    python tools/audit_firehose.py prog_firehose_ddr.elf --copies
    python tools/audit_firehose.py prog_firehose_ddr.elf --gadgets
    python tools/dump_evidence.py prog_firehose_ddr.elf

The tool prints a sha256 and refuses to pretend the offsets are right if the file does
not match 31ad5664….
