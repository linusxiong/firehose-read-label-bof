# Lab results — hardware validation of the `<read label>` overflow

Date: 2026-11-09 / 2026-11-10
Device: OnePlus 15T (PLZ110), retail unit, owned by the author
Programmer: `prog_firehose_ddr.elf`, sha256 `31ad5664023af3f9022913272e2c180fde5f658f31c9094ae9ec57c128c59086`
Tooling: `tools/exploit_label_oob.py`, `tools/flag1_chain.py`, `tools/exec_label.py`, `tools/oracle_loop.py`

Everything in this document was confirmed on hardware, not inferred. Where a claim
could not be confirmed, it says so.

---

## 1. Proven on the unit

### 1.1 Reachability of the copy (no authentication)

The full unauthenticated sequence — Sahara upload of the programmer, VIP digest load,
`<configure ModeType="5">`, then `<read … label="…">` — reaches the vulnerable copy at
`0x149a438c`. A label of 0x38 bytes (staying below the canary slot) leaves the session
answering `<nop>` ACKs, confirming the copy path and the buffer-layout assumptions.

### 1.2 The overflow reaches saved x30

A label of 0x5C bytes overwrites the canary slot, saved `x29`, and the low 5 bytes of
saved `x30` (the formatter contributes the NUL at `dst+0x5C`). This was confirmed by
the canary oracle below, which only works if the copy really lands in the canary slot
at `dst+0x48`.

### 1.3 The stack address is a fixed literal — the label is code

The programmer's entry stub pins the stack:

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

The stack is a `.bss` array at `0x149db000`, not a randomized stack. `dst` is therefore
the **same address on every command of every session**.

The region-attribute table (`0x149d23c0`/`0x149d23e0`) maps both `0x149db000` and
`0x149de000` with type `0x22`; the descriptor-selection code at `0x149c7a3c` keeps the
EL1 descriptor, which carries **UXN=1, PXN=0**. The programmer executes at EL1 (it
manipulates `sctlr_el1` in its entry stub), so EL1 fetches from the stack pages are
permitted. UXN only blocks EL0.

Consequences, both confirmed live:

1. **The label is code.** It lands at a known address on an EL1-executable page. No
   ROP chain, no stack pivot, no address leak is needed — write the payload into the
   label, point saved `x30` at `dst`, and the handler's `ret` executes it.
2. **The handler epilogue restores `sp` before `ret`.** `0x149a42e8 add sp,sp,#0x160`
   runs immediately before `0x149a42ec ret`, so when the payload starts, `sp == SP_L`
   — exactly what the dispatcher loop expects. Branching to the resync entry
   `0x149a1f94` (which re-opens the RX buffer and reloads the loop's `x19`/`x20..x23`
   invariants) rejoins the loop as if the handler had returned normally.

### 1.4 Same-session code execution, confirmed

A five-word label payload was executed on the unit:

```
dst+0x00  1f 20 03 d5   nop                     (padding / trim shield)
dst+0x04  20 20 80 52   mov w0, #0x101          (NUL-free "non-zero" for the setter)
dst+0x08  3a 33 ff 97   bl  0x149aabd0           set_flag1(1)
dst+0x0C  …             bl  0x149aabf0           set_flag3(1)
dst+0x10  …             b   0x149a1f94           resync -> dispatcher loop
```

Byte constraint: every label byte must be NUL-free (XML attribute + `strlen`
semantics). `mov w0,#1` encodes `20 00 80 52` and contains a NUL; `mov w0,#0x101` =
`20 20 80 52` is NUL-free and the setter's `cset w9, ne` still stores 1.

Observed on the unit: the payload ran, the dispatcher loop was rejoined, and the
session stayed up. `<program>` stopped answering `download is not allowed` — i.e.
`flag1` was set and **persisted for the session**.

### 1.5 The canary is stable across power cycles

The bytewise oracle (below) recovered the canary as `22 01 01 01 01 01 01 01` and
re-derivation after power cycling returned the same value. One recovery therefore
covers every later attempt on this unit.

## 2. The canary oracle (works, measured)

A label of length `0x48 + i` overwrites canary bytes 0..i-1 and writes one guessed byte
at index i; the cookie check at `0x149a42bc` compares all 8 bytes, but bytes i+1..7
keep their original values. So a probe with a known-correct prefix of length i and
guess G at index i **survives iff byte i == G**.

* Survival = the guess was right.
* Silence = wrong: the CPU parks in the non-returning spin loop `0x149a006c`; USB
  stays enumerated; recovery is a physical power cycle + Sahara re-upload.

Cost: up to 255 probes per byte (0x00 is unprovable — if all 255 nonzero guesses miss,
the byte is NUL and the exec path is dead on that unit). `tools/oracle_loop.py` runs
this unattended across power cycles, resuming from `cookie.bin`; measured throughput on
the bench was roughly one guess per 20-second cycle including the power cycle.

Measured recovery of byte 0 on the test unit: guesses 0x18 through 0x21 missed (each
parking the programmer), guess **0x22 hit**. Bytes 1–7 each hit on the first guess
(0x01). Full canary: `22 01 01 01 01 01 01 01`.

## 3. The blocker on this unit: a raw `0x22` in the canary

The XML parser does **not** entity-decode attribute values (`&quot;` and `&#34;` are
written through literally — both tested), and it does not accept unquoted values.

A raw `0x22` inside the value terminates it. With the canary's first byte being `0x22`,
the quote sits one byte *before* the canary slot would need to be written — the value
ends at `dst+0x47` and saved `x30` at `dst+0x58` is never reached:

| label | parses | canary | reaches x30 |
|---|---|---|---|
| `A*0x48 + c0c0c0c0` (probe) | yes | shipped-constant check only | no |
| `A*0x48 + <cookie>` | **no** (fails at EOF) | — | — |
| `A*0x47 + 0x22` | **yes** | equal (untouched) | **no** |
| `A*0x47 + cookie + b"/>"` | **yes** | equal | **no** |

Attempts tried and measured, all failing at the tail:

```
"...\x22\x01*7JJJJJJJJ\xe0\xde\x9d\x14" />      -> error at 252 (EOF)
"...\x22\x01*7/>"  + body bytes                  -> error at 240
"...\x22\x01*7= \"JJJJJ" + dst + "\" />          -> error at 222 (at the '=')
```

Everything after the quote would have to be legal XML again, and the bytes that must
follow (`01*7`, `J*8`, the little-endian `dst` dword `e0 de 9d 14`) are not:
`\x01` is rejected as an attribute-name byte and `\x9d\x14` is not valid UTF-8.

**Conclusion (structural, not tuning):** with a canary that *starts* with `0x22`, a
single `<read>` can write at most `dst+0x47` and can never reach saved `x30`. On this
unit the overflow is usable as a canary-exact, non-hijacking overwrite; the
code-execution path is fully built and validated up to the quote, and applies as-is on
any unit whose canary does not contain a quote byte.

Ways out, in order of cost:

1. A different handler frame whose canary slot does not sit in front of a
   controllable return address — `program`/`patch` look promising but are themselves
   behind `flag1`.
2. A unit (or programmer build) whose TZ seed service returns a quote-free canary.
3. The vendor's own authorization path (OSIG `<verify>`), which is unaffected by any
   of this.

## 4. What was NOT run on hardware

* `--stage arm` (the full flag1-setting payload) was blocked by the quote, not by
  doubt: the `arm-noflag` variant (exec + resync only) was not exercised either,
  because on this unit the label cannot reach `x30` at all. Every step *up to* the
  quote — reachability, canary slot, oracle, fixed stack address, EL1-executable
  pages — is hardware-confirmed.
* No flash (`<program>`) was performed via the overflow on this unit. The flash flow
  in the tools is the standard digest-checked `program` sequence and was only
  exercised through legitimate read paths.

## 5. Practical cautions

* A wrong canary guess parks the CPU with USB still enumerated — the device *looks*
  alive. Recovery is a long power-press.
* Do not run the oracle on a device you cannot physically power-cycle, and never
  during a flash: a hung programmer mid-`program` is a brick.
* The `transfercfg reboot_type="reset_to_edl"` safety net (ungated handler at
  `0x149a39d4`) makes a timeout re-enter EDL instead of bootlooping; the flash stage
  sets it before touching partitions and clears it before the final reset.
