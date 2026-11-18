# Coordinated disclosure notes

## What to send

If reporting this to Qualcomm (Product Security) and to the device vendor (OPPO /
OnePlus), include:

* `prog_firehose_ddr.elf` identity: sha256
  `31ad5664023af3f9022913272e2c180fde5f658f31c9094ae9ec57c128c59086`, 295,636 bytes,
  build string `Jul 22 2025 - 15:41:08`, `SM8850_V1.0.05`.
* The affected command: Firehose `<read>`, attribute `label`.
* The control-flow window: `read` handler entry `0x149a41a4`; the copy at `0x149a438c`;
  the dead bound check at `0x149a4368`/`0x149a436c`.
* The claim that matters: the copy size is `strlen(label) + 1` where `label` is fully
  attacker-controlled, into a fixed 0xD8-byte stack buffer.
* Reachability: `<configure ModeType="5">` then `<read label="…">`, unauthenticated
  (no OSIG `<verify>`, no digest table). One extra condition: `auth_type != 1`.
* Impact class: CWE-787 / CWE-121, stack overflow; overwrites stack cookie, saved x29 and
  saved x30. DoS is unconditional (cookie check → non-returning spin at `0x149a006c`);
  control-flow hijack is conditional on the cookie being the firmware constant
  `0x00000000c0c0c0c0` rather than a boot-chain seed.
* A minimal fix description (below).

## Suggested fix

```c
/* before: the bound is computed from the literal, then clobbered */
len = strlen("label");           /* 5 */
if (len > 0x48) goto too_long;   /* dead */
len = strlen(host_label);        /* wrong value, from here on */
snprintf(buf, len + 1, "%s", host_label);

/* after: one length, one check, one copy */
len = strlen(host_label);
if (len + 1 > sizeof(buf))       /* sizeof(buf) == 0xD8 */
    goto too_long;
snprintf(buf, sizeof(buf), "%s", host_label);
```

or reject over-long `label` values in the XML attribute parser before the handler runs.

## Do not

* Do not attach the vendor firmware blob to a public issue. Reference the sha256 and the
  build string; the file is redistributable only under the vendor's terms.
* Do not include the RSA moduli extracted from `.rodata` in a report as if they were
  secrets — they are public keys and print in `evidence/command_table.txt` for
  verification, not disclosure.
* Do not describe this as an "OSIG bypass". It is not; see §7 of the writeup. A report
  that overstates the impact will be closed as invalid.

## Cross-generation lineage

The dead-bound copy is **not specific to the OnePlus 15T / SM8850**. A byte-pattern
scan (`tools/lineage_scan.py`) of OPPO-programmer builds from the same lineage finds
the identical instruction sequence in three SoC generations:

| SoC | programmer | vulnerable copy (VA) |
|---|---|---|
| SM8650 (8 Gen 3) | OPPO SM8650 Chimera V1.0.21 | 0x149a2844 |
| SM8750 (8 Elite) | OPPO SM8750 Chimera V1.0.05 | 0x149a45ac |
| SM8850 (8 Gen 5) | prog_firehose_ddr.elf (PLZ110, sha256 31ad5664…) | 0x149a4368 |

In each: `cmp x0,#0x47` (comparing `strlen("label")`, a constant 5), `b.hi` to the
unreachable error path, then `add x1,x0,#1` / `sub x0,x29,#0x50` — the copy with a
host-controlled size into the fixed stack buffer. Register allocation and literal
addresses differ (independent recompilation); the structure is identical. All three
binaries also carry the OPPO authorization layer strings (`oplus get AUTH_INTRANET`,
`download is not allowed`, `getsigndata`).

Two consequences for the report:

* **Scope.** Every OPPO/OnePlus/realme device whose EDL programmer descends from this
  line (8 Gen 3 through 8 Gen 5 flagships at minimum) ships the same defect.
* **Attribution.** Firehose programmer source is not published on CodeLinaro (checked:
  `firehose` / `devprg` / `sahara` / `programmer` project searches all empty; only
  host-side `qdl` and ABL are public). The `auth_type != 1` branch the copy sits on is
  part of the OPPO modification layer, so the defect is most likely in OPPO's shared
  programmer codebase — but a same-generation non-OPLUS programmer (e.g. a ZTE SM8850
  build) scanned with `tools/lineage_scan.py` would settle baseline-vs-OEM definitively.
  Send the report to both vendors regardless.

## Timeline placeholder

```
YYYY-MM-DD  reported to Qualcomm Product Security (vendor of the programmer)
YYYY-MM-DD  reported to OPPO/OnePlus security
YYYY-MM-DD  public writeup
```
