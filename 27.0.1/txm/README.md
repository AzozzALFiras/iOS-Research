# TXM — Code-Signing Monitor (iOS 27.0.1)

TXM ("Code Signing Monitor Image4 Module v7.0.0") is the GL-level monitor that owns code-signing
and executable-mapping (W^X) decisions — the companion to SPTM. Binary:
`Firmware/txm.iphoneos.release.im4p` → arm64e, stripped, ~301 KB text, 1604 functions.

This is the first full characterization + 27.0.1→27.2 diff in this project.

## Approach

TXM is built with **`-fbounds-safety`** (wide-pointer idioms, `SoftwareBreakpoint` traps on OOB).
That means classic spatial bugs become a *trap* (DoS), not corruption — so the audit targeted
**logic / trust-decision** bugs (the W^X and code-signing decisions themselves), not buffer OOB.

GL1 entry: a per-trap length-check wrapper `FUN_0x1706867c`; the image4 dispatch `FUN_0x1703d2b8`
(op selector: 1 = pin root, 2 = evaluate trust). Functional surface (from strings): image4 / CMS
manifest evaluation, CoreEntitlements DER, trust caches, nonces, AMFI (can-execute / load-cdhash),
and the **executable-mapping authorization** — the W^X crown jewel.

## Patch-diff (27.0.1 → 27.2): inconclusive, not escalated

~34 changed + 6 inserted functions, all concentrated in one subsystem: a **recursive digest**
("hash of hashes") tree. The worker was restructured from fixed-stride staging to a variable
element-size accumulator (bigger stack buffer, new teardown helpers). It *could* be a staging
stack-overflow fix — **but the string diff shows zero new semantic strings** (only build/date
metadata; all asserts byte-identical), unlike SPTM's clearly `VIOLATION_*`-tagged fixes. Entry to
the digest is via function-pointer/vtable only (no textual caller), so reachability and
attacker-control-of-count are unproven. Classified **refactor / inconclusive** — deliberately **not**
written up as a finding (no manufactured bug).

## Executable-mapping / code-signing cold-audit — SOUND

The best "live" target (W^X enforcement is unchanged 27.0.1↔27.2, so any flaw would be live in
both) was mapped end-to-end:

```
FUN_0x1703af38  GL1 map-perm dispatch (ops 0–5; addr/VA 16KB-align + overflow panics)
  → FUN_0x170308cc  per-page decision: writable ⇒ deny W^X; exec + "validated cache" flag ⇒ allow;
                     else per-page CS_CodeDirectory walk (FUN_0x170460b8)
  → FUN_0x170349d4  the validator: checks has-sig / base==signed-base / size==covered /
                     per-slot coverage; registers uncovered tail; idempotent
  → FUN_0x170460b8  CodeDirectory verifier (BE bswap, version gates, slot < nCodeSlots,
                     codeLimit, hashSize)
```

A plausible bypass — *can an uncovered-tail page be exec-mapped via the "validated cache" flag?* —
was investigated and **refuted**: the per-page frame **type** byte gates it; the CODE path is
entered only for type `0xe`, and a validated region's uncovered tail is retyped to `0x3b`
(via a `CallSupervisor(0)` privileged type write XNU cannot forge), so `if (type != 0xe) → panic`.
The `+0x18` "validated" cache flag is set only by the validator and only applies to covered code.
**No code-signing bypass; enforcement is sound.**

## Device reality

TXM cannot be dynamically tested here: the only on-hand 27.0.1 device is personal/off-limits and
stock (not jailbroken), and the older research phone is pre-SPTM/TXM silicon. TXM work is
**static-only**. A read-only crash-log pull from the connected device (authorized) showed **zero**
SPTM/TXM/Code-Signing-Monitor panics — no observable monitor bug.

## Verdict

TXM fully characterized, diffed, and its W^X/code-signing enforcement cold-audited → **no confirmed
bug; the surface is sound and hardened**, matching the project-wide pattern. The SK/exclaves layer
(`exclavecore_bundle`) is covered separately in [`../exclaves/`](../exclaves/).

## Detailed report

- [`reports/enforcement-audit.md`](reports/enforcement-audit.md) — the full W^X/code-signing chain,
  the uncovered-tail bypass refutation, and the inconclusive digest-refactor diff.
- [`evidence/wx-type-gate.md`](evidence/wx-type-gate.md) — reproduction command + real disasm of the
  `type != 0xe → FUN_0x17039970(0x90)` violation gate in `FUN_0x170308cc` (the bypass refutation,
  verifiable).
