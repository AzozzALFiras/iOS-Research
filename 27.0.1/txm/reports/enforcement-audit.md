# TXM 27.0.1 — W^X / code-signing enforcement cold-audit (sound)

**Verdict:** sound / hardened. TXM owns the code-signing and executable-mapping (W^X) decisions. Its
enforcement chain is **unchanged 27.0.1 ↔ 27.2**, so any flaw would be *live in both* — which makes
it a high-value audit target. It holds up. A plausible bypass was investigated and **refuted**.

- Binary: `Firmware/txm.iphoneos.release.im4p` → arm64e, stripped, ~301 KB text, 1604 funcs. Build
  27.0.1; TXM `v7.0.0`. Built with **`-fbounds-safety`** → classic OOB = a `SoftwareBreakpoint` trap
  (DoS), so the audit targets **logic/trust** bugs, not buffer OOB.
- GL1 entry: per-trap length-check wrapper `FUN_0x1706867c`; image4 dispatch `FUN_0x1703d2b8`
  (op selector: 1 = pin root, 2 = evaluate trust).

## The executable-mapping / code-signing chain

```
FUN_0x1703af38   GL1 map-perm dispatch (ops 0–5; addr/VA 16KB-align + overflow panics)
  → FUN_0x170308cc   per-page decision:
                       writable           ⇒ deny (W^X)
                       exec + region "validated-cache" flag ([lVar7+0x18] & 1) ⇒ allow (no rehash)
                       else               ⇒ per-page CS_CodeDirectory walk
  → FUN_0x170349d4   the validator: has-sig? base == signed-base? size == covered? per-slot
                       coverage sum? overflow? registers the uncovered tail; idempotent (0x51)
  → FUN_0x170460b8   CodeDirectory verifier: BE bswap, version gates (0x20100/300/500),
                       slot < nCodeSlots (err 0x1213e), codeLimit/hashSize sanity
```

The "validated-cache" flag at region `+0x18` is set **only** by the validator `FUN_0x170349d4`,
after a successful signature verification, and applies only to covered code.

## The bypass hypothesis — and its refutation

**Question:** can an *uncovered-tail* page (the part of a signed region past `codeLimit`) be
exec-mapped via the `+0x18` validated-cache flag, skipping the per-page hash walk?

**Answer: no — refuted.** The value `FUN_0x1703cfd0` returns is a per-page frame-metadata **type**
byte (classifier `FUN_0x17065c58` reads `meta+2` from the managed-frame table
`meta_base + (pa − base) >> 10`, with a carveout binary-search; default `0x1a`). `FUN_0x170308cc`
enters the CODE path **only for type `0xe`**; any other type (including the tail's `0x3b`) hits
`if (iVar4 != 0xe) → FUN_0x17039970(0x90)` = fail-closed **panic**. And the validator
retypes the uncovered tail to `0x3b` via a `CallSupervisor(0)` privileged type write (SVC-gated;
XNU cannot set type `0xe` directly). So in a validated region only the covered pages stay `0xe`;
the tail is `0x3b` and **cannot** be exec-mapped. The `+0x18` cache correctly applies only to
validated code. **No code-signing bypass.**

The gate is disassembled byte-for-byte in
[`../evidence/wx-type-gate.md`](../evidence/wx-type-gate.md): in `FUN_0x170308cc` the type comes
from `bl 0xfffffff01703cfd0`, the switch tests `cmp w19, #0xe` and `b.ne loc_fffffff017030e10`, and
that else-branch is `mov w0, #0x90 ; bl 0xfffffff017039970` (the violation handler, which formats the
monitor-fault string `"[code: 0x%08X | %u]"`). The CODE/exec path is the fall-through reached **only**
when `type == 0xe`.

## Patch-diff (inconclusive, deliberately not escalated)

~34 changed + 6 inserted functions, concentrated in one subsystem: a recursive **digest**
("hash of hashes") tree. The worker `FUN_0x17051324` was restructured from fixed-stride staging to a
variable element-size accumulator (bigger stack buffer + 4 new teardown helpers). This *could* be a
staging stack-overflow fix — **but the string diff shows zero new semantic strings** (only
build/date metadata; all asserts byte-identical), unlike SPTM's `VIOLATION_*`-tagged fixes. Entry to
the digest is via function-pointer/vtable only (no textual caller), so reachability and
attacker-control-of-count are unproven. Classified **refactor / inconclusive** — not written up as a
finding (no manufactured bug). Logged in [`../../../STATUS.md`](../../../STATUS.md).

## Device reality

TXM is **static-only** here: the only on-hand 27.0.1 device is personal/off-limits and stock (not
jailbroken), and the older research phone is pre-SPTM/TXM silicon. An authorized read-only crash-log
pull from the connected device showed **zero** SPTM/TXM/Code-Signing-Monitor panics across 762
reports — no observable monitor bug.
