# 27.2 (24B119) → 27.3 beta (24C5037i) — patch-diff

**Logic:** a security check present in 27.3 beta but **absent** in 27.2 = a bug still **live in the
current public release** (27.2), and worth confirming against 27.0.1. A *new feature* in 27.3 is not
a bug. Static patch-diff only; no PoC. All VAs unslid; structures relocated by content anchor
(cstring xref, `zone_create` immediates, panic strings), never by reusing a prior build's address.

**Result:** 27.3 beta is a **feature + recompile** release. No new security fix lands on any surface
this project tracks (SPTM / TXM / exclaves / media parsers / the IOSurface·IOHID·AVD kexts). One
confirmable fix was found **outside** that set (AGXG17P GPU), live in 27.2 and 27.0.1, with
reachability unresolved.

---

## SPTM — feature (RNX region remap), not a fix

- Diff: 534 → 535 functions (442 unchanged, 92 changed, 1 inserted, 0 deleted). Of the 92 changed,
  ~86 are sim ≥ 0.90 (address-shift relocation + a panic-helper rename `FUN_0xf8abc → FUN_0xf8f08`).
- The whole meaningful delta is **one new endpoint**: `SPTM_FUNCTIONID_REMAP_REGION_RNX`
  (+ `sptm_remap_region_rnx`, `sptm_prepare_region_for_remapping`) — strings 0 (27.2) → 3 (27.3).
  Receipt: [`../evidence/sptm-rnx-endpoint.md`](../evidence/sptm-rnx-endpoint.md).
- The lowest-similarity cluster (`idx184-187` @ `0x270b2960`, sim 0.026–0.266) is the **PAPT
  range-management** refactor: 27.2's monolithic range-lookup+split function is split into a shared
  helper (`0xb2ba8`) so the existing path and the new remap path reuse it — **all 27.2 validations
  preserved** (range-bounds, overflow, 16 KiB alignment, exhaustion cap `< 0x32`). Extract-helper
  refactor, not a missing-check fix.
- Prior §F1–§F5 (27.0.1→27.2) are **not re-worked**: `sptm_retype` `0xedf40 → 0xee378` sim 0.999
  (pure relocation). The DART STE candidate `idx322` (sim 0.763) was checked — all four carveout /
  dead-page assertion strings present in **both** builds; the function *shrank*; panic-helper swap +
  codegen churn, not a fix.
- **Verdict:** clean negative. Apple is **not** silently fixing a 27.2 SPTM memory-safety bug in this
  beta — it is adding a capability. Full analysis: server report `sptm_272_vs_273_live_findings.md`.

## TXM — no change

Byte-identical payload (557,088 B) and tag (`txm-374`) 27.2 and 27.3. See
[`../evidence/monitor-sizes-versions.md`](../evidence/monitor-sizes-versions.md).

## Media / userland parsers — feature + recompile, no new fix

Zero-click surface (ImageIO, CoreMedia, CoreGraphics PDF path, Model I/O USD) diffed from the 27.3
DSC; the 27.2 fixes are all **intact**, and nothing security-shaped is added:

- **ImageIO**: churn is dominated by two non-security events — a new `ReadPluginInitData` init API on
  every reader plugin, a new **ATX texture decoder** (new 27.3 attack surface, not a 27.0.1-live
  question), and an 8-byte reader-object layout growth that ripples through ~45 `CreateReader_*` /
  ~40 `::D0` as pure offset/vtable-slot/line-number churn. `TIFFReadPlugin::{sanityCheck,
  calculateBlockCount,updateTiffStruct}` differ only by the +8 field-offset shift and `__LINE__`
  immediates; the 27.2 widened-`umull` overflow guard is byte-identical.
- **CoreMedia**: all sim < 0.9 funcs are `_OUTLINED_FUNCTION_*`, `.cold.*` error paths, or XPC infra;
  the hot ISOBMFF box parsers are unchanged; the DV-RPU clamp (`cmp w23,#2; b.hi`) persists.
- **CoreGraphics (PDF)**: byte-parallel (identical instruction + `function_starts` counts); every
  changed func is pure adrp/address-literal rebasing; `_CGPDFShadingType5Init` not in the changed set
  (its 27.2 `cmp #0x4; b.hi` guard persists).
- **USD** (`libusd_ms`): toolchain recompile + relocation; all four 27.2 fixes intact.

Full analysis: server report `userland_2701_to_273_live_findings.md`.

## Kernel kexts — one fix, outside the tracked set

Per-kext content-anchored body-diff (server `kernel_272_vs_273_live_findings.md`):

| kext | 27.2→27.3 | verdict |
|---|---|---|
| AppleJPEGDriver | 8.1.7→8.1.8 | NEGATIVE — codegen + logging churn; both bounds checks intact |
| IOSurface | 403.1 | no change (GOT/data-const reloc); 27.2 `+0xf1` UAF fix intact |
| AppleAVD | 995 | `__text` byte-identical |
| IOHIDFamily | 2.0.0 | feature/robustness; prior OOB accessors untouched (still fixed) |
| **AGXG17P** | 363.3 | **security fix @idx2404 — OOB read, LIVE in 27.2 (and 27.0.1)** |
| IOGPUFamily / M2ScalerCSC / H16ANE | — | feature/telemetry + high-churn recompile; no isolable fix |

**AGXG17P idx2404 (honest).** A GPU "vChannel / GTP" C++ virtual method reads a channel-index byte
from an attacker-influenced descriptor (`ldrb w9,[x1,#3]`, range 0–255), gates it **only** by a
64-bit bitmap tested with `1 << (w9 & 63)` (mod-64 aliasing), then does `add x9,base,w9` with the
**full** unmasked `w9` and `ldrb` → OOB read up to ~+191 bytes; the fetched byte then feeds a
secondary index. 27.3 adds the two checks the sibling `bounded_ptr` paths already had: `cmp x9,#0x3f;
b.hi` (clamp primary index to 0–63) and `ldrb w11,[x8,#8]; cmp w9,w11; b.hs` (bound the secondary).
Verified byte-identical vulnerable in **27.0.1 (`@0xfffffff0084f4cfc`)** and **27.2
(`@0xfffffff00850602c`)**, fixed only in 27.3 beta (`@0xfffffff00853221c`).

- **Status:** the fix and the live-in-27.2/27.0.1 status are **solid**. Bounty value hinges on
  **reachability**, which is **unresolved**: this is a GPU channel/profiling path likely gated behind
  GPU-profiling entitlements (Instruments/Metal debugger), and dispatch is via a PAC-signed vtable
  (`blraa`, no plaintext caller) so the `IOUserClient` + `externalMethod` selector was not resolved
  statically. Classified **confirmed OOB read, reachability pending** — an honest open lead, not a
  confirmed-reachable bug. It is outside the kext set this project originally tracked (IOSurface /
  IOHID / AVD), which is why the "no new fix to tracked surfaces" statement still holds.

## Zone / CTRR / RO-zone defensive map — all SAME

The five characterized mitigations are unchanged in 27.3 beta vs the 27.0.1 baseline (server
`mitigation_diff_2702_2703beta.md`): proc_task zone params (receipt
[`../evidence/proc-task-layout.md`](../evidence/proc-task-layout.md)); inlined zone-id metadata
validation (byte-identical); `__DATA_CONST` r-- placement of the zone anchors; SPTM-owned CTRR-D
caching (`mrs ctrr_d_*_el2`, never `msr`); the SPRR-gated RO-zone write wall (receipt
[`../evidence/sprr-ro-wall.md`](../evidence/sprr-ro-wall.md)). Items 2/4/5 are byte-identical
instruction sequences; only global VAs and host-function addresses shifted.

---

## Bottom line

27.3 beta = **adding capability + recompiling**, not patching a 27.2 security bug on any tracked
surface. The one confirmable fix (AGXG17P, outside the tracked set) is a real OOB read live in
27.2/27.0.1 whose severity is pending a reachability answer. This is a clean negative for the
"fixed-in-beta ⇒ live-in-public" angle on SPTM/TXM/media, and it is itself informative.
</content>
