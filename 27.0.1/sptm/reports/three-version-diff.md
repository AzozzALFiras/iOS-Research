# SPTM three-build diff — 820.0.22 → 820.40.24 → 820.60.12

What changed in SPTM across the three studied iOS builds on iPhone17,2 (`d94ap`), and which changes
are real bugs vs. defense-in-depth vs. boot-time. Every row links to the `evidence/` receipt.

| Build | iOS | SPTM version | Size (B) |
|---|---|---|---|
| 24A446 | 27.0.1 | `SPTM-820.0.22` | 1,196,064 |
| 24B119 | 27.2 | `SPTM-820.40.24` | 1,212,448 |
| 24C5037i | 27.3 (beta seed) | `SPTM-820.60.12` | 1,212,448 |

The architecture (GL2 dispatch state machine, Frame Table, retype core, the 0x90-stride type lattice
with magic `0xacce55ed`) is **identical in shape across all three** — see
[`architecture.md`](architecture.md). What moves is accounting, locking, and one boot-time endpoint.

## Step 1 — 27.0.1 → 27.2 (`820.0.22` → `820.40.24`)

This is the big delta (24 functions with body-similarity < 0.85 + a string-table diff). Six changes,
classified in [`findings.md`](findings.md). The two that matter for "what SPTM actually did":

- **§F5 — T8110 DART unganged-GAPF race (the one real GL1-runtime bug).** 27.0.1 claims the DART
  slice owner token with a bare `casab` and no per-slice lock across the dependent RMW
  (`FUN_0xfffffff0270c6dc4` inc / `FUN_0xfffffff0270c8cc0` dec). 27.2 adds a per-slice lock and the
  panic `VIOLATION_T8110_DART_UNGANG_GAPF_RACE` (string **0 → 1**). Genuine concurrency bug,
  **patched**. Evidence: [`../evidence/f5-t8110-dart-gapf.md`](../evidence/f5-t8110-dart-gapf.md).

- **§F2 — IOMMU read-refcount: a new 27.2 *feature*, not a 27.0.1 fix.** The refcount engine
  `iommu_update_page_refcount` goes `FUN_0xfffffff0270e44fc` (27.0.1) → `FUN_0xfffffff0270e5414`
  (27.2). 27.0.1 only touches the word counters at FTE `+8` (`read_refcnt`) and `+0xc` (`wx_refcnt`)
  with word `ldadd`. 27.2 **adds** a byte `ldaddb` on FTE `+5` — a new `iommu_read_refcnt` subset
  counter — and its consistency panic. The `iommu_read_refcnt` string has **0** occurrences in
  27.0.1 and **2** in 27.2: the counter did not exist before, so §F2 guards a 27.2-introduced field,
  i.e. **defense-in-depth, not a patched 27.0.1 bug**. Evidence:
  [`../evidence/f2-iommu-refcount-engine.md`](../evidence/f2-iommu-refcount-engine.md).

- The remaining §F1/§F3/§F4/§F6 changes are the GMMU/SAPT TLBI-verify feature (DeviceTree-gated off
  here — see below), the NVMe-security rewrite, and the hibernation-trust cluster (boot-time,
  DoS-class). None is a live GL1-runtime bug. Detail in [`findings.md`](findings.md).

## Step 2 — 27.2 → 27.3 (`820.40.24` → `820.60.12`)

Much smaller. The headline is **one new endpoint**:

- **`SPTM_FUNCTIONID_REMAP_REGION_RNX` + `sptm_prepare_region_for_remapping`
  (`FUN_0xfffffff0270d8004`)** appears only in 27.3 (strings `REMAP_REGION_RNX` /
  `prepare_region_for_remapping` = 0/0/1 across the three builds). The handler is **bootstrap-stage
  gated** — its first instruction panics if bit 7 of `DAT_0xfffffff02710a140` is set — and every
  caller is the boot region registrar passing fixed firmware-region names (`SPTM-ro`, `BootKC-rx`,
  `TXM-*`, `SEPFW`, …). Plus a coalescer `FUN_0xfffffff0270d853c` and an alias verifier
  `FUN_0xfffffff0270b638c` (stage-gated on bit 0x10). **Boot-time only; no new runtime GL1 surface.**
  Evidence: [`../../../27.3/sptm/evidence/remap-region-rnx.md`](../../../27.3/sptm/evidence/remap-region-rnx.md);
  summary in [`../../../27.3/sptm/README.md`](../../../27.3/sptm/README.md).
- The 27.2 §F2 (`iommu_read_refcnt`) and §F5 (T8110 DART lock) hardening carry forward unchanged.

## The GMMU-TLBI persistence (live across all three)

The 27.2 GPU-MMU TLBI completion-verify block (§F1/§F6) is gated on the DeviceTree key
`verify-gmmu-tlbis-at-sync`. That key is **absent (count 0) on iPhone17,2 / `d94ap` in 27.0.1, 27.2
AND 27.3**, while `issue-gmmu-tlbis-at-retype` = 1 in all three. So the TLBI is issued but the verify
block never runs on this device — the "fix" is **inert across every build studied**, and the GPU-MMU
async-completion behaviour is identical 27.0.1 → 27.3 here. This is the only item that is technically
"live" on the latest build, but it is DeviceTree-gated off, requires dynamic confirmation, and has
public prior art. Evidence:
[`../evidence/gmmu-tlbi-devicetree-gating.md`](../evidence/gmmu-tlbi-devicetree-gating.md).

## Net across the three builds

- **One genuine GL1-runtime bug** in the window: §F5 (T8110 DART), **patched in 27.2**.
- **Everything else** is defense-in-depth (§F2 new counter, NVMe), boot-time (§F4 hibernation,
  §REMAP_REGION_RNX), or DeviceTree-gated-off (§F1/§F6 GMMU-TLBI verify).
- **No live, unpatched, GL1-runtime-exploitable SPTM bug** on iPhone17,2 across 27.0.1 → 27.2 → 27.3.
