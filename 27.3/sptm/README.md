# SPTM — Secure Page Table Monitor (iOS 27.3)

Binary: `Firmware/sptm.t8140.release.im4p` → arm64e Mach-O, stripped. 27.3 (24C5037i, a beta seed) =
`SPTM-820.60.12` (1,212,448 B — byte-for-byte the same *size* as 27.2's `SPTM-820.40.24`, but not
identical content). This directory documents what 27.3 changes relative to 27.2, and the honest
finding: **the one new endpoint is a boot-time facility, not a new runtime GL1 attack surface.**

For SPTM architecture (dispatch, Frame Table, retype, the type lattice) see
[`../../27.0.1/sptm/reports/architecture.md`](../../27.0.1/sptm/reports/architecture.md); it is
unchanged in structure across all three builds. The full three-build delta is in
[`../../27.0.1/sptm/reports/three-version-diff.md`](../../27.0.1/sptm/reports/three-version-diff.md).

## Version summary (27.2 → 27.3)

| Area | 27.2 (`820.40.24`) | 27.3 (`820.60.12`) | Assessment |
|---|---|---|---|
| **`REMAP_REGION_RNX` endpoint** | absent | **new** `SPTM_FUNCTIONID_REMAP_REGION_RNX` + `sptm_prepare_region_for_remapping` | **boot-time only**, stage-gated; no runtime surface |
| IOMMU `iommu_read_refcnt` (FTE+5) | present (new in 27.2) | present (carried forward) | defense-in-depth, unchanged |
| T8110 DART unganged-GAPF lock | present (`VIOLATION_T8110_DART_UNGANG_GAPF_RACE`) | present | §F5 stays patched |
| GMMU-TLBI verify (`verify-gmmu-tlbis-at-sync`) | DeviceTree-gated OFF on d94ap | **still gated OFF** on d94ap | inert on this device in all three builds |

Nothing in 27.3 reopens a 27.2 fix, and the one addition is boot-fenced. No live exploitable SPTM
bug was found in 27.3.

## The new endpoint: `SPTM_FUNCTIONID_REMAP_REGION_RNX`

27.3 introduces a region-remapping facility. Three functions make it up, all **gated on the global
bootstrap-stage word `DAT_0xfffffff02710a140`**:

- **`sptm_prepare_region_for_remapping` = `FUN_0xfffffff0270d8004`** — the handler behind
  `SPTM_FUNCTIONID_REMAP_REGION_RNX`. Its first real instruction reads the stage word and
  **panics if bit 7 is set** (`tbnz w9,#0x7 → panic`). Bit 7 flips once early boot completes, so the
  endpoint can only run during boot; a post-boot (GL1-runtime) call faults immediately. It reuses
  the same lattice bound as retype (`type < 0x44`).
- **Coalescer `FUN_0xfffffff0270d853c`** — merges adjacent prepared regions; driven off the same
  region-table cursor (`…105300`) and only reached from PAPT-range boot setup
  (`FUN_0xfffffff0270b2960`, which panics `"Number of supported PAPT ranges has been exhausted"`) and
  the master boot builder `FUN_0xfffffff0270d8a04`.
- **Alias verifier `FUN_0xfffffff0270b638c`** — validates no illegal aliasing of the remapped range;
  stage-gated on **bit 0x10** of the same word.

**Why it is not a new runtime surface.** All 40 callers of `FUN_0xfffffff0270d8004` are the boot
region registrar `FUN_0xfffffff0270b30c0`, each passing a hard-coded firmware region name
(`DeviceTree`, `SPTM-ro`, `SPTM-rx`, `BootKC-rx`, `TXM-*`, `AuxKC-*`, `CL4-*`, `TrustCache`,
`RAMDisk`, `SEPFW`, …). That is a boot sequence, not a GL1-controlled data path, and the handler
self-fences after boot via the bit-7 stage gate. So `REMAP_REGION_RNX` **does not expand the GL1
attack surface** reachable by a compromised XNU.

Full disassembly and the boot-caller list:
[`evidence/remap-region-rnx.md`](evidence/remap-region-rnx.md).

## Carried-forward 27.2 state on this device

- **GMMU-TLBI verify stays inert.** `verify-gmmu-tlbis-at-sync` = 0 on iPhone17,2 / `d94ap` in 27.3
  too (only `issue-gmmu-tlbis-at-retype` = 1), identical to 27.0.1 and 27.2 — evidence:
  [`../../27.0.1/sptm/evidence/gmmu-tlbi-devicetree-gating.md`](../../27.0.1/sptm/evidence/gmmu-tlbi-devicetree-gating.md).
- **§F2 (`iommu_read_refcnt`) and §F5 (T8110 DART lock)** are present and unchanged — the 27.2
  hardening holds in 27.3.

## Scope / honesty

All SPTM findings across 27.0.1 → 27.2 → 27.3 are **patched, defense-in-depth, or boot-time**. No
live, unpatched, GL1-runtime-exploitable SPTM bug was identified on this device. This is a static
analysis of stripped monitor binaries plus DeviceTree strings; the one remaining dynamic question
(GMMU-TLBI async completion) is gated off here and has public prior art.
