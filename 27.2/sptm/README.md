# SPTM — Secure Page Table Monitor (iOS 27.2)

Binary: `Firmware/sptm.t8140.release.im4p` → arm64e Mach-O, stripped. 27.2 (24B119) =
`SPTM-820.40.24` (1,212,448 B). This is the "fixed" reference build against which 27.0.1 is diffed.

Per the repo convention ([`../../STRUCTURE.md`](../../STRUCTURE.md)), the SPTM findings are
inherently cross-version (what was wrong/changed in 27.0.1 → how 27.2 behaves), so the detailed
write-ups and receipts live under [`../../27.0.1/sptm/`](../../27.0.1/sptm/). This page is the 27.2
entry point.

## What 27.2 changes in SPTM (vs 27.0.1)

Six changes, severity-ranked and classified in
[`../../27.0.1/sptm/reports/findings.md`](../../27.0.1/sptm/reports/findings.md). The ones that
define 27.2's SPTM behaviour:

- **§F5 — T8110 DART unganged-GAPF race is *fixed* here.** 27.2 adds a per-slice lock and the panic
  `VIOLATION_T8110_DART_UNGANG_GAPF_RACE` (string 0 → 1). This is the patch for the one real
  27.0.1 GL1-runtime bug. Evidence:
  [`../../27.0.1/sptm/evidence/f5-t8110-dart-gapf.md`](../../27.0.1/sptm/evidence/f5-t8110-dart-gapf.md).
- **§F2 — a new IOMMU subset counter is *introduced* here.** 27.2's refcount engine
  `FUN_0xfffffff0270e5414` adds a byte `ldaddb` on FTE `+5` (`iommu_read_refcnt`, 0 → 2 string
  occurrences) plus its consistency panic. This is a new field + guard, i.e. defense-in-depth — not
  a fix for a 27.0.1 defect. Evidence:
  [`../../27.0.1/sptm/evidence/f2-iommu-refcount-engine.md`](../../27.0.1/sptm/evidence/f2-iommu-refcount-engine.md).
- **§F1/§F6 — GMMU-TLBI completion-verify is added but DeviceTree-gated OFF** on iPhone17,2 /
  `d94ap` (`verify-gmmu-tlbis-at-sync` absent). The verify block never runs on this device, so 27.2
  behaves like 27.0.1 here. Evidence:
  [`../../27.0.1/sptm/evidence/gmmu-tlbi-devicetree-gating.md`](../../27.0.1/sptm/evidence/gmmu-tlbi-devicetree-gating.md).
- §F3 (NVMe-security rewrite) and §F4 (hibernation-trust cluster, boot-time/DoS-class) — see
  findings.md.

## Across builds

The full 820.0.22 → 820.40.24 → 820.60.12 progression is in
[`../../27.0.1/sptm/reports/three-version-diff.md`](../../27.0.1/sptm/reports/three-version-diff.md);
the 27.3 delta is in [`../../27.3/sptm/README.md`](../../27.3/sptm/README.md).

(The broader 27.2 advisory context — media parsers, kernel — is in
[`../README.md`](../README.md).)
