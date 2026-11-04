# Evidence — SPTM 27.3 beta adds a new boot-time `REMAP_REGION_RNX` endpoint (feature, not a fix)

**Claim.** The only meaningful SPTM change 27.2→27.3 is a **new capability** — a region-remap
endpoint — not a security patch to any tracked surface. Proof it is new: its strings are absent in
27.0.1/27.2 and present (×3) in 27.3.

## (a) Reproduction

```sh
W=~/ios-research/_evidence   # sptm.bin = ipsw img4 im4p extract of Firmware/sptm.t8140.release.im4p
for v in 27.0.1 27.2 27.3; do
  printf "%-8s " "$v"
  strings -a "$W/$v/sptm.bin" | grep -icE 'remap_region_rnx|prepare_region_for_remapping'
done
strings -a "$W/27.3/sptm.bin" | grep -iE 'remap_region_rnx|prepare_region_for_remapping' | sort -u
```

## (b) Output (pulled 2026-11-04)

```
27.0.1   0
27.2     0
27.3     3
# 27.3 strings:
SPTM_FUNCTIONID_REMAP_REGION_RNX
sptm_prepare_region_for_remapping
sptm_remap_region_rnx
```

## (c) Annotation

- 0 → 0 → 3: the endpoint and its two helpers do not exist in the public releases, so any defect in
  them cannot be live in 27.0.1/27.2. This is a clean **negative** for the "fixed-in-beta ⇒
  live-in-public" angle on SPTM.
- The large low-similarity cluster in the 27.2→27.3 SPTM body-diff (PAPT range-management,
  `idx184-187` @ `0x270b2960`, sim 0.026–0.266) is the refactor that **extracts a shared range-split
  helper** so the existing path and the new remap path can both use it — all prior validations
  (range-bounds, overflow, 16 KiB alignment, exhaustion cap `< 0x32`) are preserved. Classic
  extract-helper refactor around a new feature, not a missing-check fix. Full analysis:
  server report `sptm_272_vs_273_live_findings.md`; summarized in [27.2-to-27.3](../27.2-to-27.3/README.md).
- Prior 27.0.1→27.2 findings (F1–F5) are **not re-worked** in 27.3: e.g. `sptm_retype`
  `0xedf40→0xee378` scores sim 0.999 (pure relocation).
</content>
