# Evidence — GMMU-TLBI verification is DeviceTree-gated OFF on iPhone17,2, all three builds

**Claim (the standout live-across-all-three observation).** SPTM's GPU-MMU TLBI *completion-verify*
block (added in 27.2, see SPTM finding [§F1/§F6](../../27.0.1/sptm/reports/findings.md)) is wrapped in
`if (DAT_…[0x81] & 1)`, a flag set only from the DeviceTree boolean key `verify-gmmu-tlbis-at-sync`.
That key is **absent on d94ap (iPhone17,2) in 27.0.1, 27.2 and 27.3 beta** → the verify path is inert
on this device across all three, so 27.2/27.3 behave like 27.0.1 here. The TLBI itself is still
issued unconditionally; only the *async-completion check* is gated off.

## (a) Reproduction

```sh
# on kd-app, per version:
unzip -oq "$IPSW" 'Firmware/all_flash/DeviceTree.d94ap.im4p' -d "$V"
ipsw img4 im4p extract "$V/Firmware/all_flash/DeviceTree.d94ap.im4p" -o "$V/dt.bin"

# is the gating key present?
strings -a "$V/dt.bin" | grep -c 'verify-gmmu-tlbis-at-sync'
# what GMMU/TLBI keys DO exist (control — proves the namespace is present, the key is not)?
strings -a "$V/dt.bin" | grep -iE 'gmmu|tlbi' | sort -u
```

## (b) Output (pulled 2026-11-04)

```
# verify-gmmu-tlbis-at-sync count:
27.0.1 : 0
27.2   : 0
27.3   : 0

# sibling GMMU/TLBI keys that ARE present (27.3 dt.bin, identical set on all three):
issue-gmmu-tlbis-at-retype
tlbi-flushes-smmu
```

## (c) Annotation

- `count = 0` in all three IPSWs is a **negative that is itself the finding**: the 27.2 "fix" (read
  the GPU status register and panic if the GMMU TLBI has not actually completed, under a UAT Dekker
  lock) can never arm on this SoC because the flag it keys off is not in the device's DeviceTree.
- The sibling keys `issue-gmmu-tlbis-at-retype` and `tlbi-flushes-smmu` **are** present → this is not
  a parsing artifact or a stripped tree; the GMMU/TLBI key namespace exists, and Apple simply did not
  ship `verify-gmmu-tlbis-at-sync` for d94ap. That is the precise, falsifiable form of "the verify is
  inert here".
- **Honest status:** the underlying async-completion race (a retyped GPU-shared page keeping a stale
  writable GPU translation → DMA to a repurposed page) is a *high-confidence inference*, not
  dynamically confirmed, and there is **public prior art** (cinder27, analysed on a different device)
  → not bounty-novel. It is classified **defense-in-depth gap / not-confirmed-exploitable**, not a
  live bug. See [SPTM findings §F1](../../27.0.1/sptm/reports/findings.md) and
  [STATUS.md](../../STATUS.md).
</content>
