# iOS 27.3 beta (24C5037i) — version landing page

27.3 beta is diffed **against 27.2 (the current public release)** on the "fixed-in-beta ⇒
live-in-public" logic: a security check present in 27.3 but absent in 27.2 points at a bug still live
in 27.2 (and worth confirming against 27.0.1). All static patch-diff; no device.

Measured monitors (receipt [`../diffs/evidence/monitor-sizes-versions.md`](../diffs/evidence/monitor-sizes-versions.md)):
SPTM `820.60.12` (1,212,448 B), TXM `txm-374` (557,088 B, byte-identical to 27.0.1/27.2), exclave
bundle 32,980,992 B (+416 KiB vs 27.2), kernelcache 79,364,096 B (+1 MiB vs 27.2).

## Verdict: feature + recompile release — no new fix to any tracked surface

Full per-area detail: [`../diffs/27.2-to-27.3/`](../diffs/27.2-to-27.3/).

| surface | 27.2 → 27.3β | verdict |
|---|---|---|
| **SPTM** | new boot-time `REMAP_REGION_RNX` endpoint (strings 0→3) + PAPT range-split refactor | **feature, not a fix**; all prior validations preserved; F1–F5 not re-worked |
| **TXM** | byte-identical | no change |
| **Media/userland** (ImageIO/CoreMedia/CoreGraphics/USD) | new ATX decoder + reader-layout ripple + codegen churn | **no** new parser memory-safety fix; 27.2 fixes intact |
| **Kernel kexts (tracked)** | IOSurface/IOHID/AVD = reloc / feature / identical | prior 27.2 fixes intact, not re-touched |
| **Kernel kext (untracked)** | **AGXG17P** GPU channel-index OOB **read** | **real fix** ⇒ live in 27.2 **and** 27.0.1; **reachability pending** (likely entitlement-gated; PAC-vtable hid caller) |
| **Zone / CTRR / RO-zone map** | all five mitigations SAME (items 2/4/5 byte-identical) | hardened, unchanged |

## Persistence findings — still live across all three builds

- **GMMU-TLBI verify still DeviceTree-gated-off** on d94ap (`verify-gmmu-tlbis-at-sync` absent, 0/0/0;
  sibling keys present) → inert here across 27.0.1/27.2/27.3β. Receipt:
  [`../diffs/evidence/gmmu-tlbi-devicetree-gating.md`](../diffs/evidence/gmmu-tlbi-devicetree-gating.md).
- **RO-zone SPRR wall still data-only** (`sprr_pperm_el1` flipped by a plain EL1 `msr`, no GXF gate),
  byte-identical idiom. Receipt: [`../diffs/evidence/sprr-ro-wall.md`](../diffs/evidence/sprr-ro-wall.md).
- **proc_task / zone-id `0x1a` stable** (27.3 address shift only). Receipt:
  [`../diffs/evidence/proc-task-layout.md`](../diffs/evidence/proc-task-layout.md).

## Honest bottom line

A clean negative for the "fixed-in-beta" angle on SPTM/TXM/media — Apple is adding a capability (RNX
region remap), not silently patching a tracked-surface bug. The one confirmable fix (AGXG17P, outside
the originally-tracked kext set) is a genuine OOB read live in the public releases whose bounty value
depends on an unresolved reachability question. See [`../STATUS.md`](../STATUS.md).
</content>
