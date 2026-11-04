# iOS 27.2 (24B119)

27.2 (released 2026-10-26) is the reference "fixed" build against which 27.0.1 is diffed. Apple's
advisory for 27.2 is heavy on media-parser fixes, which is *why* the 27.0.1 media bugs documented in
[`../diffs/`](../diffs/) were silent in the 27.0→27.0.1 point release — they landed in 27.2.

## Advisory highlights relevant to this research

| Component | 27.2 fixes | Notes |
|---|---|---|
| **ImageIO** | ~11 CVEs | explains why ImageIO was byte-identical 27.0→27.0.1; several credited Mateusz Jurczyk (GPZ/j00ru) |
| **Model I/O** | 7 CVEs (incl. int-overflow → memory corruption) | 3D USD/USDZ zero-click, under-audited |
| **CoreGraphics** | PDF/font OOB write | |
| **CoreMedia** | parsing → arbitrary code execution | the Dolby-Vision RPU fix |
| **Kernel** | 17 CVEs | separate kernelcache-diff track |

## What this directory is for

The 27.2 binaries are kept here only as the diff baseline. The *findings* live in
[`../diffs/`](../diffs/) (confirmed-patched bugs, with before/after) because they are inherently
cross-version. Per-monitor 27.2 changes (SPTM six findings, TXM refactor) are documented in the
respective [`../27.0.1/sptm/`](../27.0.1/sptm/) and [`../27.0.1/txm/`](../27.0.1/txm/) write-ups,
since the point is "what was wrong in 27.0.1 and how 27.2 fixed it".

## Open 27.2-specific checks (not yet run)

- Did 27.2 make the **zone-metadata submap** read-only, or trap `msr sprr_pperm_el1` to GL? That
  would move the kernel credential wall from a *data-only* boundary to a *code-exec* boundary
  (see [`../27.0.1/kernel-zone/`](../27.0.1/kernel-zone/)).
- Map the remaining ImageIO 27.2 CVEs (PSD / KTX / KTX2 / BC decoders).
- Kernelcache UAF/type-confusion CVEs beyond IOSurface/IOHID.
