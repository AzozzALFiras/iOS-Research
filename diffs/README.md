# Cross-version diffs — the three-version trajectory (27.0.1 → 27.2 → 27.3β)

This directory holds the **cross-version** analysis: what changed in the monitors, the exclave world,
the kernel, and the media parsers across three consecutive iPhone17,2 builds, and — the valuable part
— which trust-boundary observations are **live across all three**.

| build | version | SPTM | role here |
|---|---|---|---|
| 27.0.1 | 24A446 | `SPTM-820.0.22` | primary target studied (all `27.0.1/<area>/` reports) |
| 27.2 | 24B119 | `SPTM-820.40.24` | current public "fixed" baseline — [`27.0.1-to-27.2/`](27.0.1-to-27.2/) |
| 27.3 beta | 24C5037i | `SPTM-820.60.12` | beta, diffed for "fixed-in-beta ⇒ live-in-public" — [`27.2-to-27.3/`](27.2-to-27.3/) |

Everything here is a **patch-diff of publicly downloadable firmware**, documented the way public
security writeups document already-fixed bugs (to learn the class and the fix). **No live exploitable
bug is confirmed on any surface.** The standout *live-across-all-three* observation is a
defense-in-depth gap (GMMU-TLBI, with public prior art), not a weaponizable 0-day.

Each claim below cites a receipt under [`evidence/`](evidence/) — paste the command, see the same
bytes. See [`methodology/verification-guide.md`](../methodology/verification-guide.md) for the full
how-to.

---

## 1. Version + size trajectory (reproducible)

Measured 2026-11-04 on `kd-app` — full receipt + exact commands:
[`evidence/monitor-sizes-versions.md`](evidence/monitor-sizes-versions.md).

| component (raw payload, bytes) | 27.0.1 | 27.2 | 27.3β | Δ→27.2 | Δ→27.3 |
|---|---:|---:|---:|---:|---:|
| **SPTM** (`sptm.t8140.release.im4p`) | 1,196,064 | 1,212,448 | 1,212,448 | +16 KiB | +0 |
| SPTM version tag | `820.0.22` | `820.40.24` | `820.60.12` | — | — |
| **TXM** (`txm.iphoneos.release.im4p`) | 557,088 | 557,088 | 557,088 | +0 | +0 |
| TXM version tag | `txm-374` | `txm-374` | `txm-374` | — | — |
| **exclavecore bundle** payload | 32,325,632 | 32,555,008 | 32,980,992 | +224 KiB | +416 KiB |
| **kernelcache** fileset | 77,987,840 | 78,315,520 | 79,364,096 | +320 KiB | +1 MiB |

TXM is byte-identical across all three. SPTM steps by version string each build (the 27.2↔27.3 byte
sizes match only by page alignment — the body-diff still shows +1 function; trust the tag).

---

## 2. What changed each step (summary; detail links)

### 27.0.1 → 27.2 — the media + monitor hardening release
*(detail: [`27.0.1-to-27.2/`](27.0.1-to-27.2/) and the `27.0.1/<area>/` reports)*

- **Media memory-safety fixes** (all zero-click, all confirmed-patched, every variant hunt negative):
  ImageIO `TIFFReadPlugin::decodeTileChunky` int-overflow; Model I/O / USD (`Image::allocate`,
  `SdfZipFile::operator++`, `HdMeshUtil::_CountTriangles`, Ptex `Block::SetSize`); CoreMedia
  Dolby-Vision RPU `ue(v)` selector clamp; CoreGraphics `CGPDFShadingType5Init` DeviceN OOB; kernel
  IOSurface register-after-teardown UAF + IOHIDFamily missing-count OOB. →
  [`27.0.1-to-27.2/media.md`](27.0.1-to-27.2/media.md).
- **SPTM** ([`27.0.1/sptm/reports/findings.md`](../27.0.1/sptm/reports/findings.md)): §F5 T8110 DART
  unganged-GAPF race fixed (**the one real GL1-runtime bug**, patched); §F2 `iommu_read_refcnt >
  read_refcnt` consistency panic **added** (defense-in-depth, desync reachability unproven); §F1/§F6
  GMMU/SAPT TLBI completion-verify block **added but DeviceTree-gated-off** on this device (see §4);
  §F3/§F4 NVMe + hibernation = boot-time / DoS-class.

### 27.2 → 27.3 beta — a feature release, no new fix to tracked surfaces
*(detail: [`27.2-to-27.3/`](27.2-to-27.3/))*

- **SPTM**: one new boot-time endpoint `SPTM_FUNCTIONID_REMAP_REGION_RNX` (+ PAPT range-split
  refactor); **no** security patch to any tracked SPTM surface — strings 0/0/3, receipt
  [`evidence/sptm-rnx-endpoint.md`](evidence/sptm-rnx-endpoint.md).
- **Media / userland** (ImageIO/CoreMedia/CoreGraphics/USD): new feature + recompile churn only; the
  27.2 fixes are intact; **no** new parser memory-safety fix.
- **Kernel kexts**: mostly relocation/feature/recompile churn. One confirmable security fix **outside
  the originally-tracked kext set** — `AGXG17P` GPU channel-selection OOB **read** (fixed in 27.3 ⇒
  live in 27.2 **and** 27.0.1); reachability is the open question (likely entitlement-gated GPU
  profiling path, PAC-vtable dispatch hid the caller). Honest open lead, not a confirmed-reachable
  bug. → [`27.2-to-27.3/README.md`](27.2-to-27.3/README.md).
- **Zone / CTRR / RO-zone defensive map**: all five characterized mitigations **SAME** (items 2/4/5
  byte-identical idioms; only VAs shifted).

---

## 3. Persistence findings — the valuable part (live across all three)

Each row is reproducible from the cited receipt. "Status" is the honest verdict.

| finding | repro (receipt) | 27.0.1 | 27.2 | 27.3β | status |
|---|---|---|---|---|---|
| **GMMU-TLBI verify gated OFF** — DeviceTree key `verify-gmmu-tlbis-at-sync` absent on d94ap | [`gmmu-tlbi-devicetree-gating.md`](evidence/gmmu-tlbi-devicetree-gating.md) | absent | absent | absent | **live defense-in-depth gap** (TLBI still issued; verify inert) — inferred race, public prior art → not bounty-novel |
| **RO-zone wall is data-only** — `sprr_pperm_el1` flipped by a plain EL1 `msr`, no GXF gate | [`sprr-ro-wall.md`](evidence/sprr-ro-wall.md) | data-only | data-only | data-only | **by-design boundary** — holds vs data-only R/W, falls to EL1 code-exec (→ PAC+CTRR+SPTM) |
| **proc_task layout** — elem `0xe38`, flags `0x02000001`, zone-id `0x1a`, `task=proc+0x768` | [`proc-task-layout.md`](evidence/proc-task-layout.md) | stable | stable | stable (VA shift) | **stable** — zone-id forgeable under full R/W, blocked at RO wall |
| **SPTM `sptm_retype` / type-lattice W^X** core | [`27.0.1/sptm/`](../27.0.1/sptm/) | hardened | hardened | hardened (sim 0.999) | **hardened** — spatial-safety layer exhaustively checked |
| **AGXG17P GPU channel-index OOB read** (outside original tracked set) | server `kernel_272_vs_273_live_findings.md` | live | live | **fixed** | **real OOB read, reachability pending** (likely entitlement-gated) |

---

## 4. The GMMU-TLBI gating gap, in one paragraph

In 27.2 Apple added an SPTM block that, after issuing the GPU-MMU TLBI during `sptm_retype`, reads the
GPU status register and panics if the flush has not actually completed (completion is async; a bare
`dsb` is insufficient), under a UAT Dekker lock with IRQs masked. But the whole block is wrapped in
`if (DAT_…[0x81] & 1)`, a flag set **only** from the DeviceTree boolean `verify-gmmu-tlbis-at-sync`.
Extracting `DeviceTree.d94ap.im4p` from **all three** IPSWs shows that key is **absent** on iPhone17,2
(while sibling keys `issue-gmmu-tlbis-at-retype` / `tlbi-flushes-smmu` are present) → the verify is
**inert on this device in 27.0.1, 27.2 and 27.3 beta alike**. The underlying async-completion race
(stale writable GPU translation → DMA to a repurposed page) is therefore technically un-mitigated here
across all three — but it is a *high-confidence inference*, not dynamically confirmed, and there is
**public prior art** (cinder27, a different device), so it is classified defense-in-depth, not a
bounty-novel 0-day. Receipt: [`evidence/gmmu-tlbi-devicetree-gating.md`](evidence/gmmu-tlbi-devicetree-gating.md).

---

## Honest bottom line

Across 27.0.1 / 27.2 / 27.3β and every tracked surface, the result is **hardened / already-patched /
defense-in-depth / boot-time**. No live exploitable bug is confirmed. The two things worth carrying
forward are (a) the **GMMU-TLBI DeviceTree gating gap**, live across all three but not novel, and
(b) two honest open leads — the **AGXG17P OOB read** (reachability pending) and the **fg_cred/so_cred
reader-side** data-only lead (see [`STATUS.md`](../STATUS.md)).
</content>
