# SPTM — Secure Page Table Monitor (iOS 27.0.1)

SPTM is the highest-privilege software monitor on modern Apple Silicon (runs at **GL2**). It owns
page-table integrity and the physical-page **type** lattice: even a fully compromised XNU kernel
(GL1) can only change a mapping or a page's type by *asking* SPTM, which enforces the invariants.
This directory documents SPTM's architecture, its GL1 attack surface, and a 27.0.1→27.2 diff.

Binary: `Firmware/sptm.t8140.release.im4p` → arm64e Mach-O, stripped. 27.0.1 = `SPTM-820.0.22`
(1,196,064 B); 27.2 = `SPTM-820.40.24` (1,212,448 B).

## Architecture (reconstructed from the stripped binary)

- **GL0/GL1/GL2 model.** Exception vectors at `0xfffffff0270f8000`. GL2 = SPTM; GL1 = XNU/kernel.
- **Dispatch** = a state machine: `state < 0x17`, `event ≤ 0xe`, transition table
  `base + state*0x1e0 + event*0x20`, PAC-authenticated; per-domain endpoint table
  (`endpoint*0x18`, permission bit). 40 `SPTM_FUNCTIONID` endpoints enumerated.
- **Frame Table (FTE).** 16-byte entry per physical page, indexed `(paddr − managed_start) >> 14`
  (16 KiB pages). Layout refined: `+0` word0 (bit0 = in-flight exclusive lock), `+2` type,
  `+4` flags, `+5` iommu_read_refcnt (u8), `+8` read_refcnt (u32), `+0xc` write/exec_refcnt (u32).
- **Retype core** (`sptm_retype`): aligns, checks managed + `type ≤ 0x43`, claims the atomic
  in-flight lock, validates the transition against a 128-bit allowed-transition bitmap in the
  per-type 0x90-byte descriptor (`+0x40/+0x48`), checks owner-domain, then runs a per-type handler.
- **Type policy (data-driven).** 68-entry type-descriptor table (stride 0x90, magic `0xacce55ed`).
  Verified invariants: **W^X** — every →page-table retype zeroes the page via the target type's
  handler, so no attacker stale PTEs survive; owner-domain gating on cross-domain transitions;
  PT-free requires `mapping_refcnt == 0 && nested_refcnt == 0`; link/unlink refcounts are
  overflow/underflow-guarded.
- **Input discipline.** GL1 scalars arrive as `X_U.UNSAFE_VALUE` and are `sanitize_integer`'d +
  `__builtin_*_overflow`-checked before use. CTRR/AMCC hardware lockdown backs the static regions.

See [`sptm_architecture.md`](sptm_architecture.md) for the full evidence-cited write-up (also an
attack-surface enumeration suitable for discussion with Apple — it claims **no** bug).

## 27.0.1 → 27.2 findings (all already patched — documented as a diff, not a 0-day)

Found via a content-anchored function-body diff (534 funcs; 24 with similarity < 0.85) plus a
string-table diff. Severity-ranked:

| # | Area | 27.0.1 state | 27.2 change | Assessment |
|---|---|---|---|---|
| **§2** | **T8110 DART unganged-GAPF race** | unprotected RMW on a shared slice counter, GL1-reachable DART handlers | per-slice lock + panic `0x6000028` | **the one real GL1-runtime bug** (patched) |
| §1 | IOMMU read-refcount invariant | no consistency check | adds `read_refcnt < iommu_read_refcnt → PANIC` | defense-in-depth; desync reachability **unproven** |
| §3/§6 | GMMU-TLBI completion verify + Dekker lock | TLBI issued, completion not verified | verify block + UAT Dekker lock | **DeviceTree-gated OFF on this device** → race live on 27.2 too, but public prior art |
| §4 | hibernation `handoffPageCount` | unbounded in cold-boot restore trampoline | adds bound | boot-time (DoS-class), not a GL1-runtime OOB |
| §5 | NVMe hib latch | — | `enforce_no_hib_latch` 0→1 | minor hardening |

The **GMMU-TLBI gating gap** is the most interesting: in 27.2 the GPU-MMU TLBI is still issued
unconditionally, but the new verification block is wrapped in `if (DAT[0x81] & 1)`, a flag set only
from the DeviceTree key `verify-gmmu-tlbis-at-sync` — which is **absent on iPhone17,2/d94ap in both
IPSWs** (confirmed by extracting `DeviceTree.d94ap.im4p`). So on this device the "fix" is inert and
27.2 behaves like 27.0.1. The underlying async-completion race (stale GPU translation → DMA to a
repurposed page) is strongly supported but **inferred** — it needs dynamic confirmation, and
there is public prior art (cinder27, iPhone19,7/v64sap), so it is likely not bounty-novel.

See [`sptm_vuln_findings.md`](sptm_vuln_findings.md) and [`sptm_verification.md`](sptm_verification.md).

## Fresh hunt (not patch-diff)

Direct audit of the crown-jewel GL1 surfaces on 27.0.1 (DART map/unmap + SID/IOVA validation,
retype + type lattice, PT map/update/PAPT, guest/stage-2) via deep tracing → **no confirmed
post-boot exploitable bug.** Bounds/arithmetic/invariant layer is solid and consistent. The
spatial-safety surface is exhaustively hardened; the confirmable 27.0.1 defect *class* is
concurrency / TLB-coherence / invariant (all patched in 27.2). Settling the live-vs-patched
reachability of the concurrency findings is a **dynamic** question (Corellium), not a static one.
