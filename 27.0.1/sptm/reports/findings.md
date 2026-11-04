# SPTM 27.0.1 → 27.2 — the six hardening changes, and which is a real bug

Found via a content-anchored function-body diff of SPTM (534 funcs; 24 with similarity < 0.85) plus
a string-table diff, then **independently re-verified** on binaries pulled fresh. All six are
already fixed in 27.2 → none is a 0-day. Documented to learn the bug classes. Severity-ranked; each
entry gives the mechanism and the before/after signal.

## F1 (headline) — `sptm_retype` core: TLB-coherence / TOCTOU window

`sptm_retype` changed `0xece94 → 0xedf40` (+173 insns, sim 0.80). Inside the retype critical
section, 27.2 adds, around the GPU-MMU TLBI: a DAIF interrupt mask, DMB/DSB barriers, a **UAT Dekker
spin-lock** ("UAT Dekker lock acquisition timed out"), and a **TLBI completion verify**
("Failed to verify TLBI", reading a verification register). 27.0.1 issues the GMMU TLBI with **none**
of these.

- **"GMMU" = the GPU MMU (AGX/SGX via UAT)** — proven by strings `/arm-io/sgx`, `gpu-iouat`,
  `IOMMU_ID_UAT`, `perform_gmmu_tlbi_if_needed`, `retype_paddr_will_be_uat_page_table`. The "UAT
  agent" in the Dekker lock is the GPU coprocessor.
- **Mechanism:** retype uses a per-GPU-context *generation* scheme (`reqGen`/`completedGen` bytes
  per asid). 27.0.1 bumps `reqGen`, issues `SysOp_W(0,9,1,2, asid<<0x30)` (GPU-MMU TLBI), `dsb`,
  then bumps `completedGen` — marking completion after a bare `dsb`. 27.2 additionally reads the GPU
  status register and panics if the TLBI is not actually complete (⇒ completion is **async**; `dsb`
  is insufficient), under the Dekker lock with a ~200µs timeout and IRQs masked.
- **Consequence (high-confidence inference, not dynamically confirmed):** a GPU-shared page retyped
  to a page-table / RO type can keep a **stale writable GPU translation** → GPU DMA-write to a
  repurposed page = monitor bypass. GL1 can reach both retype and GPU workload submit.

> ⚠️ **The gating gap.** In 27.2 the TLBI is still issued *unconditionally*; the whole verify block
> is wrapped in `if (DAT_…921e8[0x81] & 1)`, a flag set only from the DeviceTree key
> `verify-gmmu-tlbis-at-sync`. Extracting `DeviceTree.d94ap.im4p` from **both** IPSWs shows that key
> is **absent on iPhone17,2** → the "fix" is inert on this device, so 27.2 behaves like 27.0.1
> here. The underlying race is therefore technically live on 27.2 too — but there is public prior
> art (cinder27, analysed on a different device), so it is likely **not** bounty-novel. Report:
> `SPTM_GMMU_TLBI_fix_gating_gap`. The key is still absent (verify still inert) on this device in
> **27.3** as well — evidence across all three builds:
> [`../evidence/gmmu-tlbi-devicetree-gating.md`](../evidence/gmmu-tlbi-devicetree-gating.md).

## F2 — IOMMU read-refcount invariant — **a 27.2 feature, not a 27.0.1 bug**

27.0.1 `FUN_…dfd44` → 27.2 `FUN_…e0c38` adds `if (read_refcnt[fte+8] < iommu_read_refcnt[fte+5])
PANIC "iommu_read_refcnt > read_refcnt for FTE"`.

**Re-verified conclusion (engine-level):** the `iommu_read_refcnt` field (FTE `+5`) and its invariant
are **new in 27.2**, so §F2 cannot be a patched 27.0.1 defect. The refcount engine
`iommu_update_page_refcount` is `FUN_0xfffffff0270e44fc` in 27.0.1 and `FUN_0xfffffff0270e5414` in
27.2. 27.0.1 touches **only** the word counters at FTE `+8` (`read_refcnt`) and `+0xc` (`wx_refcnt`)
via word `ldadd` — there is no `ldaddb` and no `+5` access anywhere in it. 27.2 **adds** a byte
`ldaddb` on FTE `+5` (`add x11,x0,#0x5 ; ldaddb`). The `iommu_read_refcnt` string count is **0 in
27.0.1** and **2 in 27.2**. So 27.2 introduced the counter *and* its consistency panic together: a
new accounting field plus a guard on it — **defense-in-depth, not a fix for a 27.0.1 bug.** Whatever
desync the panic catches would require dynamic testing on 27.2+, but it has no 27.0.1 analogue
because the field does not exist there. Evidence:
[`../evidence/f2-iommu-refcount-engine.md`](../evidence/f2-iommu-refcount-engine.md).

## F3 — NVMe security subsystem (11-function rewrite)

`0xbc240–0xbf3e0` rewritten (sim 0.026–0.68): `SET_SQ_ENTRY` DMA-target validation +
`VIOLATION_NVME_ILLEGAL_HIBERNATION_QUEUE_LATCH` + `enforce_no_hib_latch` (0 in 27.0.1). A
storage-controller DMA-to-protected-memory / queue-state-confusion-across-hibernate class.

## F4 — hibernation image-trust cluster

`0xea7e0` (handoffPageCount bound moved header→ → hib_header_copy→, a check-vs-use/TOCTOU on the
authenticated copy), `0xe756c` (image1Size bound), `0xea7c8` (phys-range PROHIBITED|DEV_MEM flags),
`0xe2258` (page-align). **Boot-time** (cold-boot restore trampoline), DoS-class — not a GL1-runtime
OOB (reachability-traced: `ea7e0` is `blr`'d directly from the restore trampoline at asm `0x98270`,
not a GL1 dispatch endpoint).

## F5 — T8110 DART unganged-GAPF race — **the one real GL1-runtime bug**

27.0.1 does an **unprotected read-modify-write** on a shared slice counter
(`DAT_…1012d8 +0xe`, inc `FUN_…c6dc4` / dec `FUN_…c8cc0`) from GL1-reachable DART handlers = a TOCTOU
race in DART clock-protection config. 27.2 adds a per-slice lock (`+0x10`, stride `0x10→0x18`) + a
race-detect panic (`VIOLATION_T8110_DART_UNGANG_GAPF_RACE`, string 0→1) + an owner-token RMW guard.
This holds up as a genuine GL1-runtime concurrency bug — **already patched**, and the fix looks
complete (variant hunt found no unpatched cross-variant sibling; GAPF-ungang is T8110-specific HW).
Evidence (the 27.0.1 unprotected `casab` RMW + the string 0→1 diff):
[`../evidence/f5-t8110-dart-gapf.md`](../evidence/f5-t8110-dart-gapf.md).

## F6 — GMMU/SAPT TLBI-verify (broad) + F7 UAT Dekker lock

The SAPT-flush side of the same TLBI-verification feature as F1 (6 funcs), and the standalone UAT
Dekker mutex (SPTM↔coagent UAT race). Coupled to F1; same DeviceTree gating caveat.

## Net

After deep reachability tracing, **§F5 (T8110 DART) is the only finding that is a real GL1-runtime
vulnerability**; the rest are defense-in-depth, boot-time, or (F1/F3) strongly-supported but
inference/dynamic-dependent. All are fixed in 27.2 ⇒ none bounty-eligible. The confirmable 27.0.1
SPTM defect *class* is **concurrency / TLB-coherence / invariant**, not missing-bounds — the
spatial-safety layer is exhaustively hardened (see [`architecture.md`](architecture.md)). The only
road to a genuinely exploitable *unpatched* SPTM bug is fresh hunting of 27.2 + dynamic confirmation
— open-ended, not done.

For how these changes continue into 27.3 (and the one new boot-time endpoint added there), see
[`three-version-diff.md`](three-version-diff.md) and [`../../../27.3/sptm/README.md`](../../../27.3/sptm/README.md).
