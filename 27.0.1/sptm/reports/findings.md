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
> `SPTM_GMMU_TLBI_fix_gating_gap`.

## F2 — IOMMU read-refcount invariant

27.0.1 `FUN_…dfd44` → 27.2 `FUN_…e0c38` adds `if (read_refcnt[fte+8] < iommu_read_refcnt[fte+5])
PANIC "iommu_read_refcnt > read_refcnt for FTE"`. This is a refcount-desync → IOMMU
use-after-retype / DMA-to-repurposed-page class. **Reachability unproven:** the accounting functions
(`FUN_…d7704` map handler, `FUN_…b7b20` reader) are byte-identical across versions, so if a desync
is reachable it is reachable in *both* — 27.2 only adds the consistency *panic* (downgrades silent
corruption to DoS). We could not statically show the unchanged accounting produces
`iommu_read_refcnt > read_refcnt` (the FTE `+5` byte is union-typed, a trap for the unwary). Needs
dynamic testing.

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
