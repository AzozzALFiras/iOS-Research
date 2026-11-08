# kR/W Dead Paths — iOS 27.0.1

**Build:** 24A446 · **Device:** iPhone 17,2 (A18 Pro, `d94ap`)
**Last updated:** 2026-11-09

---

## Purpose

This directory documents **27 tested-and-eliminated paths** to achieving a kernel Read/Write
primitive on iOS 27.0.1. Every path was investigated through static reverse engineering, on-device
testing, or both — and every one is confirmed dead.

**The goal is to save other researchers time.** Each report explains *why* the path fails, with
evidence, so the next person does not repeat the same work.

### The situation

| Stage | Status |
|---|---|
| **KASLR defeat** | ✅ Solved — timing oracle v4.1, z-score 7.67 ([`kaslr-info-leak.md`](reports/kaslr-info-leak.md)) |
| **kR/W primitive** | ❌ **Unsolved — all 27 known paths dead** |
| Remaining chain | SPRR flip → F2 cross-domain retype → T1 trust-cache forgery → T2 entitlement gate |

KASLR is not the blocker. **kR/W is the sole remaining obstacle** to a full jailbreak chain on
iOS 27.0.1. The Handle Race entry (CVE-2026-112477) provides a dangling IOSurface reference and
spray-reclaim, but converting that to a stable read/write primitive has not been achieved.

---

## Summary table

| # | Path | Category | CVE | Kill mechanism | Evidence |
|---|------|----------|-----|----------------|----------|
| A1 | `mach_port_kobject` | KASLR | — | Apple zeroes `kaddr` for all types | [kaslr-info-leak.md](reports/kaslr-info-leak.md) |
| A2 | `task_info(DYLD_INFO)` | KASLR | — | Returns userspace address | [kaslr-info-leak.md](reports/kaslr-info-leak.md) |
| A3 | IORegistry property scan | KASLR | — | 0 kernel pointers in properties | [kaslr-info-leak.md](reports/kaslr-info-leak.md) |
| A4 | Port space scan | KASLR | — | 241 ports, all addr=0x0 | [kaslr-info-leak.md](reports/kaslr-info-leak.md) |
| A5 | IOSurface `CopyAllValues` | KASLR | — | User-facing properties only | [kaslr-info-leak.md](reports/kaslr-info-leak.md) |
| A6 | decmpfs scanning | KASLR | — | 23 files, 0 leaks | [kaslr-info-leak.md](reports/kaslr-info-leak.md) |
| A7 | IOSurface `GetBaseAddress` | KASLR | — | Conceptual error — returns userspace pixel buffer | [kaslr-info-leak.md](reports/kaslr-info-leak.md) |
| B1 | F1OOB GPU → kernel | GPU | — | DART blocks GPU VA → kernel PA | [gpu-metal.md](reports/gpu-metal.md) |
| B2 | GPU→Kernel R/W via UAT | GPU | — | UAT isolates GPU VA from kernel memory | [gpu-metal.md](reports/gpu-metal.md), [evidence](evidence/gpu-uat-isolation.md) |
| B3 | GPU PTE corruption | GPU | — | Writes to pixel buffer, not DART entries | [gpu-metal.md](reports/gpu-metal.md) |
| B4 | Metal buffer-extension OOB | GPU | — | DART silently discards OOB writes | [gpu-metal.md](reports/gpu-metal.md) |
| C1 | compressionType=3 overflow | IOSurface | — | Kernel rejects all variants (`e00002c2`) | [iosurface-overflow.md](reports/iosurface-overflow.md) |
| C2 | sliceCount tile OOB | IOSurface | — | Kernel clamps `sliceCount=1` | [iosurface-overflow.md](reports/iosurface-overflow.md) |
| D1 | AVE DMA corruption | AVE | — | DART/IOMMU protection + separate zone | [ave-video-encoder.md](reports/ave-video-encoder.md) |
| D2 | AVE OOB v2 | AVE | — | Spray does not reach target zone | [ave-video-encoder.md](reports/ave-video-encoder.md) |
| D3 | MMCO DPB OOB | AVE | CVE-2026-112689 | Binary-confirmed: 2 bounds checks in AppleAVE2 | [ave-video-encoder.md](reports/ave-video-encoder.md) |
| D4 | AVE Temporal kR/W | AVE | CVE-2026-112705 | VT clamps NTL=1 + kernel bounds check | [ave-video-encoder.md](reports/ave-video-encoder.md), [evidence](evidence/ave-vt-gatekeeper.md) |
| E1 | AVC SPS `log2_max_frame_num` | AVC | — | VT validates: `log2_fn>16` → `-12911` | [ave-video-encoder.md](reports/ave-video-encoder.md), [evidence](evidence/ave-vt-gatekeeper.md) |
| E2 | AVC SPS (device-confirmed) | AVC | — | VT: `poc_lsb≥17` → `-12710` | [ave-video-encoder.md](reports/ave-video-encoder.md) |
| F1 | IPC Request Table OOB | IPC | CVE-2026-112507 | Table grows ONCE; freelist prevents race | [ipc-request-table.md](reports/ipc-request-table.md), [evidence](evidence/ipc-table-grow-once.md) |
| F2 | IPC Port Table Write (old) | IPC | — | Same mechanism as F1 | [ipc-request-table.md](reports/ipc-request-table.md) |
| G1 | ANE symbolIndex OOB | ANE | CVE-2026-84494 | Buffer in `aned` daemon, not app | [ane-symbolindex.md](reports/ane-symbolindex.md), [evidence](evidence/ane-sandbox-barrier.md) |
| H1 | SPTM CAS race | SPTM | — | Requires EL2/EL3 or kernel compromise | [sptm-iomfb-misc.md](reports/sptm-iomfb-misc.md) |
| H2 | SAPT bypass | SPTM | — | Requires EL2/EL3 | [sptm-iomfb-misc.md](reports/sptm-iomfb-misc.md) |
| H3 | GMMU TLBI skip | SPTM | — | Requires EL2/EL3 | [sptm-iomfb-misc.md](reports/sptm-iomfb-misc.md) |
| I1 | IOMobileFrameBuffer race | IOMFB | CVE-2026-112459 | No IOMFB kext on A18 Pro — DCP firmware | [sptm-iomfb-misc.md](reports/sptm-iomfb-misc.md) |
| J1 | Handle Race Strategy A | Handle Race | — | Type isolation: `kalloc_data` ≠ `kalloc_type` | [handle-race-strategies.md](reports/handle-race-strategies.md), [evidence](evidence/type-isolation-zones.md) |
| J2 | Handle Race Strategy B | Handle Race | — | No kptrs in serialized properties | [handle-race-strategies.md](reports/handle-race-strategies.md) |
| J3 | Handle Race Strategy C | Handle Race | — | No kptrs via IOKit selectors 0–35 | [handle-race-strategies.md](reports/handle-race-strategies.md) |
| J4 | Handle Race Strategy D | Handle Race | — | 200 race attempts, 0 hits on sel 17 | [handle-race-strategies.md](reports/handle-race-strategies.md) |
| K1 | AGX-RW-iOS-PoC | External | — | Targets iOS 18.6.2 + needs ClearSword KRW | [sptm-iomfb-misc.md](reports/sptm-iomfb-misc.md) |

---

## Reports

| File | Covers | Paths |
|------|--------|-------|
| [`ipc-request-table.md`](reports/ipc-request-table.md) | CVE-2026-112507 IPC port request table OOB | F1, F2 |
| [`ane-symbolindex.md`](reports/ane-symbolindex.md) | CVE-2026-84494 ANE symbolIndex OOB | G1 |
| [`ave-video-encoder.md`](reports/ave-video-encoder.md) | AVE / AVC video paths | D1–D4, E1–E2 |
| [`gpu-metal.md`](reports/gpu-metal.md) | GPU / Metal paths | B1–B4 |
| [`iosurface-overflow.md`](reports/iosurface-overflow.md) | IOSurface overflow arithmetic | C1–C2 |
| [`handle-race-strategies.md`](reports/handle-race-strategies.md) | Handle Race kR/W conversion attempts | J1–J4 |
| [`kaslr-info-leak.md`](reports/kaslr-info-leak.md) | KASLR info leak paths (dead, but KASLR solved) | A1–A7 |
| [`sptm-iomfb-misc.md`](reports/sptm-iomfb-misc.md) | SPTM / IOMFB / external references | H1–H3, I1, K1 |
| [`lessons-learned.md`](reports/lessons-learned.md) | Seven key lessons from 27 failed paths | — |

## Evidence

| File | Claim proved |
|------|-------------|
| [`ipc-table-grow-once.md`](evidence/ipc-table-grow-once.md) | IPC request table grows once; no race window after |
| [`ane-sandbox-barrier.md`](evidence/ane-sandbox-barrier.md) | ANE mutable buffer is in `aned`, not the app |
| [`ave-vt-gatekeeper.md`](evidence/ave-vt-gatekeeper.md) | VT userspace validates bounds before kernel |
| [`type-isolation-zones.md`](evidence/type-isolation-zones.md) | `kalloc_type<IOSurface>` is isolated from `kalloc_data` |
| [`gpu-uat-isolation.md`](evidence/gpu-uat-isolation.md) | UAT prevents GPU access to kernel memory |

---

## Statistics

```
 Dead paths total:           27
 ─────────────────────────────
 KASLR Info Leak:              7   (A1–A7) — dead but KASLR solved via timing oracle
 GPU / Metal:                  4   (B1–B4)
 IOSurface Overflow:           2   (C1–C2)
 AVE / Video Encoder:          4   (D1–D4)
 AVC / Video Codec:            2   (E1–E2)
 IPC / Mach Port:              2   (F1–F2)  ← device-confirmed ×2 + external tool
 ANE / Neural Engine:          1   (G1)     ← device-confirmed 2026-11-09
 SPTM:                         3   (H1–H3)
 Display / IOMFB:              1   (I1)
 Handle Race Strategies:       4   (J1–J4)
 External Reference:           1   (K1)
 ─────────────────────────────
 Device-confirmed dead:       12
 Binary-confirmed dead:        3
 Architecturally impossible:   5
```
