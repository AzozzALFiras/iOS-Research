# AVE / AVC Video Encoder & Codec Paths — 6 Dead

**Build:** 24A446 (iPhone 17,2, A18 Pro)
**Evidence:** [`ave-vt-gatekeeper.md`](../evidence/ave-vt-gatekeeper.md)

---

## Overview

Six separate attempts to achieve kR/W through Apple's video encoder (`AppleAVE2`) and video
codec (`AVC` / `HEVC`) subsystems. All dead. The common pattern: **VideoToolbox (VT) userspace
validation blocks malformed parameters before they reach the kernel.**

---

## D1 — AVE DMA corruption

**Idea:** Trigger an integer overflow in AVE's internal buffer-size calculations via extreme
resolution/layer-count parameters, causing DMA writes past the allocated buffer and into
adjacent kernel heap objects.

**Test matrix:** 6 resolution configurations × 4 spray sizes, with both kernel and userspace
canary objects.

| Resolution | Layers | Calculated overflow | Corruption |
|------------|--------|---------------------|------------|
| 3840×2160 | 255 | 0xF845C000 | 0 |
| 3840×2160 | 130 | 0x1148000 | 0 |
| 4096×2160 | 255 | 0x19E40000 | 0 |
| 3840×2160 | 200 | 0x8B820000 | 0 |
| 1920×1080 | 255 | no overflow | — |
| 2048×2048 | 255 | no overflow | — |

**Why dead:** DART (Device Address Resolution Table) / IOMMU protection prevents DMA from
writing outside the mapped region. Additionally, AVE uses a dedicated allocation zone separate
from `kalloc`, so even if DMA corruption occurred, it would not reach attacker-controlled heap
objects.

---

## D2 — AVE OOB Trigger v2 (IOSurface property spray)

**Idea:** Spray IOSurface properties adjacent to AVE's kernel allocation, then trigger an OOB
write via the encode path to corrupt property data.

**Test:** 192 IOSurface properties sprayed (24 surfaces × 8 properties × 4096 bytes). Encode
succeeds with overflow (status=0, callback=YES).

**Why dead:** The OOB targets a different `kalloc` zone than IOSurface property storage. The
spray and the vulnerable buffer are in different heap zones with no overlap. Type isolation
prevents cross-zone corruption.

---

## D3 — MMCO DPB OOB (CVE-2026-112689)

**Idea:** Use H.264 MMCO (Memory Management Control Operation) type 6 to set
`long_term_frame_idx` beyond the DPB (Decoded Picture Buffer) array bounds `m_saEntry[16]`,
achieving an OOB write in the kernel's AVE driver.

**Binary analysis of AppleAVE2 (24A446):**

**Check 1 — DPB initialization** (VA `0xfffffff00886d0338`):
```arm64
; num_ref_frames checked against AVE_DPB_MAX_SIZE (16)
cmp    w8, #16
b.hi   error_0xe00002bc     ; returns error if num_ref_frames > 16
```

**Check 2 — MMCO type 6 handler** (VA `0xfffffff00886d46f0`):
```arm64
; long_term_frame_idx checked against num_ref_frames
cmp    w2, w8               ; w2 = ltfi, w8 = num_ref_frames
b.hs   reject               ; reject if ltfi >= num_ref_frames
```

Since `num_ref_frames ≤ 16` (enforced by Check 1) and `AVE_DPB_MAX_SIZE = 16` (the
`m_saEntry` array size), the maximum valid `long_term_frame_idx` is 15 — the last valid array
entry. **No OOB is possible.**

**Device testing:** 8 IPA versions tested. `ltfi` values tested: {2, 4, 8, 14, 15, 16, 17, 18,
24, 32, 64, 1024, 8192, 32768}. All results: `kwrite=no, corrupt=0x0, kernel survived`.

**Why dead:** Binary-confirmed — two independent bounds checks in AppleAVE2 block all paths.
This is not a runtime mitigation but a compile-time enforcement.

---

## D4 — AVE Temporal kR/W (CVE-2026-112705)

**Idea:** Set `NumberOfTemporalLayers` to a value > 8 via `VTSessionSetProperty`, causing an
OOB write in `AVE_HEVC_CheckInfo`.

**Two independent blocks:**

1. **VideoToolbox userspace clamp:** `VTSessionSetProperty("NumberOfTemporalLayers", N)` returns
   0 (success), but VT internally clamps the value to 1 before passing it to the kernel.
   `VTSessionCopyProperty` always returns 1 regardless of what was set.

2. **Kernel bounds check** in `AVE_HEVC_CheckInfo` at VA `0xfffffff00872b100`:
   ```arm64
   cmp    w8, #0x9
   b.hs   error_path          ; returns -1001 (kIOReturnBadArgument)
   ```
   This is an enforced check with error return, not a compiled-out assert.

**Device test:** NTL values 1–64 all accepted by VT API (set returns 0), but readback = 1 for
all. Encode with NTL=9 survives because the kernel sees 1.

**Why dead:** VT clamps before kernel, and the kernel has its own check. Both must be bypassed
— neither is feasible from the documented API.

---

## E1 — AVC SPS `log2_max_frame_num` OOB

**Idea:** The 27.0.1 AppleAVE2 binary lacks the `CMP w, #4` / `CMP w, #16` / `CMP w, #17`
bounds checks that 27.2 added for `log2_max_frame_num_minus4` and `log2_max_pic_order_cnt_lsb_minus4`.
Without these checks, extreme values could cause undersized allocations leading to OOB.

**Binary evidence (27.0.1):**

At VA `0xfffffff00876bb80` (SPS processing path 1):
- `log2_max_frame_num` stored at `[x19, #0x268]`
- Only check: `tbnz bit31` (skip if negative) — **not** a range check
- Zero `CMP` instructions on value range

At VA `0xfffffff008805060` (SPS processing path 2):
- Same pattern: `tbnz bit31` only, zero `CMP` on value range

**Why dead:** `CMVideoFormatDescriptionCreateFromH264ParameterSets` in VideoToolbox parses the
SPS in **userspace** and validates `log2_max_frame_num` range:

```
log2_fn ≤ 16:  passes (H.264 spec maximum is 16)
log2_fn ≥ 17:  rejected with error -12911 (VTDecompressionSession create failed)
```

The kernel's missing checks are **defense-in-depth** — the VT userspace layer is the real
gatekeeper. Values that would trigger OOB never reach the kernel.

---

## E2 — AVC SPS (device confirmed, v3 test)

**Extension of E1.** Device test on 2026-11-08 confirmed:

```
poc_lsb ≤ 16:  passes
poc_lsb ≥ 17:  rejected with error -12710 (CMVideoFormatDescription creation failed)
```

Both `log2_max_frame_num` and `log2_max_pic_order_cnt_lsb` are validated by VT userspace.

---

## The lesson

**VideoToolbox (VT) is the gatekeeper for all video encode/decode kernel paths.**

Every parameter that reaches `AppleAVE2` in the kernel first passes through VT's userspace
validation layer. VT checks ranges, clamps values, and rejects malformed inputs — often more
strictly than the kernel itself.

The 27.2 AppleAVE2 bounds checks (the ones that appear in patch-diffs and CVE descriptions) are
**defense-in-depth**. They are real hardening, but on 27.0.1, VT already prevents the malicious
values from reaching the kernel.

To exploit an AVE/AVC kernel bug from an app, an attacker would need a **separate VT
vulnerability** — a bug in VideoToolbox's own parsing that lets a malformed value pass through
to the kernel. No such bypass was found.

---

## Related

- Evidence: [`ave-vt-gatekeeper.md`](../evidence/ave-vt-gatekeeper.md)
