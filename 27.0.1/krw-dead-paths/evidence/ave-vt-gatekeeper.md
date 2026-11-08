# Evidence: VideoToolbox userspace validates bounds before kernel

**Build:** 24A446 (iPhone 17,2, A18 Pro, `d94ap`)
**Claim:** VideoToolbox (VT) in userspace validates parameter ranges for AVE/AVC before they
reach the kernel. Kernel-side bounds checks (added in 27.2) are defense-in-depth, not the
primary defense.

---

## Reproduction

### AVE Temporal Layers (CVE-2026-112705)

**Method:** Call `VTSessionSetProperty` with `"NumberOfTemporalLayers"` set to values 1–64,
then read back with `VTSessionCopyProperty`.

**Result:**
```
VTSessionSetProperty("NumberOfTemporalLayers", N) for N=1..64:
  Set return value: 0 (kVTPropertyNotSupportedErr = 0 = "accepted")
  VTSessionCopyProperty readback: 1    ← ALWAYS 1, regardless of N
```

VT accepts the set call (returns 0) but **internally clamps** the value to 1 before storing it.
The kernel never sees a value > 1.

**Kernel-side check (present but unnecessary):**
```arm64
; AVE_HEVC_CheckInfo @ VA 0xfffffff00872b100
cmp    w8, #0x9
b.hs   error_path        ; returns -1001 (kIOReturnBadArgument)
```

The kernel check at `0x872b100` would catch values ≥ 9. But VT ensures the kernel only ever
sees the value 1.

### AVC SPS log2_max_frame_num

**Method:** Construct H.264 bitstreams with controlled SPS fields. Use
`CMVideoFormatDescriptionCreateFromH264ParameterSets` to create format descriptions, then
`VTDecompressionSessionCreate` to establish a decode session.

**Result:**
```
log2_max_frame_num_minus4:
  value ≤ 12 (log2_fn ≤ 16):  FmtDesc OK, Session OK
  value ≥ 13 (log2_fn ≥ 17):  Session create failed: -12911

log2_max_pic_order_cnt_lsb_minus4:
  value ≤ 12 (poc_lsb ≤ 16):  FmtDesc OK, Session OK
  value ≥ 13 (poc_lsb ≥ 17):  FmtDesc failed: -12710
```

The H.264 specification maximum for `log2_max_frame_num_minus4` is 12 (i.e. `log2_fn` ≤ 16).
VT enforces this spec limit.

**Kernel-side checks (absent in 27.0.1, added in 27.2):**

27.0.1 AppleAVE2 at VA `0xfffffff00876bb80` (SPS processing path 1):
```arm64
; log2_max_frame_num stored at [x19, #0x268]
; ONLY check: tbnz bit31 (skip if negative/uninitialized) — NOT a range check
; ZERO CMP instructions on value range
```

27.0.1 AppleAVE2 at VA `0xfffffff008805060` (SPS processing path 2):
```arm64
; Same pattern: tbnz bit31 only, ZERO CMP on value range
```

27.2 adds:
```arm64
cmp    w, #4     ; min bound
cmp    w, #16    ; max for frame_num
cmp    w, #17    ; max for poc_lsb
```

The 27.2 checks are the ones described in the CVE advisory and visible in patch-diffs. On
27.0.1, these checks are absent — but VT prevents the values from reaching the kernel anyway.

### MMCO DPB (CVE-2026-112689)

**Binary analysis of AppleAVE2 (27.0.1):**

**Check 1** at VA `0xfffffff00886d0338`:
```arm64
; DPB initialization
cmp    w8, #16                ; num_ref_frames vs AVE_DPB_MAX_SIZE
b.hi   error_0xe00002bc      ; reject if > 16
```

**Check 2** at VA `0xfffffff00886d46f0`:
```arm64
; MMCO type 6 handler
cmp    w2, w8                 ; long_term_frame_idx vs num_ref_frames
b.hs   reject                ; reject if ltfi >= num_ref_frames
```

Since `num_ref_frames ≤ 16` (Check 1) and `m_saEntry` has exactly 16 entries, the maximum
valid `long_term_frame_idx` is 15 — the last valid entry. These are **kernel-side** checks, but
they are enforced on 27.0.1 (they are not new in 27.2).

**Device test:** 14 ltfi values tested: {2, 4, 8, 14, 15, 16, 17, 18, 24, 32, 64, 1024, 8192,
32768}. Results for all: `kwrite=no, corrupt=0x0, kernel survived`. Tested across 8 IPA
versions (v1–v8) to rule out bitstream construction errors.

---

## Annotation

The defense architecture for video encode/decode on iOS 27.0.1 is layered:

```
App → VideoToolbox (userspace) → videocodecd (daemon) → AppleAVE2 (kernel)
           ↑ PRIMARY DEFENSE              ↑ DEFENSE-IN-DEPTH (some present, some added in 27.2)
```

VT validation is comprehensive: it checks spec-defined ranges, clamps values, and rejects
malformed inputs before they leave userspace. The kernel checks (where present) are a second
line. The 27.2 kernel patches add defense-in-depth for cases where VT might miss something, but
on 27.0.1, VT is already blocking all tested attack vectors.

Bypassing VT validation would require a **separate VT vulnerability** — a bug in VideoToolbox's
own SPS/PPS/session-property parsing that lets an out-of-range value through to the kernel. No
such bypass was found during this research.
