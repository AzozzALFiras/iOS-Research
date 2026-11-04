# 27.0.1 → 27.2 patch-diffs

Function-body diffs that locate silently-patched bugs, each reverse-engineered to before/after and
then variant-hunted. **These are all already fixed by Apple in 27.2** — they are documented the way
public security writeups document patched bugs (to learn the bug class and the fix), not as live
exploits. See [`../methodology/`](../methodology/) for the pipeline.

## Confirmed-patched memory-safety bugs

All are zero-click (auto-decoded file) unless noted; all 27.0.1 variant hunts were **negative** (no
unpatched sibling found).

### ImageIO — `TIFFReadPlugin::decodeTileChunky`  (~CVE-2026-112488)
27.0.1 computes the tile-buffer allocation as a **three-factor 32-bit multiply**
`ceil(H/tileLen) * field210 * field220 → malloc` → integer overflow → undersized heap buffer →
OOB write while decoding (reachable via a TIFF/EXIF thumbnail). 27.2 widens the multiply to 64-bit
and adds a high-word guard (`lsr x8,#0x20; cbnz bail`). Variant hunt: all sibling decoders
(`decodeStrip*`, WBMP, JP2 palette) use widening `umull` or mask dims pre-multiply → safe.

### Model I/O / USD (Pixar USD in `/usr/lib/usd/libusd_ms.dylib`)
- **`adobe::usd::Image::allocate(w,h,c)`** (~112565/112449): `w*h*channels` 3-factor 32-bit
  int-overflow → heap OOB write (USDZ/QuickLook/AR). 27.2: `umull` + 64-bit + `cmp #0x100000001`
  bound + neg-check.
- **`SdfZipFile::Iterator::operator++`** (~112413): USDZ zip walk reads the next record by
  base+offset **without** validating the ZIP local-header signature → OOB read. 27.2 adds a
  `PK\x03\x04` sig check.
- **`HdMeshUtil::_CountTriangles`** (~112461/112486): per-face triangle count accumulated in a
  **32-bit** int, then `count*3` → `VtArray` resize → crafted `faceVertexCounts` overflows INT32 →
  undersized alloc → OOB index write. 27.2 widens the accumulator to `size_t` + adds bail guards at
  all 7 call sites. (The *quad* path has the same raw multiply but `_ComputeNumQuads` caps the
  per-face contribution → needs ~1B faces to overflow → not practically reachable → Apple left it.)
- **Ptex `Block::SetSize`**: `1 << log2` dims stored in 16-bit fields with no bound on log2 →
  log2 ≥ 16 overflows the field → Ptex mipmap packer heap overflow. 27.2 rejects log2 ≥ 16.

### CoreMedia — `_hevcbridgeParseVDRRPUDataPayload`  (~CVE-2026-112688)
A Dolby-Vision RPU field decoded as unsigned Exp-Golomb `ue(v)` (attacker-controlled, unbounded) is
used as a selector/index. 27.0.1 clamps one path but not the second (`w23`); 27.2 adds
`cmp w23,#0x2; b.hi` on the missing path. Zero-click via a crafted Dolby-Vision video. Variant hunt
negative (all DV/HDR siblings already guard their `ue(v)` indices).

### CoreGraphics — `CGPDFShadingType5Init`  (~CVE-2026-112611/112610)
DeviceN ColorSpace `numComponents > 4` writes past a **fixed inline 4-double** color array → OOB
write. 27.2 adds `cmp #0x4; b.hi bail`. Variant hunt: Shading Types 4/6 allocate dynamically from
numComponents → safe, left unchanged.

### Kernel kexts
- **IOSurface** — a client "torn-down" flag at `+0xf1`; 27.0.1 lets a client **register after
  teardown**, inserting a dangling pointer into the live notification list → **UAF** on a later
  walk (reachable from the app sandbox). 27.2 rejects an already-torn-down client at registration.
- **IOHIDFamily** — an accessor indexes an array (`obj+0x38`) by an attacker value without checking
  the count (`obj+0x40`) → OOB r/w. 27.2 adds `ldr count; cmp; b.ge bail` across ~4 accessors.
- **AppleAVD** — 10 changed funcs, mostly noise; one plausible write-before-validate reorder
  (low-confidence, unconfirmed).

## Takeaway

The methodology works end-to-end on real current iOS and precisely localizes each fix. But every
one was already patched, and every variant hunt was negative — i.e. the media/kernel surface here is
**saturated and well-combed**. Patch-diff → variant-hunt on this surface is high-skill portfolio
work, **low-yield for a novel (reportable) 0-day**. The honest conclusion drove the later pivot to
the less-combed SPTM / TXM / exclave surfaces (also hardened — see [`../STATUS.md`](../STATUS.md)).
