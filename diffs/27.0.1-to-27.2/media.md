# Media patch-diffs 27.0.1 → 27.2 — instruction-level before/after (success proofs)

This is the expanded version of the table in [`README.md`](README.md). Each entry follows the
**"proving success"** bar from [`../../methodology/proof-methodology.md`](../../methodology/proof-methodology.md):
reachable input → the defect at instruction level → before/after → variant hunt. All are **already
fixed by Apple in 27.2**; shown to learn the bug class and the fix.

> Addresses are per-binary offsets within each dylib; the normalized body-diff (see
> [`../../methodology/patch-diff-scripts/`](../../methodology/patch-diff-scripts/)) is what flagged
> each pair. The "kept immediate" that survives normalization is the fix.

---

## 1. ImageIO `TIFFReadPlugin::decodeTileChunky` — int-overflow → heap OOB write

**Reachable input:** a TIFF (or the TIFF-encoded EXIF thumbnail inside a JPEG/HEIC) — zero-click via
Messages / Safari / QuickLook / Photos. Attacker controls `ImageWidth`, `ImageLength`, `TileLength`,
and the per-tile `field210`/`field220` (bytes-per-row / rows factors).

**Defect (27.0.1):** the tile buffer size is a **three-factor 32-bit multiply** that feeds `malloc`:

```
size32 = ceil(ImageLength / TileLength) * field210 * field220    ; all 32-bit
buf    = malloc(size32)
...    copy per-tile decoded data into buf                        ; uses the REAL (large) dims
```

With crafted dimensions the 32-bit product wraps to a small value → `malloc` returns an undersized
buffer → the decode copy writes past it = **controlled heap OOB write**.

**Fix (27.2):** widen the product to 64-bit and add a high-word guard. In normalized disasm the pair
scores very low similarity because two things change and both survive normalization:

```
27.0.1:   mul   x8, x9, x10          ; 32-bit-ish product, no overflow check
          ...   bl _malloc

27.2:     umull x8, w9, w10          ; WIDENING 32x32 -> 64
          ...   mul/ umulh with high-word
          lsr   x8, x?, #0x20        ; <-- new: inspect high 32 bits
          cbnz  x8, <bail>           ; <-- new: bail if product doesn't fit 32 bits
          ...   bl _malloc
```

The inserted `lsr #0x20; cbnz` is the kept-immediate signature the diff surfaces. ~CVE-2026-112488.

**Variant hunt (negative):** every sibling tile/strip decoder — `decodeStripPlanar`,
`decodeStripChunky`, `decodeTileSubsampled` — already uses a widening `umull`; WBMP masks its dims
`& 0xffff` *before* multiplying; `JP2GetPalette`'s multiply isn't the allocation size. No unpatched
sibling. → the finding is bounded to this one function.

---

## 2. Model I/O / USD `adobe::usd::Image::allocate(w, h, channels)`

Parser lives in `/usr/lib/usd/libusd_ms.dylib` (Pixar USD, 68 MB). Reachable via a USDZ opened by
QuickLook / AR Quick Look — zero-click.

**Defect (27.0.1):** `w * h * channels` as a 3-factor 32-bit product → undersized heap alloc → OOB
write filling the image. **Fix (27.2):** `umull` + 64-bit + an explicit bound and a negative check:

```
27.2:     umull x1, w<w>, w<h>
          ...   mul  x1, x1, x<channels>
          cmp   x1, #0x100000001        ; <-- new upper bound (kept immediate)
          b.hs  <bail>
          ...                           ; + negative/zero checks
```

~CVE-2026-112565 / 112449. Variant hunt negative (the `Image` family funnels through `allocate()`;
`imageTransformAffine`'s copy loop uses the already-validated size).

Companion USD fixes located the same way:
- **`SdfZipFile::Iterator::operator++`** — USDZ zip walk advanced by `base + next_offset` with **no
  local-header signature check** → OOB read. 27.2 inserts `cmp w8, #0x04034b50 ("PK\x03\x04");
  b.ne <bail>` — the literal `PK\x03\x04` magic is the kept-immediate tell. ~112413.
- **`HdMeshUtil::_CountTriangles`** — per-face triangle count in a **32-bit** accumulator
  (`std::pair<int,bool>`), caller does `count*3` → `VtArray` resize → crafted `faceVertexCounts`
  overflows INT32 → undersized alloc → OOB index write. 27.2 widens the accumulator/return to
  `size_t` (`std::pair<size_t,bool>`) and adds `tbnz w1, #0 → bail` at all 7 call sites (0 before).
  ~112461 / 112486.

---

## 3. CoreMedia `_hevcbridgeParseVDRRPUDataPayload` — Dolby-Vision RPU → OOB

**Reachable input:** a crafted Dolby-Vision HEVC video (Messages/Safari/Photos/QuickLook). The
offending field is decoded as unsigned Exp-Golomb `ue(v)` (`_hevcbridgeUEPullLong`) — attacker-
controlled and unbounded — and later used as a selector/index into a per-element struct.

**Defect (27.0.1):** two code paths consume the field; path 1 is clamped (`cmp w19, #2`), **path 2
(`w23`) is not**, so an out-of-range value reaches `strb w23, [x10, x8]` and is later used as an
index. **Fix (27.2):** add the missing clamp on path 2:

```
27.2:     cmp  w23, #0x2            ; <-- new (kept immediate)
          b.hi loc_...             ; reject > 2 before the store
```

~CVE-2026-112688. Variant hunt negative — only `ParseVDRRPUDataPayload` changed; the DM/HDR
siblings already guard their `ue(v)` indices (`cmp #0xff; b.hs`).

---

## 4. CoreGraphics `CGPDFShadingType5Init` — DeviceN OOB write

**Reachable input:** a PDF with a Type-5 (lattice) shading whose ColorSpace is DeviceN with
`numComponents > 4`. **Defect (27.0.1):** the per-vertex color is written into a **fixed inline
4-`double` array**; a DeviceN space with >4 components writes past it. **Fix (27.2):**

```
27.2:     cmp  x9, #0x4             ; x9 = numComponents (kept immediate)
          b.hi <bail>
          cmp  x10, x9
          b.ne <bail>
```

~CVE-2026-112611 / 112610. Variant hunt negative — Shading Types 4/6 `malloc` from `numComponents`
(dynamic, safe) and were left unchanged; only Type 5 (the fixed inline array) was vulnerable.

---

## 5. Kernel kexts (kext body-diff)

Stripped kexts: aligned by `function_starts` **index** (same starts-count both versions) then
normalized-body diff (`driver272_kext.sh` variant on `__TEXT_EXEC.__text`).

- **IOSurface UAF** — a new "client torn-down" flag at object `+0xf1`. 27.0.1 teardown
  (`@0xfffffff00a38ee04`) sets `+0xf1=1`, unlinks and `kfree`s the client's list nodes; registration
  (`@0xfffffff00a38eb80`) did **not** check it, so a *register-after-teardown* inserts a dangling
  client pointer into the live notification list → **UAF** on a later list walk (reachable from the
  app sandbox). 27.2 adds (+4 insns) `ldrb w, [x21, #0xf1]; tbz; <bail 0xe00002d8>`. Variant hunt
  negative: `+0xf1` is read/written in exactly two sites; the client-node insertion path is the
  sole one, now guarded.
- **IOHIDFamily OOB** — an array at `obj+0x38` indexed by an attacker value without checking the
  count at `obj+0x40`. 27.2 adds `ldr w9,[x20,#0x40]; cmp w8,w9; b.ge <bail>` across ~4 accessors
  (`idx 526/527/672/673`). ~CVE-2026-112507.

---

## Meta-lesson

Five frameworks + two kexts, every bug an integer-overflow / missing-bound / UAF in a
well-understood class, **every one already fixed in 27.2, every variant hunt negative.** The
method is proven and precise; the surface is saturated. This negative-yield result is what drove
the pivot to SPTM / TXM / exclaves / kernel-zone — documented, and also hardened, in
[`../../STATUS.md`](../../STATUS.md).
