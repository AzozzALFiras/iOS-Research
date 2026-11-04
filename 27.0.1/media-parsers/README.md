# Media parsers — zero-click decode surface (iOS 27.0.1 static audit)

Before the patch-diff work (see [`../../diffs/`](../../diffs/)), the zero-click image/media decode
surface on 27.0.1 was audited statically — the classic "a message/web page auto-decodes an
attacker file" threat. The honest result: **the current ImageIO/CMPhoto/MediaToolbox stack is
comprehensively hardened.** This note records the *map* of where decoding actually happens, which
is the reusable value.

## Where HEIF/HEIC decoding really lives (the scoping finding)

A common misconception is that ImageIO parses the HEIF container. It does **not** on current iOS:

- **ImageIO** only has thin `HEIFReadPlugin` glue + `_IIO_LoadHEIFSymbols` which `dlopen`s helpers.
  Its own decoders (PNG/JP2/TIFF/WebP/BMP/…) are all guarded (128-bit product checks, division
  checks, `calloc`, high-word masks, per-copy bounds). The classic allocator thunks were mapped.
- The real **HEIF container (ISOBMFF box) parsing** — `ispe/iloc/iinf/ipma/grid`, the classic
  zero-click int-overflow surface — is in **`CMPhoto.framework`** and, below it,
  **`MediaToolbox.framework`** (`_IFFParseByteStreamAndCreateItemInformation` and friends). Decode
  is routed through **XPC** (`iio_xpc_plugin_data_heif_req_cs`) into a separate sandboxed process.

## MediaToolbox ISOBMFF audit — hardened across 5 layers

The real box parser was traced layer by layer:

1. **Atom framing** (in CoreMedia): `_ReadAtomHeader` etc. — offset+8 ≤ limit, 64-bit size checks,
   negative-size reject, uuid/extended-size handled; error strings confirm ("Negative size",
   "past end of parent").
2. **CLAP** (`_IFFItemPropertyApplyPropertiesToDimensions`): exact-division + positivity +
   **clamps clap dims to the original** (the missing-clamp class, here present).
3. **iref** (`_IFFInformationAddItemReference`): count ≥ 1 guard + overflow-safe typed-calloc.
4. **grid**: version/flags gates, rows/cols = byte+1 (≤ 256, re-checked), extent-accum overflow
   check; tiles bounded by #dimg refs; typed-calloc.
5. **iloc**: construction_method validated < 2; extent table = `calloc(count, 0x10)` NULL-checked;
   32-bit-fit guards on offsets/lengths.

**Keystone:** the "calloc-like" allocator is Apple's **`_malloc_type_calloc`** (hardened typed
allocator = checked `count*size`, NULL on overflow). A whole-binary sweep found **0** malloc-style
calls fed by an unchecked multiply/shift. The classic HEIF `count*size → alloc` overflow class is
structurally neutralized.

## CMPhoto

Audited (DNG/DICOM/RAW metadata + HEIF item properties). Two low-confidence **read-only** candidates
remained that would need a device/Corellium to even poke (a JPEG marker-walk and a RAW CLAP
conversion), both gated behind narrow preconditions — not confirmed bugs.

## Upstream-library fuzzing (complementary, low-yield)

libheif / libwebp / libavif / libtiff and a tinygltf harness were fuzzed (libFuzzer+ASAN) as a
differential-to-Apple angle. Result: **0 real crashes** (only decompression-bomb OOMs and
timeouts) — unsurprising, since OSS-Fuzz runs these 24/7. The differential value (does a crash
reach Apple's forked copy?) never triggered.

## Verdict

Current iOS media parsing is hardened across ImageIO + CMPhoto + MediaToolbox: a bounds-checked
atom stream + typed-`calloc` + field-width/dimension clamps. The exploitable bugs that *did* exist
were all in the **27.2 patch-diff** set ([`../../diffs/27.0.1-to-27.2/`](../../diffs/27.0.1-to-27.2/))
and are already fixed.

## Detailed report

- [`reports/heif-decode-map.md`](reports/heif-decode-map.md) — the full HEIF/HEIC decode routing map
  (ImageIO → CMPhoto → MediaToolbox → CoreMedia) and the 5-layer ISOBMFF audit.
