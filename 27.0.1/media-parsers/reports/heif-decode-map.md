# Where HEIF/HEIC decoding really happens (27.0.1) — the scoping map

A reusable map of the zero-click image decode path, and the audit result at each layer. The useful
output of the media work is knowing **where to look** — a common mistake is auditing ImageIO for
HEIF container bugs that are not there.

## The routing

```
HEIC/HEIF file (iMessage / Safari / QuickLook / Photos auto-decode)
  → ImageIO            thin HEIFReadPlugin glue + _IIO_LoadHEIFSymbols (dlopens helpers);
                       routes container parse over XPC (string iio_xpc_plugin_data_heif_req_cs)
  → CMPhoto.framework  CMPhotoDecompressionContainerCopyHEIFItemProperties… (item/property model)
  → MediaToolbox.fwk   _FigPictureCollectionCreateFromByteStream
                         → _IFFParseByteStreamAndCreateItemInformation   ← the real ISOBMFF box walker
  → CoreMedia          _ReadAtomHeader / _FigAtomStream* (the byte-level atom framing)
  → VideoToolbox/…     HEVC pixel decode
```

So the classic zero-click int-overflow surface (`ispe/iloc/iinf/ipma/grid` box parsing) is in
**MediaToolbox + CoreMedia**, *not* ImageIO, and runs in a **separate sandboxed (XPC) process**.

## Audit results by layer (all hardened)

### ImageIO's own decoders — guarded
PNG/JP2/TIFF/WebP/BMP/GIF/ASTC decoders: every size/index path is guarded by one of a 128-bit
product check (`SUB168(a*b,8)==0`), a division check (`0x7fffffff/width < count`), `calloc`, a
high-word (`& 0xffffffff00000000`) check, 16-bit truncation, or a per-copy bound. (The one bug that
*was* here — `TIFFReadPlugin::decodeTileChunky` — is the 27.2 patch-diff in
[`../../../diffs/27.0.1-to-27.2/media.md`](../../../diffs/27.0.1-to-27.2/media.md).) ImageIO was
byte-identical 27.0 → 27.0.1; its fixes landed in 27.2.

### MediaToolbox ISOBMFF — hardened across 5 layers
1. **Atom framing** (CoreMedia `_ReadAtomHeader @0x18efcda54`, `_FigAtomStreamAdvanceToNextAtom`):
   `offset+8 ≤ limit`, 64-bit size handling, size==1→extended (`offset+16 ≤ limit`), negative-size
   reject, size ≥ header. Error strings confirm ("Negative size", "past end of parent").
2. **CLAP** `_IFFItemPropertyApplyPropertiesToDimensions @0x1970d0e44`: exact-division + positivity +
   **clamps clap dims to the original** (`origW ≥ newW && origH ≥ newH`).
3. **iref** `_IFFInformationAddItemReference @0x19754a3d4`: count ≥ 1 + overflow-safe typed-calloc.
4. **grid** (`_IFFInformationSetItemBodyImageDerivationGrid @0x1970d1dec`): version/flags gates,
   rows/cols = byte+1 (≤ 256, re-checked), extent-accum add-overflow check; tiles bounded by #dimg.
5. **iloc** `_IFFInformationReserveItemExtentTable @0x19754ae68`: `construction_method < 2`;
   extent table = `calloc(extent_count, 0x10)` NULL-checked; 32-bit-fit guards on offset/length.

**Keystone:** the "calloc-like" allocator is Apple's **`_malloc_type_calloc`** (hardened typed
allocator — checked `count*size`, NULL on overflow). A whole-binary sweep of the parser found **0**
malloc-style calls fed by an unchecked multiply or shift. The classic HEIF `count*size → alloc`
overflow class is structurally neutralized.

### CMPhoto — hardened, two read-only low-confidence candidates
DNG/DICOM/RAW metadata + HEIF item properties audited. Two low-confidence **read-only** candidates
remained (a `_JPEGDecompressSurface` marker walk, a `__convert8bitsRAWTo8BitsReadableFormat` CLAP
conversion), both behind narrow preconditions and needing a device/Corellium even to poke — not
confirmed bugs.

## Residual (dynamic-only)

Static RE hit diminishing returns; the only remaining avenues are dynamic (Corellium): the grid
`out_w*out_h` downstream `CVPixelBuffer`/`IOSurface` allocation (clamped downstream in normal flow),
and the CMPhoto read-only candidates. Logged in [`../../../STATUS.md`](../../../STATUS.md).
