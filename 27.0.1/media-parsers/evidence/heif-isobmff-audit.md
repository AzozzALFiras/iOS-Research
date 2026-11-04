# Evidence — HEIF/ISOBMFF decode routing + 5-layer hardening audit (27.0.1)

**Claim.** The zero-click HEIF container parse does **not** live in ImageIO; it is routed over XPC
into `CMPhoto` → `MediaToolbox` (`_IFFParseByteStreamAndCreateItemInformation`) → `CoreMedia` atom
framing. That ISOBMFF path is hardened across five layers (atom-framing bounds, CLAP clamp, iref /
grid / iloc typed `_malloc_type_calloc`), with **0** unchecked-multiply→alloc sites found in a
whole-binary sweep. The exploitable media bugs were all in the **27.2** patch-diff set (owned by the
`diffs/` work), not on the 27.0.1 side documented here.

## Evidence availability (honest, read this first)

The media-parser dylibs are **not present in the 27.0.1 DSC extraction on `kd-app`**, so per-layer
disassembly could **not** be pulled from this binary set. Verified:

```sh
DSC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/dyld_shared_cache_arm64e
ipsw dyld image "$DSC" | grep -E 'Frameworks/(CoreMedia|MediaToolbox)\.framework/'   # -> (empty)
ipsw dyld image "$DSC" | grep -E '/ImageIO\.framework/.*/ImageIO$'                   # -> (empty)
```

Only ImageIO's `imageimporter.appex` and `ImageIOXPCService.xpc` are listed in this cache; the core
`ImageIO`, `CMPhoto`, `MediaToolbox` and `CoreMedia` dylibs were not included in the extraction.
This matches the kernelcache/TXM split: the IOKit and TXM claims in sibling evidence files are
pulled live here; the media claims below are a **recovered map + method** with the exact
reproduction commands to re-pull them against a *full* DSC (the before/after full cache lives under
`diffs/`, owned by the other agent). No media disasm is fabricated in this file.

## The routing map (recovered)

```
HEIC/HEIF file (iMessage / Safari / QuickLook / Photos auto-decode)
  → ImageIO            thin HEIFReadPlugin glue + _IIO_LoadHEIFSymbols (dlopens helpers);
                       routes container parse over XPC  (symbol: iio_xpc_plugin_data_heif_req_cs)
  → CMPhoto.framework  CMPhotoDecompressionContainerCopyHEIFItemProperties… (item/property model)
  → MediaToolbox.fwk   _FigPictureCollectionCreateFromByteStream
                         → _IFFParseByteStreamAndCreateItemInformation   ← the real ISOBMFF box walker
  → CoreMedia          _ReadAtomHeader / _FigAtomStream*  (byte-level atom framing)
  → VideoToolbox/…     HEVC pixel decode
```

Consequence for auditing: the classic zero-click int-overflow surface
(`ispe` / `iloc` / `iinf` / `ipma` / `grid` box parsing) is in **MediaToolbox + CoreMedia**, running
in a **separate sandboxed (XPC) process**, *not* in ImageIO. Auditing ImageIO for HEIF container
bugs is the common mistake this map corrects.

## The 5-layer audit — targets + what to confirm, with repro

All addresses are the full-DSC VAs recovered during the original audit. To re-pull against a full
27.0.1 cache (one holding the framework dylibs), use:

```sh
DSC=<path to a FULL dyld_shared_cache_arm64e>
# disassemble a target function by VA (resolve the subcache automatically):
ipsw dyld disass "$DSC" --vaddr <VA> --count <N>
# or by symbol:
ipsw dyld disass "$DSC" --image MediaToolbox --symbol _IFFParseByteStreamAndCreateItemInformation
```

| # | Layer | Function (VA) | What the disasm must show |
|---|-------|---------------|---------------------------|
| 1 | Atom framing (CoreMedia) | `_ReadAtomHeader @0x18efcda54`, `_FigAtomStreamAdvanceToNextAtom` | `offset+8 ≤ limit`; size==1 → extended `offset+16 ≤ limit`; negative-size reject; strings "Negative size", "past end of parent" |
| 2 | CLAP | `_IFFItemPropertyApplyPropertiesToDimensions @0x1970d0e44` | exact-division + positivity; **clamps clap dims to original** (`origW ≥ newW && origH ≥ newH`) |
| 3 | iref | `_IFFInformationAddItemReference @0x19754a3d4` | `count ≥ 1` guard + overflow-safe typed-calloc |
| 4 | grid | `_IFFInformationSetItemBodyImageDerivationGrid @0x1970d1dec` | version/flags gates; rows/cols = byte+1 (≤ 256, re-checked); extent-accum add-overflow check; tiles bounded by #dimg |
| 5 | iloc | `_IFFInformationReserveItemExtentTable @0x19754ae68` | `construction_method < 2`; extent table `calloc(count, 0x10)` NULL-checked; 32-bit-fit guards on offset/length |

**Keystone to confirm at layers 3–5:** the "calloc-like" allocator is Apple's hardened typed
allocator **`_malloc_type_calloc`** (checked `count * size`, NULL on overflow). The audit's
whole-binary sweep found **0** malloc-style calls fed by an unchecked multiply/shift — the classic
HEIF `count * size → alloc` overflow class is structurally neutralized.

## Residual (honest)

- Static RE of the full cache hit diminishing returns; remaining avenues are dynamic (Corellium):
  the grid `out_w * out_h` downstream `CVPixelBuffer`/`IOSurface` allocation (clamped downstream in
  normal flow), and two low-confidence **read-only** CMPhoto candidates (`_JPEGDecompressSurface`
  marker walk, `__convert8bitsRAWTo8BitsReadableFormat` CLAP conversion), both behind narrow
  preconditions — not confirmed bugs.
- The per-layer disasm blocks are intentionally **not** reproduced here because the dylibs are
  absent from this extraction; this file records the verifiable *targets and commands* so the claims
  can be re-pulled and checked against a full cache rather than asserted.
