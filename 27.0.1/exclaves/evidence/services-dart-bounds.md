# Evidence — Services: XnuSharedSegment overflow + DART mapper bounds

Backs finding #6 in [`../README.md`](../README.md).

## Binary / tooling

- Binary: `exclavecore_bundle` → `APP/sharedcache`. On kd-app:
  `/root/ios-research/analysis/exclaves/2701/extracted/APP/sharedcache`. Build 27.0.1.
- Disassembler: `ipsw macho disass -a <vaddr> -c <count>`.
- `XnuSharedSegment` setup `sub_8272f94`; DART mapper entry `sub_851054c`. `segmentID` is a
  dictionary **key**, not a raw array index.

## Claim

The shared-segment and DART-mapping paths bound every XNU-influenced size/offset: (a) `nPages ×
PageSize` is overflow-checked with `umulh` before the product is used; (b) the init range end is
bounded by `nPages`; (c) a DART map's `offset + size` is add-overflow-checked; (d) the IOVA is
bounded below the span size; (e) the mapping end is bounded by `maxOffset`.

## Reproduction

```sh
SHC=/root/ios-research/analysis/exclaves/2701/extracted/APP/sharedcache
ipsw macho disass -a 0x8272fe4 -c 12 $SHC    # (a) nPages*PageSize umulh overflow
ipsw macho disass -a 0x827cd10 -c 16 $SHC    # (b) range-vs-nPages bounds (@0x827cd24/0x827cd38)
ipsw macho disass -a 0x85105c8 -c 10 $SHC    # (c) DART offset+size overflow  (@0x85105d8)
ipsw macho disass -a 0x8512e68 -c 10 $SHC    # (d) DART IOVA < span           (@0x8512e78)
ipsw macho disass -a 0x850e1e8 -c 10 $SHC    # (e) DART end <= maxOffset       (@0x850e1f8)
```

## Disassembly (pulled 27.0.1)

(a) `nPages × PageSize` overflow guard — `sub_8272f94`:

```
0x08272ff0:  umulh x8, x19, x0          ; high 64 bits of nPages(x19) * PageSize(x0)
0x08272ff4:  cmp   xzr, x8
0x08272ff8:  b.ne  loc_82735c0          ; product overflows 64 bits -> trap
0x08273000:  mul   x0, x19, x0          ; low product used only after the check
```

(b) init range end bounded by nPages:

```
0x0827cd1c:  subs  x21, x19, x23        ; range size = end - start
0x0827cd20:  b.ls  loc_827cfa8          ; end <= start -> reject
0x0827cd24:  cmp   x20, x19
0x0827cd28:  b.lo  loc_827cfa8
0x0827cd38:  cmp   x8, x21              ; x8 = nPages ([x28,#0x10])
0x0827cd3c:  b.lo  loc_827d0a8          ; range size > nPages -> reject
```

(c) DART `offset + size` overflow — `sub_851054c`:

```
0x085105d8:  adds  x1, x23, x8          ; offset + size, set flags
0x085105dc:  b.hs  loc_8510678          ; carry (wrap) -> trap
```

(d) DART IOVA below span size:

```
0x08512e78:  ldp   x8, x9, [x20, #0x28] ; span [lo,hi]
0x08512e7c:  subs  x8, x9, x8           ; span size
0x08512e80:  b.lo  loc_8512f28
0x08512e84:  cmp   x1, x8               ; IOVA vs span size
0x08512e88:  b.hs  loc_8512eb8          ; IOVA >= span -> trap
```

(e) DART mapping end bounded by maxOffset:

```
0x0850e1f8:  ldr   x8, [x20, #0x10]     ; maxOffset
0x0850e1fc:  cmp   x8, x1               ; maxOffset vs end
0x0850e200:  b.hs  loc_850e250          ; end > maxOffset -> reject
```

## Annotation

- (a) The `umulh ... ; cmp xzr ; b.ne` pair is the textbook "check the high half before you trust the
  low half" overflow guard; the `mul` producing the usable byte count is reached only when the top
  64 bits are zero.
- (b) The init-range end is bounded both against the start (`subs; b.ls`) and against `nPages`
  (`cmp x8,x21; b.lo`), so a caller cannot describe a range longer than the backing page array.
- (c)–(e) The DART mapper checks the three independent ways an XNU descriptor could escape its
  window: integer wrap of `offset+size` (`adds; b.hs`), IOVA past the span (`cmp; b.hs`), and
  mapping end past `maxOffset` (`cmp; b.hs`). Because `segmentID` is a dictionary key (looked up),
  not a raw index, there is no index-scaling sink to overflow here.

**Verdict:** hardened across the shared-segment and DART mapping paths.
