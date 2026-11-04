# Evidence — RO-zone destination & source validators (27.0.1)

**Claim.** Before any RO-zone write, two validators run:
- **destination** — `pmap_ro_zone_validate_element` `0xfffffff00ad31d84`: checks the dst zone-id is a
  valid RO zone (`w0-0xf` range), the dst is inside the RO-zone range anchor `0xfffffff007de5e30`,
  the metadata zone-id halfword matches `w0`, and the element offset+len are in bounds.
- **source** — `0xfffffff00b41dce0`: checks the src pointer lies in an allowed const/RO range.
- the public-facing RO zone check `zone_require_ro` `0xfffffff00b411164` uses the same RO-zone range
  anchor `0xfffffff007de5e30` and the RO-id table `0xfffffff007debdd0` (107 call sites).

## (a) Reproduction

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00ad31d84 -c 40 --quiet"  # dst validator
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00b41dce0 -c 40 --quiet"  # src validator
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00b411164 -c 30 --quiet"  # zone_require_ro
ssh kd-app "grep -c 'bl.*0xfffffff00b411164\$' /tmp/kc_2701_full.txt"                       # -> 107
```

## (b) Disassembly (pulled)

`pmap_ro_zone_validate_element` — `0xfffffff00ad31d84`:

```asm
0xfffffff00ad31d84:  pacibsp
0xfffffff00ad31d94:  sub  w8, w0, #0xf                 ; zone-id normalized (RO zones start at 0xf)
0xfffffff00ad31d98:  mov  w9, #0xfff3
0xfffffff00ad31d9c:  cmp  w9, w8, uxth
0xfffffff00ad31da0:  b.hs 0xfffffff00ad31e30           ; id out of RO range -> fail
0xfffffff00ad31da4:  adrp x8, 0xfffffff007de5000
0xfffffff00ad31da8:  add  x8, x8, #0xe30               ; RO-zone range anchor 0xfffffff007de5e30
0xfffffff00ad31dac:  ldp  x9, x8, [x8]                 ; RO {base,bound}
0xfffffff00ad31db0:  cmp  x1, x9
0xfffffff00ad31db4:  ccmp x1, x8, #0x2, cs
0xfffffff00ad31db8:  b.hs 0xfffffff00ad31ebc           ; dst not in RO range -> fail
0xfffffff00ad31dc0:  adrp x8, 0xfffffff007deb000
0xfffffff00ad31dc4:  add  x8, x8, #0xdd0               ; RO-id elem-size table 0xfffffff007debdd0
0xfffffff00ad31de8:  adrp x9, 0xfffffff007de5000
0xfffffff00ad31dec:  ldr  x9, [x9, #0xe90]             ; metadata base 0xfffffff007de5e90
0xfffffff00ad31df0:  lsr  x10, x1, #0xa
0xfffffff00ad31df4:  and  x10, x10, #0xffffffff0        ; (addr>>14)*16
0xfffffff00ad31dfc:  ldrh w9, [x9]
0xfffffff00ad31e00:  and  w9, w9, #0x3ff               ; metadata zone-id
0xfffffff00ad31e04:  cmp  w0, w9
0xfffffff00ad31e08:  b.ne 0xfffffff00ad31ebc           ; dst zone-id mismatch -> fail
0xfffffff00ad31e0c:  add  x8, x8, w0, uxtw #0x3
0xfffffff00ad31e10:  ldr  w8, [x8, #0x4]               ; elem size for this RO zone
0xfffffff00ad31e14:  subs x9, x8, x2
0xfffffff00ad31e18:  b.ls 0xfffffff00ad31e64           ; offset past element -> fail
0xfffffff00ad31e1c:  cmp  x3, x9
0xfffffff00ad31e20:  b.hi 0xfffffff00ad31e90           ; offset+len overflow -> fail
```

`zone_require_ro` — `0xfffffff00b411164` (same RO-range anchor, used standalone at 107 sites):

```asm
0xfffffff00b411164:  pacibsp
0xfffffff00b411184:  adrp x8, 0xfffffff007de5000
0xfffffff00b411188:  add  x8, x8, #0xe30               ; RO-zone range anchor 0xfffffff007de5e30
0xfffffff00b41118c:  ldp  x9, x8, [x8]
0xfffffff00b411190:  cmp  x9, x1
0xfffffff00b411194:  ccmp x8, x1, #0, ls
0xfffffff00b411198:  b.hi 0xfffffff00b4111bc           ; in RO range -> continue; else panic
0xfffffff00b4111c4:  adrp x9, 0xfffffff007deb000
0xfffffff00b4111c8:  add  x9, x9, #0xdd0               ; RO-id table 0xfffffff007debdd0
            ...
```

`src` validator — `0xfffffff00b41dce0` (range table at `0xfffffff007e8b000+0xc00`):

```asm
0xfffffff00b41dce0:  bti  c
0xfffffff00b41dce4:  adrp x8, 0xfffffff007e8b000
0xfffffff00b41dce8:  ldrb w8, [x8, #0xbf0]
0xfffffff00b41dcec:  tbz  w8, #0, 0xfffffff00b41dda4    ; feature off -> accept (fast path)
0xfffffff00b41dd10:  adrp x8, 0xfffffff007e8b000
0xfffffff00b41dd14:  ldr  x8, [x8, #0xc18]             ; allowed range base
0xfffffff00b41dd1c:  ldr  x9, [x9, #0xc20]             ; allowed range bound
0xfffffff00b41dd20:  cmp  x0, x8
0xfffffff00b41dd24:  ccmp x0, x9, #0x2, cs             ; src in allowed range?
            ... iterate a per-zone range table (0xc00) for other RO submaps ...
```

## (c) Annotation

- The dst validator enforces four things *in sequence*, all before `pmap_ro_zone_memcpy` opens the
  SPRR window: (i) zone-id is a legitimate RO zone id (`w0-0xf` within `0xfff3`), (ii) dst ∈ RO-zone
  range (anchor `0xfffffff007de5e30`), (iii) the **page metadata zone-id** halfword equals the
  claimed `w0`, and (iv) `offset` and `offset+len` fit the per-zone element size from the RO-id table
  (`0xfffffff007debdd0`). So even inside the legitimate write path, you can only write a correctly
  typed, in-bounds RO element.
- The src validator restricts the copy source to an allowed range set — consistent with the design
  intent that RO-zone writes come from constant data / kernel stack / a RO copy, not an attacker's
  arbitrary heap buffer.
- `zone_require_ro` (107 bl sites) is the standalone RO-type guard used by readers and setters
  (see [`cred-reader-ttro.md`](cred-reader-ttro.md), [`proc-ro-reader.md`](proc-ro-reader.md),
  [`csflags-setters.md`](csflags-setters.md)). It shares the RO-range anchor and RO-id table with
  the dst validator above.
