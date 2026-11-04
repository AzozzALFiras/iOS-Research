# Evidence — `zone_id_require` and its backing anchors (27.0.1)

**Claim.** The out-of-line `zone_require` is at `0xfffffff00b41101c`. It reads `z_elem_size` from
`[zone, #0x34]`, range-checks the pointer against the zone-map anchor `0xfffffff007de5de0`, then reads
the per-page metadata halfword at `metadata_base (0xfffffff007de5e90) + (addr >> 14) * 16`, masks the
low 10 bits (`and #0x3ff`) and compares it to the expected zone id. The anchor lives in
`__DATA_CONST`; the metadata array it points to is ordinary writable kernel memory.

## (a) Reproduction

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00b41101c -c 40 --quiet"
```

## (b) Disassembly (pulled)

```asm
sub_fffffff00b41101c:                                  ; zone_require(zone_t x0, void* x1)
0xfffffff00b41101c:  pacibsp
0xfffffff00b411038:  mov  x19, x1
0xfffffff00b41103c:  ldrh w8, [x0, #0x34]              ; z_elem_size
0xfffffff00b411040:  adds x8, x1, x8                   ; elem + size
0xfffffff00b411044:  b.hs 0xfffffff00b411064           ; overflow -> panic path
0xfffffff00b411048:  adrp x9, 0xfffffff007de5000
0xfffffff00b41104c:  add  x9, x9, #0xde0               ; &anchor @ 0xfffffff007de5de0
0xfffffff00b411050:  ldp  x10, x9, [x9]                ; zone-map {base, bound}
0xfffffff00b411054:  cmp  x10, x19
0xfffffff00b411058:  ccmp x8, x10, #0, ls
0xfffffff00b41105c:  ccmp x8, x9,  #0x2, cs
0xfffffff00b411060:  b.ls 0xfffffff00b411084           ; in range -> continue
0xfffffff00b411064:  mov  w8, #0x580                   ; (panic: out of zone map)
            ... bl 0xfffffff00b4076bc (panic) ...
0xfffffff00b411084:  mov  x20, x0
0xfffffff00b411088:  adrp x8, 0xfffffff007de5000
0xfffffff00b41108c:  ldr  x8, [x8, #0xe90]             ; metadata_base @ 0xfffffff007de5e90
0xfffffff00b411090:  lsr  x9, x19, #0xa
0xfffffff00b411094:  and  x9, x9, #0xffffffff0         ; (addr >> 14) * 16  (one 16B entry / 16KiB page)
0xfffffff00b411098:  add  x8, x9, x8
0xfffffff00b41109c:  ldrh w8, [x8]                     ; metadata halfword
0xfffffff00b4110a0:  and  x23, x8, #0x3ff              ; zone id = low 10 bits
0xfffffff00b4110a4:  adrp x8, 0xfffffff00b747000
0xfffffff00b4110a8:  ldrh w8, [x8, #0xf78]             ; zone_array bound (0xfffffff00b747f78)
0xfffffff00b4110ac:  cmp  w23, w8
0xfffffff00b4110b0:  b.hs 0xfffffff00b4110cc
            ... index zone_array, compare expected id ...
```

## (c) Annotation

- The metadata index `(addr >> 0xa) & 0xffffffff0` is algebraically `(addr >> 14) * 16`: 16-byte
  metadata entry per 16 KiB page. This exact mask (`and … #0xffffffff0`) is the fingerprint of every
  zone-id / RO-zone check in the kernel; it occurs **298** times across the fileset, and the zone-id
  extract mask `and … #0x3ff` occurs **279** times — the population of zone-id comparisons that the
  prior "~165 zone_id_require guard sites" figure is a subset of (most are inlined; only **2** call
  the out-of-line `0xfffffff00b41101c`).
- Two backing data structures with **different** trust (verified addresses):
  - **anchor** `0xfffffff007de5de0` (zone-map `{base,bound}`) and `0xfffffff007de5e90` (metadata base
    pointer) are in `__DATA_CONST` — CTRR-D-locked by SPTM at boot; not writable under data-only R/W.
  - **metadata array** (what `0xde5e90` points to) is an ordinary writable kernel submap: the runtime
    `zalloc/zfree` fast path updates the same halfword the check reads, with a plain `strh`. Under
    full kernel R/W the zone-id halfword is therefore **forgeable**.
- Consequence: `zone_id_require` blocks *constrained* type-confusion but is not a post-R/W boundary.
  Full reasoning in [`../reports/trust-boundary.md`](../reports/trust-boundary.md).

### Related anchors (same `__DATA_CONST` block)

| anchor | value | role |
|---|---|---|
| `0xfffffff007de5de0` | `{base,bound}` | regular zone-map range |
| `0xfffffff007de5e90` | ptr | regular zone metadata base |
| `0xfffffff007de5e30` | `{base,bound}` | RO-zone range (used by RO validators) |
| `0xfffffff007debdd0` | table | RO zone-id → elem-size table |
