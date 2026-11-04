# Evidence — `pmap_ro_zone_memcpy`: validate-before-flip ordering + the SPRR window (27.0.1)

**Claim.** `pmap_ro_zone_memcpy` at `0xfffffff00ad31c08` is the worker that actually writes a RO-zone
element. It (1) validates the **source** range (`bl 0xfffffff00b41dce0`) and (2) validates the
**destination** element (`bl 0xfffffff00ad31d84` = `pmap_ro_zone_validate_element`) **before** it (3)
flips `sprr_pperm_el1` from RO (index `0xa`) to RW (index `0xb`), does the copy, and (4) flips back.
The write window is bracketed by the two `msr sprr_pperm_el1` instructions; the validations are
outside and before it.

## (a) Reproduction

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00ad31c08 -c 100 --quiet"
```

## (b) Disassembly (pulled, trimmed to the control flow)

```asm
sub_fffffff00ad31c08:                                  ; pmap_ro_zone_memcpy
0xfffffff00ad31c08:  pacibsp
0xfffffff00ad31c24:  cbz  x3, 0xfffffff00ad31cf0        ; len==0 -> out
0xfffffff00ad31c40:  add  x21, x2, x1                   ; x21 = dst_base + offset
0xfffffff00ad31c48:  add  x1, sp, #0x38
0xfffffff00ad31c4c:  mov  x0, x21
0xfffffff00ad31c50:  bl   0xfffffff00b41dce0            ; (1) VALIDATE SRC range  [BEFORE flip]
0xfffffff00ad31c54:  cbnz w0, 0xfffffff00ad31d08        ;     fail -> panic
0xfffffff00ad31c58:  mrs  x8, daif
0xfffffff00ad31c70:  msr  daifset, #0x7                 ;     IRQs off
0xfffffff00ad31c84:  mov  x0, x22
0xfffffff00ad31c94:  bl   0xfffffff00ad31d84            ; (2) VALIDATE DST element [BEFORE flip]
                                                        ;     = pmap_ro_zone_validate_element
; ---- SPRR window opens: RO(0xa) -> RW(0xb) ----
0xfffffff00ad31c98:  mrs  x8, sprr_pperm_el1
0xfffffff00ad31c9c:  mov  x9, #0xb
0xfffffff00ad31ca0:  bfi  x8, x9, #0x8, #0x4            ;     perm index [8:11] = 0xb (READ-WRITE)
0xfffffff00ad31ca4:  msr  sprr_pperm_el1, x8
0xfffffff00ad31ca8:  isb
0xfffffff00ad31cb8:  bl   0xfffffff00b3fd798            ; (3) copy helper
0xfffffff00ad31cd0:  bl   0xfffffff00b420c10            ;     copy helper
; ---- SPRR window closes: RW(0xb) -> RO(0xa) ----
0xfffffff00ad31cd4:  mrs  x8, sprr_pperm_el1
0xfffffff00ad31cd8:  mov  x9, #0xa
0xfffffff00ad31cdc:  bfi  x8, x9, #0x8, #0x4            ;     perm index [8:11] = 0xa (READ-ONLY)
0xfffffff00ad31ce0:  msr  sprr_pperm_el1, x8
0xfffffff00ad31ce4:  isb
0xfffffff00ad31cf0:  ldp  fp, lr, [sp, #0x70]
0xfffffff00ad31d04:  retab
```

## (c) Annotation

- **Ordering is the security property.** Both validators run while the RO-zone pages are still
  read-only (index `0xa`): `bl 0xfffffff00b41dce0` at `…31c50` (source), `bl 0xfffffff00ad31d84` at
  `…31c94` (destination). The permission flip to RW (`mov x9,#0xb; bfi x8,x9,#0x8,#0x4; msr
  sprr_pperm_el1,x8`) is at `…31c98`, strictly after both. Only validated `{src,dst}` can reach a
  writable RO page, and the window is re-closed (`mov x9,#0xa …`) at `…31cd4` with IRQs held off the
  whole time (`msr daifset,#0x7` at `…31c70`).
- The source validator `0xfffffff00b41dce0` confirms `src` is inside an allowed read-only/const
  range (its own range table at `0xfffffff007e8b000+0xc00`); see
  [`ro-zone-validators.md`](ro-zone-validators.md). The destination validator
  `0xfffffff00ad31d84` checks the dst zone-id, RO-range and element bounds (same file).
- The two `bfi … #0x8, #0x4` give the exact SPRR perm-index field being remapped: bits [8:11] of
  `sprr_pperm_el1`, value `0xa` → read-only, `0xb` → read-write. This is the mechanism analysed in
  [`sprr-flip.md`](sprr-flip.md).
