# Evidence — `sprr_pperm_el1` is freely EL1-writable: the RO wall is data-only (27.0.1)

**Claim.** The RO-zone write permission is controlled by the EL1 system register `sprr_pperm_el1`.
It is flipped with a bare `msr` in ordinary EL1 kernel text, with **no GXF/GL transition gating**.
There are **30** `sprr_pperm_el1` references (16 `msr` + 14 `mrs`) in `com.apple.kernel` EL1 text. A
data-only R/W primitive cannot touch a register, so the RO wall holds against data-only attackers;
an attacker with EL1 **code execution** flips RO→RW in three instructions.

## (a) Reproduction

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
# full fileset disassembly -> /tmp/kc_2701_full.txt (see zalloc-ro-mut.md), then:
ssh kd-app "grep -c 'msr.*sprr_pperm_el1' /tmp/kc_2701_full.txt"          # -> 16
ssh kd-app "grep -c 'mrs.*sprr_pperm_el1' /tmp/kc_2701_full.txt"          # -> 14
ssh kd-app "grep -c 'sprr_pperm_el1' /tmp/kc_2701_full.txt"               # -> 30
ssh kd-app "grep -cE 'sprr_config_el12|gxf_config_el12' /tmp/kc_2701_full.txt"  # -> 8 (boot/init only)
```

## (b) Disassembly (pulled) — the canonical flip, from `pmap_ro_zone_memcpy`

```asm
; RO (0xa) -> RW (0xb) : three instructions, plain EL1, no GXF entry
0xfffffff00ad31c98:  mrs  x8, sprr_pperm_el1
0xfffffff00ad31c9c:  mov  x9, #0xb
0xfffffff00ad31ca0:  bfi  x8, x9, #0x8, #0x4
0xfffffff00ad31ca4:  msr  sprr_pperm_el1, x8
0xfffffff00ad31ca8:  isb
; ... copy ...
; RW (0xb) -> RO (0xa)
0xfffffff00ad31cd4:  mrs  x8, sprr_pperm_el1
0xfffffff00ad31cd8:  mov  x9, #0xa
0xfffffff00ad31cdc:  bfi  x8, x9, #0x8, #0x4
0xfffffff00ad31ce0:  msr  sprr_pperm_el1, x8
0xfffffff00ad31ce4:  isb
```

## (c) Annotation

- `sprr_pperm_el1` is a **register**, not memory. A data-only kernel R/W primitive (the premise of
  the trust-boundary analysis) writes *memory*; it has no way to execute an `msr`. Therefore the
  RO-zone pages stay mapped read-only in the normal SPRR domain and a data-only arbitrary write to a
  `proc_ro`/`ucred`/`cs_blob` page **faults**. → the RO wall **holds vs data-only**.
- But the register is written by ordinary EL1 code: the flip above is just `mrs/bfi/msr/isb` with no
  preceding `genter`/GL transition. Of the 30 `sprr_pperm_el1` sites, none is behind a GXF gate.
  (The 8 `sprr_config_el12`/`gxf_config_el12` references are CPU-init/boot configuration of the SPRR
  layout, not runtime permission toggles.)
- So the RO wall is a **data-only boundary, not a code-exec boundary**. An attacker who achieves EL1
  **code execution** writes `sprr_pperm_el1` directly:

  ```asm
  mrs x8, sprr_pperm_el1 ; mov x9, #0xb ; bfi x8, x9, #8, #4 ; msr sprr_pperm_el1, x8 ; isb
  ```

  and every RO-zone page becomes writable. Crossing from data-only R/W to code execution is what the
  PAC + CTRR + SPTM triad is there to deny — that is the real wall, analysed in
  [`../reports/trust-boundary.md`](../reports/trust-boundary.md).
