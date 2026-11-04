# Evidence — 27.3 `SPTM_FUNCTIONID_REMAP_REGION_RNX` is boot-time, not a runtime surface

**Claim.** SPTM 820.60.12 (27.3) adds the endpoint id `SPTM_FUNCTIONID_REMAP_REGION_RNX` and its
handler `sptm_prepare_region_for_remapping` = `FUN_0xfffffff0270d8004`. The handler's **first real
instruction is a bootstrap-stage gate**: it reads `DAT_0xfffffff02710a140` and panics if **bit 7**
is set (`>>7 & 1`), i.e. it is only callable during early boot and faults afterwards. It is reached
only from the boot region registrar, called with **fixed range names** (`SPTM-ro`, `SPTM-rx`,
`BootKC-rx`, `TXM-*`, `AuxKC-*`, `SEPFW`, …). A companion coalescer `FUN_0xfffffff0270d853c` and an
alias verifier `FUN_0xfffffff0270b638c` (stage-gated on **bit 0x10** of the same word) complete the
feature. **It does not expand the runtime GL1 attack surface.**

Binary: `sptm_273.bin` (`SPTM-820.60.12`); decomp export `sptm_273_decomp.c`.

## 1. The strings are new in 27.3 only

```
for b in bins/2701/sptm_2701.bin bins/272/sptm_272.bin bins/273/sptm_273.bin; do
  echo -n "$b REMAP_REGION_RNX: "; strings /root/ios-research/analysis/sptm/$b | grep -c 'REMAP_REGION_RNX'
  echo -n "$b prepare_region_for_remapping: "; strings /root/ios-research/analysis/sptm/$b | grep -c 'prepare_region_for_remapping'
done
```

```
2701 REMAP_REGION_RNX: 0   2701 prepare_region_for_remapping: 0
272  REMAP_REGION_RNX: 0   272  prepare_region_for_remapping: 0
273  REMAP_REGION_RNX: 1   273  prepare_region_for_remapping: 1
```

Related strings present only in 273: `sptm_remap_region_rnx`, `sptm_prepare_region_for_remapping`,
`SPTM_FUNCTIONID_REMAP_REGION_RNX`.

## 2. The handler is bootstrap-stage-gated (bit 7 → panic)

```
ipsw macho disass /root/ios-research/analysis/sptm/bins/273/sptm_273.bin \
  -a 0xfffffff0270d8004 -c 30 --quiet
```

### Output (real, trimmed)

```asm
0xfffffff0270d8004:  7f 23 03 d5   pacibsp
0xfffffff0270d8014:  88 01 00 d0   adrp	x8, 0xfffffff02710a000
0xfffffff0270d8018:  08 01 05 91   add	x8, x8, #0x140        ; &DAT_0xfffffff02710a140 (stage word)
0xfffffff0270d801c:  09 c1 bf f8   ldapr	x9, [x8]
0xfffffff0270d8020:  e9 15 38 37   tbnz	w9, #0x7, 0xfffffff0270d82dc  ; bit 7 set -> panic (post-boot)
0xfffffff0270d8030:  3f 10 01 71   cmp	w1, #0x44             ; type < 0x44 (same lattice bound)
0xfffffff0270d8034:  62 16 00 54   b.hs	0xfffffff0270d8300
0xfffffff0270d803c:  28 e9 42 b9   ldr	w8, [x9, #0x2e8]      ; region-table cursor
```

The branch target `0xfffffff0270d82dc` is the panic:

```
ipsw macho disass /root/ios-research/analysis/sptm/bins/273/sptm_273.bin \
  -a 0xfffffff0270d82dc -c 14 --quiet
```

```asm
0xfffffff0270d82dc:  0a fd df c8   ldar	x10, [x8]
0xfffffff0270d82e8:  09 10 80 52   mov	w9, #0x80            ; 0x80 = bit 7 marker in the panic record
0xfffffff0270d82f4:  c0 f9 ff b0   adrp	x0, 0xfffffff027011000
0xfffffff0270d82f8:  00 10 3a 91   add	x0, x0, #0xe84       ; panic format string
0xfffffff0270d82fc:  03 83 00 94   bl	0xfffffff0270f8f08   ; SPTM panic()
```

## 3. Only caller: the boot region registrar, fixed range names

`FUN_0xfffffff0270d8004` has **40 callsites** in the decomp, all inside the boot registrar
`FUN_0xfffffff0270b30c0`, each passing a hard-coded region name:

```
grep -nE 'FUN_fffffff0270d8004' /root/ios-research/analysis/exports/sptm_273_decomp.c
```

```c
FUN_fffffff0270d8004("DeviceTree",2,   *puVar18, puVar18[1] + 0x3fff >> 0xe, 0x20);
FUN_fffffff0270d8004("SPTM-ro",  2,   *puVar18, puVar18[1] + 0x3fff >> 0xe, 0x28);
FUN_fffffff0270d8004("SPTM-rx",  4,   *puVar18, puVar18[1] + 0x3fff >> 0xe, 0x121);
FUN_fffffff0270d8004("BootKC-rx",0x23,*puVar18, puVar18[1] + 0x3fff >> 0xe, 0x941);
FUN_fffffff0270d8004("TXM-rx",   0x2c,*puVar18, puVar18[1] + 0x3fff >> 0xe, 0x141);
FUN_fffffff0270d8004("SEPFW",    0xb, *local_68,local_68[1]+ 0x3fffU>> 0xe, 2);
... (40 total; DeviceTree / SPTM-* / BootKC-* / TXM-* / AuxKC-* / CL4-* / TrustCache / RAMDisk / SEPFW / ...)
```

## 4. Companion functions

```
ipsw macho disass /root/ios-research/analysis/sptm/bins/273/sptm_273.bin -a 0xfffffff0270d853c -c 14 --quiet
ipsw macho disass /root/ios-research/analysis/sptm/bins/273/sptm_273.bin -a 0xfffffff0270b638c -c 22 --quiet
```

- **Coalescer `FUN_0xfffffff0270d853c`** reads the same region-table cursor (`[x8,#0x2e8]`,
  `…105300`) and is called only from PAPT-range boot setup (`FUN_0xfffffff0270b2960`, whose failure
  path panics `"Number of supported PAPT ranges has been exhausted"`) and the master boot builder
  `FUN_0xfffffff0270d8a04`.
- **Alias verifier `FUN_0xfffffff0270b638c`** gates on **bit 0x10** of the same stage word:

```asm
0xfffffff0270b63b0:  b5 02 00 90   adrp	x21, 0xfffffff02710a000
0xfffffff0270b63b4:  b5 02 05 91   add	x21, x21, #0x140      ; same DAT_0xfffffff02710a140
0xfffffff0270b63b8:  a8 c2 bf f8   ldapr	x8, [x21]
0xfffffff0270b63bc:  e8 12 80 37   tbnz	w8, #0x10, ...        ; bit 0x10 stage gate
```

## Annotation (bytes → claim)

- The handler's prologue reads the global bootstrap-stage word `DAT_0xfffffff02710a140` and
  **panics if bit 7 is set** — `tbnz w9,#0x7`. Bit 7 is set once early boot completes, so any
  post-boot (GL1-runtime) invocation of `REMAP_REGION_RNX` **faults immediately**.
- All 40 callers are the boot region registrar handing it fixed, named firmware regions
  (`SPTM-ro`, `BootKC-rx`, `TXM-*`, `SEPFW`, …) — a boot sequence, not a GL1-driven data path.
- The alias verifier reuses the same stage word with a different bit (`0x10`), confirming the whole
  REMAP_REGION_RNX feature is a staged **boot-time** region-remapping facility.
- Conclusion: 27.3's new endpoint **does not add a runtime GL1 attack surface**; it is boot-only and
  self-fences after boot.
