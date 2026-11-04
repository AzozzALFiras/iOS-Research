# Evidence — the RO-zone SPRR wall is a data-only boundary, unchanged through 27.3 beta

**Claim.** The read-only (`ZC_READONLY`) zone write worker still flips `sprr_pperm_el1` with a plain
EL1 `msr` — no GXF/SPTM transition — in 27.3 beta, exactly as in 27.0.1/27.2. So the credential wall
remains a **data-only** boundary (holds vs data-only kernel R/W; falls to EL1 *code execution*), in
all three builds. See [kernel-zone trust-boundary](../../27.0.1/kernel-zone/reports/trust-boundary.md).

## (a) Reproduction

```sh
KC=extracted/27.3/24C5037i__iPhone17,2/kernelcache.release.iPhone17,2
# worker located by the content-anchored zone/CTRR diff (mitigation_diff_2702_2703beta):
ipsw macho disass -t com.apple.kernel --vaddr 0xfffffff00ae6388c --count 22 -q "$KC"
```

## (b) Disassembly (pulled, 27.3 beta @ 0xfffffff00ae6388c)

```asm
0xfffffff00ae6388c:  mrs  x8, sprr_pperm_el1          ; c8 f1 3e d5
0xfffffff00ae63890:  mov  x9, #0xb                    ; perm index 0xb = READ-WRITE
0xfffffff00ae63894:  bfi  x8, x9, #0x8, #0x4          ; set field [8:11] = 0xb
0xfffffff00ae63898:  msr  sprr_pperm_el1, x8          ; c8 f1 1e d5  <-- plain EL1 msr, NO GXF gate
0xfffffff00ae6389c:  isb
            ... (bl copy helpers — the actual RO-element write) ...
0xfffffff00ae638c8:  mrs  x8, sprr_pperm_el1
0xfffffff00ae638cc:  mov  x9, #0xa                    ; perm index 0xa = READ-ONLY
0xfffffff00ae638d0:  bfi  x8, x9, #0x8, #0x4          ; restore field [8:11] = 0xa
0xfffffff00ae638d4:  msr  sprr_pperm_el1, x8
0xfffffff00ae638d8:  isb
```

## (c) Annotation

- The `msr sprr_pperm_el1, x8` encoding `c8 f1 1e d5` is a **plain EL1 system-register write** — the
  same instruction XNU uses here with no GXF/SPTM hop. A data-only kernel R/W cannot touch a register,
  so the RO wall **holds** against data-only primitives; but EL1 *code execution* flips RO→RW in the
  three instructions above → the wall is a data-only boundary, not a code-exec one.
- 27.3 is **byte-identical in idiom** to 27.0.1/27.2 (`#0xb` write / `#0xa` restore, `bfi #0x8,#0x4`):
  the content-anchored zone/CTRR diff scores this worker SAME across all three (only the host VA
  shifted: 27.0.1 `…ad31c08` → 27.2 `…ad7cd40` → 27.3 `…ae6388c`). So the "did 27.2/27.3 trap
  `msr sprr_pperm_el1` to GL?" open question is answered **No** through 27.3 beta.
</content>
