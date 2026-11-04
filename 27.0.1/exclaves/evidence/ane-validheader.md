# Evidence — ANE ZinRt ValidHeader gate (widening multiply + bounds) and multiply census

Backs finding #5 in [`../README.md`](../README.md) and [`../reports/ane-zinrt.md`](../reports/ane-zinrt.md).

## Binary / tooling

- Binary: `exclavecore_bundle` → `APP/sharedcache`. On kd-app:
  `/root/ios-research/analysis/exclaves/2701/extracted/APP/sharedcache`. Build 27.0.1.
- Disassembler: `ipsw macho disass -a <vaddr> -c <count>`.
- `ZinComputeProgramSharedValidHeader` @ `0x83ddcd0`; `CheckRuntimeDataAccess` helper @ `0x83e49d0`.
  Names via `__PRETTY_FUNCTION__` strings (`ZinComputeProgram*`, `ZinRtDeserializeUtil::*`).

## Claim

The ANE compute-program (Mach-O-like) header parser validates before it trusts: magic `== 0x19`,
8-byte alignment, declared size `>= 0x48`, and the load-command table size computed with a
**widening** `umull` (count × 0x50, zero-extended 32×32→64) that is then compared 64-bit against the
declared size and capped at `count <= 0x100`. Every field read is preceded by a
`CheckRuntimeDataAccess(ptr,len,span)` call. Across the contiguous Shared-parser cluster, every
non-widening multiply is a divide-by-constant reciprocal idiom or a bounds-/count-dominated
`index × constant-stride`, with two low-confidence residuals noted below.

## Reproduction

```sh
SHC=/root/ios-research/analysis/exclaves/2701/extracted/APP/sharedcache
# the header gate
ipsw macho disass -a 0x83dddc0 -c 32 $SHC
# multiply census over the contiguous Shared-parser cluster
ipsw macho disass -a 0x83dd000 -c 23000 $SHC | grep -vE 'Loaded|parsing' > /tmp/ane_region.asm
tail -1 <(grep -oE '^0x0[0-9a-f]+:' /tmp/ane_region.asm)      # last VA covered: 0x83f375c
for m in umull umaddl smull smaddl mul madd mneg umulh smulh; do \
  printf '%-7s %d\n' "$m" "$(grep -cE "[[:space:]]$m[[:space:]]" /tmp/ane_region.asm)"; done
```

## Disassembly (pulled 27.0.1) — the header gate

```
0x083dddc0:  bl    0x83e49d0                ; CheckRuntimeDataAccess before any read
0x083dddc4:  cbnz  w0, loc_83de078          ; access denied -> reject
0x083dddc8:  ldr   w8, [x24, #0x4]          ; declared size
0x083dddcc:  tst   x8, #0x7
0x083dddd0:  b.ne  loc_83de0c0              ; must be 8-byte aligned
0x083dddd4:  ldr   w9, [x24]                ; magic
0x083dddd8:  cmp   w9, #0x19
0x083ddddc:  b.ne  loc_83ddf30              ; magic must be 0x19
0x083ddde0:  cmp   x8, #0x48
0x083ddde4:  b.lo  loc_83de0c0              ; size >= 0x48
0x083dddf8:  bl    0x83e49d0                ; bounds-check the 0x48 header span
0x083dde00:  ldr   w8, [x24, #0x40]         ; ncmds (32-bit count)
0x083dde04:  umull x8, w8, w19              ; w19 = 0x50 -> count*0x50  (WIDENING 32x32->64)
0x083dde08:  add   x8, x8, #0x48
0x083dde0c:  ldr   w9, [x24, #0x4]
0x083dde10:  cmp   x8, x9
0x083dde14:  b.hi  loc_83de0c0              ; count*0x50 + 0x48 must fit the declared size
0x083dde34:  cmp   w8, #0x100
0x083dde38:  b.hi  loc_83de0c0              ; and count <= 0x100
```

## Multiply census (pulled) — region `0x83dd000 .. 0x83f375c`

```
umull   : 7     (widening — safe)
umaddl  : 0
smull   : 0
smaddl  : 0
mul     : 13    (non-widening, classified below)
madd    : 1     (non-widening, reciprocal-division idiom)
mneg    : 0
umulh   : 0
smulh   : 0
```

> **Honesty note / correction to the draft.** Earlier notes quoted "191 widening vs ~10 non-widening"
> for this surface; that figure is **not reproducible** at any scope (the entire 22 MB sharedcache
> has 321 `umull` / 2004 `mul`) and almost certainly came from a Ghidra pass over a differently-scoped
> set of functions. The numbers above are the exact counts over the stated, reproducible contiguous
> region. The *qualitative* result is unchanged: the allocation-sizing multiply in the header gate is
> widening, and no attacker-controlled unchecked multiply reaches an allocation. All 14 non-widening
> multiplies were classified by hand:

| VA | insn | classification |
|---|---|---|
| 0x83dd568 | `mul x11,x11,x12` | ÷-by-const: `asr #3` then `×0xAAAAAAAAAAAAAAAB`, then `cmp;b.hs` |
| 0x83dd594 | `mul x8,x8,x9` | ÷-by-const: `asr #3` then `×0xCCCCCCCCCCCCCCCD`, then `cmp;b.hs` |
| 0x83dd7c0 | `mul x10,x10,x11` | ÷-by-const: `asr #3` then `×0xAAAAAAAAAAAAAAAB` |
| 0x83dd80c | `madd w8,w8,w9,w10` | ÷-by-const: `lsr #3` then `×0xCCCCCCCD` + base |
| 0x83ddc3c | `mul x13,x9,x12` | bounded loop index × const stride 0x838 (count from [x0,#0x58]) |
| 0x83de74c | `mul x9,x25,x20` | `cmp x25,limit; b.hs` dominates (idx×stride) |
| 0x83de770 | `mul x10,x25,x20` | `cmp x25,limit; b.hs` dominates (idx×stride) |
| 0x83df258 | `mul x9,x9,x10` | array-end = count × 0x838, count capped `<= 0x100` |
| 0x83df2e4 | `mul x8,x8,x10` | `add idx; cmp idx,[x22,#0x28]; b.hs` dominates × 0x838 |
| 0x83df888 | `mul x11,x10,x9` | count × 0x838 from validated structure, `cbz` guard |
| 0x83e41cc | `mul x11,x9,x10` | count × 0x838 from validated structure, `cbz` guard |
| 0x83e4270 | `mul x13,x13,x12` | bounded loop index × const stride 0x838 |
| 0x83df14c | `mul x9,x9,x10` | **low-confidence**: idx (`[sp,#0x48]`) × 0x838; dominating `cmp x19,[x22,#0x48];b.hs` is on the spilled copy, not statically tied |
| 0x83ec898 | `mul x8,x9,x8` | **low-confidence**: generic `a*b` helper, two memory operands, store `[x3]`; needs caller context to bound a,b |

## Annotation

`umull x8,w8,w19` zero-extends the 32-bit `ncmds` and the 0x50 stride into a 64-bit product (max
≈ 2^37), so `count*0x50` cannot wrap before the 64-bit `cmp` against the declared size and the
`count <= 0x100` cap. The `CheckRuntimeDataAccess` bracketing (`bl 0x83e49d0; cbnz w0,reject`)
appears before each field read. Of the 14 non-widening multiplies, 12 are provably safe
(4 reciprocal-division idioms, 8 count/index-dominated × constant-stride); 2 are downgraded to
low-confidence rather than rounded up — matching the proof methodology's coverage requirement.

**Verdict:** hardened, with two low-confidence residuals (`0x83df14c`, `0x83ec898`).
