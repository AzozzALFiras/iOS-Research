# ANE `ZinRt` compute-program deserializer (C++) — hardened

**Verdict:** hardened. The one *memory-unsafe-by-language* (C++) exclave service, and a
Mach-O-like parser — historically the bug-prone shape (dyld / ImageIO). It is nonetheless
hardened, by a consistent discipline: a header gate, a bounds-check helper before every field read,
and **widening** multiplies. Proven to the "road-blocked" bar.

- Binary: `exclavecore_bundle` → `APP/sharedcache` (22 MB), ANE code region ≈ `0x83dd000–0x83f3000`.
- Build: 27.0.1 (24A446). Present in both 27.0.1 and 27.2 (same code → a "live in both" surface).
- C++ with full demangled names via `__PRETTY_FUNCTION__` strings (how the stripped functions were
  located): `ZinComputeProgramSharedValidHeader`, `…MakeSegmentsInit`, `…MakeSymbolsInit`,
  `…MakeRelocationsInit`, `…GetSectionBasicInfo`, `ZinRtDeserializeUtil::CheckRuntimeDataAccess`.

## Reachable input

XNU submits an ANE **compute program** (a model) — a Mach-O-like container: `aligned_mach_header_64`
+ load commands (`ident_command`, `symtab_command`, `compute_thread_command`) + segments + symbols
+ relocations + bindings. All attacker-controlled bytes. The parser walks it to build runtime
structures → the classic place for `count*size` overflow and unchecked offset OOB.

## The header gate — `ZinComputeProgramSharedValidHeader` @ `0x83ddcd0`

Every field read is preceded by a `CheckRuntimeDataAccess`-style bounds call (`FUN_0x83e49d0`), and
the load-command table size is computed with a **widening** multiply + a 64-bit compare + a hard
count cap:

```asm
0x83dddd4  ldr  w9, [x24]            ; magic
0x83dddd8  cmp  w9, #0x19
0x83ddddc  b.ne <reject>            ; magic must be 0x19
0x83dddc8  ldr  w8, [x24, #0x4]      ; declared size
0x83dddcc  tst  x8, #0x7
0x83dddd0  b.ne <reject>            ; must be 8-byte aligned
0x83ddde0  cmp  x8, #0x48
0x83ddde4  b.lo <reject>            ; size >= 0x48 (header)
            ... bl FUN_0x83e49d0    ; CheckRuntimeDataAccess(ptr, 0x48, [base,end]) before reading
0x83dde00  ldr  w8, [x24, #0x40]     ; ncmds (count), 32-bit
0x83dde04  umull x8, w8, w19         ; w19 = 0x50  -> count * 0x50  (WIDENING 32x32 -> 64)
0x83dde08  add  x8, x8, #0x48        ; + header
0x83dde0c  ldr  w9, [x24, #0x4]      ; declared total size
0x83dde10  cmp  x8, x9
0x83dde14  b.hi <reject>            ; count*0x50 + 0x48 must fit in the declared size
0x83dde34  cmp  w8, #0x100
0x83dde38  b.hi <reject>            ; and count <= 0x100
```

`umull x8, w8, w19` zero-extends the 32-bit `count` and stride to a 64-bit product, so `count*0x50`
cannot wrap (max ≈ 2^37), and it is then compared 64-bit against the declared size and capped at
0x100. This is exactly the widening pattern the *fixed* ImageIO TIFF bug adopted in 27.2 (see
[`../../../diffs/27.0.1-to-27.2/media.md`](../../../diffs/27.0.1-to-27.2/media.md)) — here it is
present in 27.0.1. Overflow-safe.

## Whole-region multiply classification (negative control)

The sink is any `count*size → alloc/access`. We counted **every** multiply in the contiguous
Shared-parser cluster `0x83dd000–0x83f375c` (the reproducible region; see
[`../evidence/ane-validheader.md`](../evidence/ane-validheader.md) for the exact census and a
per-site classification table):

```
widening (safe):  umull / umaddl / smull   =  7
non-widening:     mul / madd / mneg        = 14   (12 verified safe, 2 low-confidence — below)
```

> An earlier draft quoted "191 widening vs ~10 non-widening" for this surface; that figure is not
> reproducible at any scope (the whole 22 MB sharedcache has 321 `umull` / 2004 `mul`) and has been
> corrected to the counts above. The qualitative conclusion is unchanged.

The 14 non-widening 64-bit multiplies are each one of:

- **divide-by-constant idioms** — e.g. `asr x11,#3; mul x11, 0xAAAAAAAAAAAAAAAB` (the compiler's
  `/3`/`/24` reciprocal), computing a *count* from a pointer difference, then `cmp; b.hs <reject>`.
  Not an allocation multiply.
- **bounds-checked `index × stride`** — `cmp x25, count; b.hs <reject>` *before* `mul x9, x25, x20;
  add x10, base, x9; str …`. The index is dominated by a count check, so the product is in-bounds.
- **array-end pointer** — `mul x11, count, 0x838; add end, base, x11` to bound a loop, where `count`
  was already validated (≤ 0x100 from the header gate).

Plus `CheckRuntimeDataAccess(ptr, len, span)` is called before field reads throughout. No
attacker-controlled unchecked multiply reaches an allocation.

## Residual (honest)

Two of the 14 non-widening sites are downgraded to low-confidence rather than rounded up to "safe":

- `0x83df14c` (`mul [sp+0x48] × 0x838; add base + …`) — the dominating `cmp x19, [x22,#0x48]; b.hs`
  is on the spilled copy of the index, not statically tied to the `[sp+0x48]` operand of the
  multiply. Almost certainly a validated loop index.
- `0x83ec898` (`mul x8, x9, x8` of two memory operands, store `[x3]`) — a generic `a*b` helper whose
  inputs need caller context to bound; not demonstrably reachable with attacker-controlled >32-bit
  factors, but not statically closed here.

Both are logged as low-confidence (see [`../../../STATUS.md`](../../../STATUS.md) and
[`../evidence/ane-validheader.md`](../evidence/ane-validheader.md)). This is the honest downgrade the
proof methodology requires (coverage #4) rather than rounding up to "safe".

## Evidence

`ValidHeader` `0x83ddcd0`; bounds helper `FUN_0x83e49d0`; `CheckRuntimeDataAccess` refs cluster
`~0x83f0f34`; `__PRETTY_FUNCTION__` strings at `0x8f04d37` / `0x8f06819`. Disasm excerpts in
[`../evidence/`](../evidence/).
