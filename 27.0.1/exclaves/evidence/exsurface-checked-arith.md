# Evidence — EXSurface create path: Swift checked arithmetic, no raw multiply

Backs finding #4 in [`../README.md`](../README.md) and [`../reports/exsurface.md`](../reports/exsurface.md).

## Binary / tooling

- Binary: `exclavecore_bundle` → `APP/sharedcache` (Swift + C++, 22 MB, symbol-stripped; `.a2s`
  cache recovers names). On kd-app:
  `/root/ios-research/analysis/exclaves/2701/extracted/APP/sharedcache`. Build 27.0.1.
- Disassembler: `ipsw macho disass -a <vaddr> -c <count>`.
- Create/transport handler: `sub_8868fd4`; region scanned `0x8868fd4 .. 0x886c040`.

## Claim

The EXSurface surface-create / ImageLayout path does its size math in Swift's trapping `Int`
arithmetic: every `adds`/`subs` is backed by `b.vs → brk`, every array subscript by `cmp idx,count;
b.hs → brk`, and the region contains **zero** raw multiply instructions. So the classic
`width × height × stride` integer-overflow → undersized-alloc cannot occur — there is no multiply to
overflow, and any overflow in the add/sub math is a trap (DoS, by design), not a wrap.

## Reproduction

```sh
SHC=/root/ios-research/analysis/exclaves/2701/extracted/APP/sharedcache
# checked-arithmetic window
ipsw macho disass -a 0x8869d60 -c 42 $SHC
# array-subscript bounds-check pattern
ipsw macho disass -a 0x886afac -c 10 $SHC
# whole-region multiply count (expect 0) + trap counts
ipsw macho disass -a 0x8868fd4 -c 3100 $SHC | grep -vE 'Loaded|parsing' > /tmp/exsurf.asm
grep -cEw 'mul|umull|umaddl|smull|smaddl|madd|mneg|umulh|smulh' /tmp/exsurf.asm   # -> 0
grep -cEw 'b.vs' /tmp/exsurf.asm                                                 # -> 9
grep -cE  'brk'  /tmp/exsurf.asm                                                 # -> 22
```

## Disassembly (pulled 27.0.1)

Checked arithmetic (overflow → `brk #0x1`):

```
0x08869d70:  subs  x26, x0, #0x1
0x08869d74:  b.vs  loc_8869e90           ; -> brk #0x1
0x08869d9c:  subs  x8, x8, #0x1
0x08869da0:  b.vs  loc_8869e94           ; -> brk #0x1
0x08869de8:  adds  x1, x26, #0x1
0x08869dec:  b.vs  loc_8869e98           ; -> brk #0x1
...
0x08869e90:  brk   #0x1
0x08869e94:  brk   #0x1
0x08869e98:  brk   #0x1
```

Array subscript (index bound → `brk #0x1`):

```
0x0886afb0:  ldr   x9, [x8, #0x10]        ; count
0x0886afb4:  cmp   x0, x9                 ; index vs count
0x0886afb8:  b.hs  loc_886afcc           ; index >= count -> brk #0x1
0x0886afbc:  add   x8, x8, #0x20
0x0886afc0:  ldr   x0, [x8, x0, lsl #0x3] ; bounds-checked load
0x0886afc8:  brk   #0x1
0x0886afcc:  brk   #0x1
```

Whole-region counts (`0x8868fd4 .. 0x886c040`):

```
mul/umull/umaddl/smull/smaddl/madd/mneg/umulh/smulh : 0
b.vs (overflow traps)                               : 9
brk  (overflow/bounds backstops)                    : 22
```

## Annotation

Zero multiply instructions in the entire create region means the surface size cannot be formed by an
unchecked `w*h*stride` product; the Swift compiler lowered the size math to trapping add/sub (and
guarded `lsl`), each paired with `b.vs` to a `brk`. Array element access is likewise dominated by a
`cmp idx,count; b.hs` guard before the scaled load. Overflow or OOB index = trap, never corruption.

**Residual (honest):** this rules out *memory-safety* bugs in the layout arithmetic, not a *logic*
bug such as trusting an XNU-supplied plane offset/size against the shared-region size — a semantic
check that does not manifest as an overflow/OOB signature. Logged low-priority.

**Verdict:** hardened (memory-safety of the layout math).
