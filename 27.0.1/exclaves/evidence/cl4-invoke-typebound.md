# Evidence — cL4 Invoke type dispatch has no type-range check (defense-in-depth gap)

Backs finding #2 in [`../README.md`](../README.md) and the "secondary note" in
[`../reports/cl4-kernel-pan.md`](../reports/cl4-kernel-pan.md).

## Claim

On the Invoke path (dispatcher selector 0), the 6-bit object type is extracted
(`cap >> 58`, range 0x00–0x3f), scaled by the per-type descriptor stride 0x58, used to index the
type-dispatch table at `0xfffffc00000135e8`, and the method pointer at `+0x28` is called via `blr` —
**with no `cmp`/`cbz` bound on the type** between the extraction and the call. Only 0x00–0x1a are
valid descriptors, so types 0x1b–0x3f would read a function pointer out of adjacent rodata and call
it. The sibling paths (Delete/Move/Revoke) *do* null-check the slot; Invoke does not. This is a
genuine missing `if (type > 0x1a)`, but it is **gated by the same precondition as finding #1** — a
kernel-written cap never has `type > 0x1a`, and PAN prevents the attacker from writing a cap word —
so it is a severity amplifier of a non-reachable condition, not an independent bug. Worth citing to
Apple as a cheap defense-in-depth addition.

## Reproduction

```sh
cd /root/ios-research/analysis/exclaves/kerncarve
python3 mkelf.py exk_code_2701.bin exk_code_2701.elf 0xfffffc0000000000   # if not already built
# the full Invoke path (selector 0 lands at 0x84fc, falls through to 0x85ec)
llvm-objdump -d --start-address=0xfffffc00000085ec --stop-address=0xfffffc0000008614 exk_code_2701.elf
```

## Disassembly (pulled 27.0.1)

```
fffffc00000085ec: f9400008   ldr   x8, [x0]              ; cap word (x0 = masked slot addr)
fffffc00000085f0: d37afd08   lsr   x8, x8, #58           ; type = bits[58:63]  (0x00..0x3f)
fffffc00000085f4: 52800b09   mov   w9, #0x58             ; descriptor stride = 0x58
fffffc00000085f8: 9ba97d08   umull x8, w8, w9            ; type * 0x58  (widening, cannot wrap)
fffffc00000085fc: f0000049   adrp  x9, 0xfffffc0000013000
fffffc0000008600: 9117a129   add   x9, x9, #0x5e8        ; table base = 0xfffffc00000135e8
fffffc0000008604: 8b08012a   add   x10, x9, x8           ; &table[type]
fffffc0000008608: f9401548   ldr   x8, [x10, #0x28]      ; method pointer at +0x28
fffffc000000860c: aa1303e1   mov   x1, x19
fffffc0000008610: d63f0100   blr   x8                    ; indirect call — NO bound on type above
```

For contrast, the Delete path at the same dispatcher does null-check its slot before use:

```
fffffc0000008544: ldr  x8, [x9]
fffffc0000008548: lsr  x8, x8, #58
fffffc000000854c: cbnz x8, 0xfffffc0000008618     ; type != 0 guard present here
```

## Annotation

Between `lsr x8,x8,#58` (0x85f0) and `blr x8` (0x8610) there is no `cmp x8,#0x1a` / `b.hi`, no
`cbz`, no table-length comparison — the 6-bit type indexes the table unconditionally. The scaling is
a widening `umull`, so the index math itself is overflow-safe; the missing check is purely the
**upper type bound** (0x1b–0x3f fall off the end of the valid-descriptor array). Reachability is
blocked exactly where finding #1 blocks it: the attacker cannot author a cap word with an invalid
type because PAN prevents the kernel from reading an attacker-writable page as a capability.

**Verdict:** real missing check, non-reachable under 27.0.1 (precondition-gated). Defense-in-depth.
