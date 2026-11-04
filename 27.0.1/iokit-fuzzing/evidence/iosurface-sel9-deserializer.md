# Evidence — IOSurface sel 9: bounded (ptr, length) pair to deserializer (27.0.1)

**Claim.** Selector 9 (`checkStructureInputSize = VAR`) floors the input size at `0xd` in its
dispatch handler `0xfffffff00a34bd74`, then calls the worker `0xfffffff00a34f600`. The worker hands
the variable payload to a length-bounded deserializer `0xfffffff00b28f330` as an explicit
`(pointer, length)` pair: `pointer = structInput + 0xc`, `length = structInputSize - 0xc` (computed
as `end − start`, not an unchecked subtraction of a raw field). **The deserializer receives a bounded
slice; it is never told a length larger than the buffer.**

Binary: kernelcache FILESET `kernelcache.release.iPhone17,2` (24A446), entry
`com.apple.iokit.IOSurface`.

## Reproduce

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
# Wrapper: size floor + call worker:
ipsw macho disass "$KC" -t com.apple.iokit.IOSurface --vaddr 0xfffffff00a34be24 --count 8
# Worker: build (ptr,len) slice and call deserializer:
ipsw macho disass "$KC" -t com.apple.iokit.IOSurface --vaddr 0xfffffff00a34f640 --count 6
```

## Output (real) — wrapper `0xfffffff00a34bd74`

```asm
0xfffffff00a34be24:  02 3b 40 b9   ldr	w2, [x24, #0x38]      ; w2 = structInputSize (args+0x38)
0xfffffff00a34be28:  ff 02 00 f1   cmp	x23, #0
0xfffffff00a34be2c:  40 18 4d 7a   ccmp	w2, #0xd, #0, ne      ; floor: structInputSize >= 0xd
...
0xfffffff00a34be3c:  e3 03 14 aa   mov	x3, x20
0xfffffff00a34be40:  f0 0d 00 94   bl	0xfffffff00a34f600    ; the worker
```

## Output (real) — worker `0xfffffff00a34f600`

```asm
0xfffffff00a34f640:  c8 42 37 8b   add	x8, x22, w23, uxtw    ; x8 = structInput + structInputSize (end)
0xfffffff00a34f644:  c0 32 00 91   add	x0, x22, #0xc         ; x0 = structInput + 0xc   (slice start)
0xfffffff00a34f648:  01 01 00 cb   sub	x1, x8, x0            ; x1 = end - start = structInputSize - 0xc
0xfffffff00a34f64c:  02 00 80 d2   mov	x2, #0
0xfffffff00a34f650:  d7 34 00 94   bl	__stub_fffffff00b28f330   ; deserializer(ptr, len, 0)
```

(In the worker, `x22 = structInput` and `w23 = structInputSize`, moved from `x1`/`x2` in the
prologue at `0xfffffff00a34f624` / `0xfffffff00a34f620`.)

## Annotation (bytes → claim)

- The wrapper floors `structInputSize >= 0xd` (`ldr w2,[x24,#0x38]` then `ccmp w2,#0xd`) before
  `bl 0xfffffff00a34f600`, so the worker never sees a payload shorter than `0xd` bytes — the
  `+0xc` header skip below can never run past the buffer.
- The length passed to the deserializer is computed as a **pointer difference**:
  `end = structInput + structInputSize` (`add x8, x22, w23, uxtw`), `start = structInput + 0xc`
  (`add x0, x22, #0xc`), `len = end − start` (`sub x1, x8, x0`). This yields
  `len = structInputSize − 0xc` **by construction from the real buffer extent**, not from an
  attacker-controlled length field — so the classic "length field > actual buffer" mismatch cannot
  occur here.
- `0xfffffff00b28f330` is the length-aware deserializer: it is invoked as `(buf = structInput+0xc,
  len = structInputSize−0xc, flags = 0)`. Every byte it is permitted to touch lies inside the
  `IOUserClient2022`-validated `structInput[0 .. structInputSize)` region. Bounded.
- Honest residual: the deserializer's own internal field walking (`0xfffffff00b28f330` downstream)
  and the remaining IOSurface value-workers were not exhaustively drilled; this evidence establishes
  only that the *entry* into the deserializer is a correctly-bounded slice.
