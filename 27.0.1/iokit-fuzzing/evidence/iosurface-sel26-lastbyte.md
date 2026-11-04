# Evidence — IOSurface sel 26: bounded last-byte NUL check (27.0.1)

**Claim.** Selector 26 (`checkStructureInputSize = VAR`) is a floor-only variable-struct method. Its
dispatch handler (the "wrapper") `0xfffffff00a34c690` floors the input size at `0xd`, then forwards
`(this, resolved-obj, structInput, structInputSize)` to the worker `0xfffffff00a3529c4`, passing the
size in `x3` via `mov x3, x25` where `w25 = [args+0x38] = structInputSize`. The worker reads exactly
one byte at `structInput[structInputSize-1]` (a trailing-NUL check). Because the wrapper floor
guarantees `structInputSize >= 0xd`, the computed index `0xc + (structInputSize - 0xd)` is
non-negative and in-bounds. **Bounded read; no OOB.**

Binary: kernelcache FILESET `kernelcache.release.iPhone17,2` (24A446), entry
`com.apple.iokit.IOSurface`.

## Reproduce

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
# Wrapper (size floor + argument marshalling + call to worker):
ipsw macho disass "$KC" -t com.apple.iokit.IOSurface --vaddr 0xfffffff00a34c6e0 --count 10
ipsw macho disass "$KC" -t com.apple.iokit.IOSurface --vaddr 0xfffffff00a34c7cc --count 4
ipsw macho disass "$KC" -t com.apple.iokit.IOSurface --vaddr 0xfffffff00a34c810 --count 8
# Worker (the last-byte read):
ipsw macho disass "$KC" -t com.apple.iokit.IOSurface --vaddr 0xfffffff00a3529e8 --count 20
```

## Output (real) — wrapper `0xfffffff00a34c690`

```asm
0xfffffff00a34c6e0:  59 38 40 b9   ldr	w25, [x2, #0x38]      ; w25 = structInputSize (args+0x38)
...
0xfffffff00a34c7cc:  ff 02 00 f1   cmp	x23, #0
0xfffffff00a34c7d0:  20 1b 4d 7a   ccmp	w25, #0xd, #0, ne     ; floor: structInputSize >= 0xd
0xfffffff00a34c7d4:  04 2b 40 fa   ccmp	x24, #0, #0x4, cs
0xfffffff00a34c7d8:  c1 01 00 54   b.ne	loc_fffffff00a34c810
...
0xfffffff00a34c810:  e4 13 00 91   add	x4, sp, #0x4          ; x4 = &out scratch
0xfffffff00a34c814:  e0 03 16 aa   mov	x0, x22               ; x0 = this
0xfffffff00a34c818:  e1 03 17 aa   mov	x1, x23               ; x1 = resolved surface object
0xfffffff00a34c81c:  e2 03 18 aa   mov	x2, x24               ; x2 = structInput pointer
0xfffffff00a34c820:  e3 03 19 aa   mov	x3, x25               ; x3 = structInputSize  <<<
0xfffffff00a34c824:  68 18 00 94   bl	0xfffffff00a3529c4    ; <<< the worker
```

## Output (real) — worker `0xfffffff00a3529c4`

```asm
0xfffffff00a3529ec:  f8 03 03 aa   mov	x24, x3               ; x24 = structInputSize
0xfffffff00a3529f0:  f7 03 02 aa   mov	x23, x2               ; x23 = structInput
0xfffffff00a3529f4:  f5 03 01 aa   mov	x21, x1               ; x21 = resolved object
...
0xfffffff00a352a20:  a8 ce 40 38   ldrb	w8, [x21, #0xc]!      ; x21 += 0xc; load flag byte [+0xc]
0xfffffff00a352a24:  48 01 00 34   cbz	w8, loc_fffffff00a352a4c
0xfffffff00a352a28:  e8 03 18 2a   mov	w8, w24               ; w8 = structInputSize
0xfffffff00a352a2c:  08 35 00 d1   sub	x8, x8, #0xd          ; w8 = structInputSize - 0xd
0xfffffff00a352a30:  a8 6a 68 38   ldrb	w8, [x21, x8]         ; load [ (x21=+0xc) + (size-0xd) ]
0xfffffff00a352a34:  28 0a 00 35   cbnz	w8, loc_fffffff00a352b78   ; last byte must be 0 (NUL)
```

## Annotation (bytes → claim)

- The wrapper loads `structInputSize` into **`w25`** from `[x2+0x38]` (the `IOExternalMethodArguments`
  `structureInputSize` slot), and the `ccmp w25, #0xd` is the **floor**: the method proceeds only if
  `structInputSize >= 0xd`.
- Argument marshalling is explicit: `x2 = structInput`, and **`mov x3, x25`** passes
  `structInputSize` as the worker's 4th argument, immediately before `bl 0xfffffff00a3529c4`.
- In the worker, the pre-indexed `ldrb w8, [x21, #0xc]!` advances the pointer to
  `structInput + 0xc` (a format/flag byte). Then `sub x8, x8, #0xd` forms `structInputSize - 0xd`,
  and `ldrb w8, [x21, x8]` dereferences `(structInput + 0xc) + (structInputSize - 0xd)` =
  **`structInput + structInputSize - 1`** — the final byte of the input buffer. `cbnz` requires it
  to be NUL (a defensive C-string terminator check).
- **Bound proof:** the wrapper floor gives `structInputSize >= 0xd`, so `structInputSize - 0xd >= 0`
  and the effective offset `0xc + (structInputSize - 0xd) = structInputSize - 1 < structInputSize`.
  The read is strictly inside the caller-supplied `structInput[0 .. structInputSize)` region that
  the `IOUserClient2022` layer already validated. No under-read, no over-read.
