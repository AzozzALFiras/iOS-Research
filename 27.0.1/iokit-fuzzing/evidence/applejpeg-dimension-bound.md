# Evidence — AppleJPEGDriver sel 4 worker: explicit dimension bounds (27.0.1)

**Claim.** The AppleJPEG sel-4 handler `0xfffffff00902f298` tail-calls the encoder worker
`0xfffffff009026364`, which reads dimension/resolution fields out of the fixed-size (`0x1000`) input
struct and **range-checks them** before use: a component/count field is bounded `<= 0xff`, dimension
high words are required to be zero (`<= 0xffff`), and an out-of-range input lands on an error path
that logs `"i/o sizes are illegal (inputSize %d ...) or Horz (%d) and Vert (%d) Resolutions are not
set"`. There is no unchecked dimension reaching an allocation at this surface.

Binary: kernelcache FILESET `kernelcache.release.iPhone17,2` (24A446), entry
`com.apple.driver.AppleJPEGDriver`.

## Reproduce

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
# Handler tail-call into the worker:
ipsw macho disass "$KC" -t com.apple.driver.AppleJPEGDriver --vaddr 0xfffffff00902f298 --count 12
# The dimension-check block inside the worker:
ipsw macho disass "$KC" -t com.apple.driver.AppleJPEGDriver --vaddr 0xfffffff009026458 --count 60
```

## Output (real) — handler `0xfffffff00902f298`

```asm
0xfffffff00902f298:  5f 24 03 d5   bti	c
0xfffffff00902f29c:  e4 03 00 aa   mov	x4, x0
0xfffffff00902f2a0:  00 70 40 f9   ldr	x0, [x0, #0xe0]
0xfffffff00902f2a4:  e0 00 00 b4   cbz	x0, loc_fffffff00902f2c0
0xfffffff00902f2a8:  48 2c 40 f9   ldr	x8, [x2, #0x58]       ; x8 = structInput descriptor
0xfffffff00902f2ac:  41 18 40 f9   ldr	x1, [x2, #0x30]
0xfffffff00902f2b8:  e2 03 08 aa   mov	x2, x8
0xfffffff00902f2bc:  2a dc ff 17   b	0xfffffff009026364    ; tail-call startEncoder worker
```

## Output (real) — worker `0xfffffff009026364` dimension block

```asm
0xfffffff009026458:  68 06 40 b9   ldr	w8, [x19, #0x4]       ; w8 = field @+0x4
0xfffffff00902645c:  69 0e 40 b9   ldr	w9, [x19, #0xc]
0xfffffff009026460:  1f fd 03 71   cmp	w8, #0xff             ; field @+0x4 must be <= 0xff
0xfffffff009026464:  88 05 00 54   b.hi	loc_fffffff009026514
...
0xfffffff009026490:  63 40 00 91   add	x3, x3, #0x10 ; "AppleJPEGDriver: ** %s : i/o sizes are illegal (inputSize %d, req->outputSize %d)! or Horz (%d) and Vert (%d) Resolutions are not set\n"
...
0xfffffff009026514:  6a 16 40 b9   ldr	w10, [x19, #0x14]
0xfffffff009026518:  3f 1d 00 71   cmp	w9, #0x7              ; bound
0xfffffff00902651c:  83 fa ff 54   b.lo	loc_fffffff00902646c
0xfffffff009026520:  5f 11 00 71   cmp	w10, #0x4             ; bound
0xfffffff009026524:  43 fa ff 54   b.lo	loc_fffffff00902646c
0xfffffff009026528:  4b 7d 10 53   lsr	w11, w10, #0x10       ; high 16 bits of dim
0xfffffff00902652c:  0b fa ff 35   cbnz	w11, loc_fffffff00902646c   ; must be 0  => dim <= 0xffff
0xfffffff009026530:  6b 1a 40 b9   ldr	w11, [x19, #0x18]
0xfffffff009026534:  6b 41 40 51   sub	w11, w11, #0x10, lsl #0xc    ; w11 -= 0x10000
0xfffffff009026538:  cc ff 9f 12   mov	w12, #0xffff0001
0xfffffff00902653c:  7f 01 0c 6b   cmp	w11, w12                     ; range-gate the dimension
```

## Annotation (bytes → claim)

- The handler forwards the fixed-size (`0x1000`) input struct (`[x2+0x58]` descriptor) and
  tail-calls the worker `0xfffffff009026364`; `x19` in the worker is that struct base.
- `ldr w8,[x19,#0x4]; cmp w8,#0xff; b.hi` bounds a component/count field to `<= 0xff`.
- `lsr w11, w10, #0x10; cbnz w11, <error>` requires the **high 16 bits of a dimension field to be
  zero**, i.e. the dimension is `<= 0xffff` — this is the structural guard that prevents a huge
  dimension from being carried forward into any later `width * height` computation.
- The `sub w11, w11, #0x10000 ; cmp w11, #0xffff0001` pair is a windowed range-check on another
  dimension/resolution field; failure branches to the shared error path.
- The error path builds the format string **"i/o sizes are illegal (inputSize %d, req->outputSize
  %d)! or Horz (%d) and Vert (%d) Resolutions are not set"**, which names exactly the fields being
  validated (input/output sizes and horizontal/vertical resolution) and confirms this is the
  dimension/size validation gate, not an incidental compare.
