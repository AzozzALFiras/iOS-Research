# Evidence — SPTM dispatch state machine (27.0.1)

**Claim.** GL1→SPTM calls go through a two-stage, PAC-adjacent dispatcher built as a state machine:
`state < 0x17`, `event < 0xf` (i.e. `event ≤ 0xe`), transition table indexed
`base + state*0x1e0 + event*0x20`.

Binary: `sptm_2701.bin` (`SPTM-820.0.22`, iPhone17,2). All addresses are unslid monitor VAs.

## Reproduce

```
ipsw macho disass /root/ios-research/analysis/sptm/bins/2701/sptm_2701.bin \
  -a 0xfffffff0270e5b2c -c 28 --quiet
```

## Output (real)

```asm
0xfffffff0270e5b2c:  7f 23 03 d5   pacibsp
0xfffffff0270e5b30:  ff 43 03 d1   sub	sp, sp, #0xd0
...
0xfffffff0270e5b54:  08 f8 3e d5   mrs	x8, currentg
0xfffffff0270e5b58:  28 13 00 b4   cbz	x8, 0xfffffff0270e5dbc
0xfffffff0270e5b5c:  35 fb 3e d5   mrs	x21, tpidr_gl2
0xfffffff0270e5b60:  b5 02 15 aa   orr	x21, x21, x21
0xfffffff0270e5b64:  a8 c2 6c 39   ldrb	w8, [x21, #0xb30]     ; w8 = current state
0xfffffff0270e5b68:  1f 5d 00 f1   cmp	x8, #0x17             ; state < 0x17
0xfffffff0270e5b6c:  e2 12 00 54   b.hs	0xfffffff0270e5dc8    ; else fault
0xfffffff0270e5b70:  1f 3c 00 71   cmp	w0, #0xf              ; event < 0xf  (event <= 0xe)
0xfffffff0270e5b74:  a2 13 00 54   b.hs	0xfffffff0270e5de8    ; else fault
0xfffffff0270e5b78:  ea 03 00 2a   mov	w10, w0
0xfffffff0270e5b7c:  09 d9 77 d3   lsl	x9, x8, #0x9          ; x9 = state * 0x200
0xfffffff0270e5b80:  29 15 08 cb   sub	x9, x9, x8, lsl #0x5  ; x9 -= state * 0x20  => state * 0x1e0
0xfffffff0270e5b84:  cb f9 ff d0   adrp	x11, 0xfffffff02701f000
0xfffffff0270e5b88:  6b 21 20 91   add	x11, x11, #0x808      ; transition-table base = 0xfffffff02701f808
0xfffffff0270e5b8c:  6c 01 09 8b   add	x12, x11, x9          ; base + state*0x1e0
0xfffffff0270e5b90:  70 01 0c ca   eor	x16, x11, x12
0xfffffff0270e5b94:  1f 26 4a f2   tst	x16, #0xffc0000000000000
0xfffffff0270e5b98:  40 00 00 54   b.eq	0xfffffff0270e5ba0    ; bounds-canary on the index
```

## Annotation (bytes → claim)

- `ldrb w8,[x21,#0xb30]` reads the per-GL2-thread **current state** from the `tpidr_gl2` block;
  `cmp x8,#0x17 / b.hs` enforces **`state < 0x17`** (23 states).
- `cmp w0,#0xf / b.hs` enforces the event argument **`event < 0xf`** (`event ≤ 0xe`, 15 events).
- The stride is encoded as `state*0x200 − state*0x20`: `0x200 − 0x20 = 0x1e0`, exactly the claimed
  **`state*0x1e0`** row stride. The event column stride `*0x20` is applied at the next table load
  (`w10 = event`, scaled by the entry size downstream).
- The `eor`/`tst #0xffc0…` pair is an index-overflow canary: it faults if adding `state*0x1e0`
  carried out of the table's address window.
