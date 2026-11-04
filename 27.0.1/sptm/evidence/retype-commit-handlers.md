# Evidence — retype commit handlers: W^X scrub vs. type 0x0b no-op (27.0.1)

**Claim (finding §3 / the W^X question).** The retype "commit" step is a per-target-type handler.
For page-table target types the handler is `FUN_0xfffffff0270e0a08`, a tail-call to
**`bzero(target, 0x4000)`** — the destination page is zeroed, so no attacker-controlled stale PTEs
survive a →page-table retype. For type **`0x0b` (`XNU_DEFAULT`)** the handler is
`FUN_0xfffffff0270e0a2c` = **`bti c; ret`** — a no-op. `0x0b` is the *release* direction (a page
going back to generic XNU-default has nothing to scrub); the dangerous edge
(`XNU_DEFAULT → page-table`) is keyed on the **target** type, so it still hits the `bzero` handler.
**No W^X bypass.**

Binary: `sptm_2701.bin` (`SPTM-820.0.22`).

## Reproduce

```
ipsw macho disass /root/ios-research/analysis/sptm/bins/2701/sptm_2701.bin \
  -a 0xfffffff0270e0a08 -c 20 --quiet
```

## Output (real)

```asm
0xfffffff0270e0a08:  5f 24 03 d5   bti	c                        ; FUN_...e0a08  (page-table target)
0xfffffff0270e0a0c:  e0 03 01 aa   mov	x0, x1                   ; x0 = target page
0xfffffff0270e0a10:  01 00 88 52   mov	w1, #0x4000              ; length = 0x4000 (16 KiB)
0xfffffff0270e0a14:  02 00 80 92   mov	x2, #0xffffffffffffffff  ; fill = -1 sentinel
0xfffffff0270e0a18:  70 16 ff 17   b	0xfffffff0270a63d8       ; tail-call bzero/memset

0xfffffff0270e0a1c:  5f 24 03 d5   bti	c                        ; (neighbour no-op slot)
0xfffffff0270e0a20:  c0 03 5f d6   ret
0xfffffff0270e0a24:  5f 24 03 d5   bti	c
0xfffffff0270e0a28:  c0 03 5f d6   ret

0xfffffff0270e0a2c:  5f 24 03 d5   bti	c                        ; FUN_...e0a2c  (type 0x0b handler)
0xfffffff0270e0a30:  c0 03 5f d6   ret                          ; no-op: bti c ; ret
```

## Annotation (bytes → claim)

- `FUN_0xfffffff0270e0a08`: `mov x0,x1 ; mov w1,#0x4000 ; b <memset>` zeroes the **0x4000-byte**
  target page and tail-calls out. Every retype whose **target** is a page-table type dispatches this
  handler, so a freshly-typed page table is always scrubbed regardless of what the page held before.
- `FUN_0xfffffff0270e0a2c`: `bti c ; ret` — the `0x0b` (`XNU_DEFAULT`) commit handler does nothing.
  This is correct: `→0x0b` is the benign release direction; zeroing a page being handed back to the
  generic XNU pool is unnecessary.
- Because the scrub is **target-type-keyed**, the attacker cannot reach a page-table type without
  going through `FUN_...e0a08`. There is no `XNU_DEFAULT → page-table` edge that skips the zeroing.
