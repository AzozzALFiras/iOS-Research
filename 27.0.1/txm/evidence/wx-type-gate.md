# Evidence — TXM W^X per-page type gate: exec path requires frame type `0xe` (27.0.1)

**Claim.** In the per-page mapping decision `FUN_0x170308cc`, the executable-mapping (CODE) path is
entered **only** when the per-page frame-metadata **type** byte equals `0xe`. The type is read by
`FUN_0x1703cfd0`; any other type falls through to `FUN_0x17039970(0x90)`, TXM's violation handler
(fail-closed). This is the gate that refutes the "uncovered-tail exec-map bypass": a validator
retypes the uncovered tail of a signed region to `0x3b` (via a `CallSupervisor(0)` privileged type
write that XNU cannot forge), and `0x3b != 0xe`, so the tail can never be exec-mapped.

Binary: `/root/ios-research/analysis/sptm/bins/2701/txm_2701.bin` (Mach-O arm64e, TXM `v7.0.0`,
build 27.0.1). All addresses are unslid monitor VAs; the Ghidra `FUN_0x170308cc` name maps to VA
`0xfffffff0170308cc`.

## Reproduce

```sh
B=/root/ios-research/analysis/sptm/bins/2701/txm_2701.bin
# The type read + the 0xe gate:
ipsw macho disass "$B" --vaddr 0xfffffff017030908 --count 30
# The else-branch target (the violation/panic call with code 0x90):
ipsw macho disass "$B" --vaddr 0xfffffff017030e10 --count 4
```

## Output (real) — the gate in `FUN_0x170308cc`

```asm
0xfffffff01703090c:  b1 31 00 94   bl	0xfffffff01703cfd0    ; w0 = per-page frame type (FUN_0x1703cfd0)
...
0xfffffff017030974:  7f 42 00 71   cmp	w19, #0x10            ; type == 0x10 ?
0xfffffff017030978:  e0 07 00 54   b.eq	loc_fffffff017030a74
0xfffffff01703097c:  7f 3e 00 71   cmp	w19, #0xf             ; type == 0xf ?
0xfffffff017030980:  00 04 00 54   b.eq	loc_fffffff017030a00
0xfffffff017030984:  7f 3a 00 71   cmp	w19, #0xe             ; type == 0xe ?  (the CODE path)
0xfffffff017030988:  41 24 00 54   b.ne	loc_fffffff017030e10  ; type != 0xe  -> violation
0xfffffff017030990:  1f 05 00 71   cmp	w8, #0x1              ; (fall-through: CODE path continues)
```

## Output (real) — the else-branch: violation handler with code `0x90`

```asm
0xfffffff017030e10:  00 12 80 52   mov	w0, #0x90             ; violation code 0x90
0xfffffff017030e14:  01 00 80 52   mov	w1, #0
0xfffffff017030e18:  d6 22 00 94   bl	0xfffffff017039970    ; FUN_0x17039970 (TXM violation handler)
```

For context, `FUN_0x17039970` is TXM's violation reporter — it formats the monitor-fault string
`"[code: 0x%08X | %u]"` and drives the fault-reporting path:

```asm
0xfffffff0170399c8:  60 fe ff 90   adrp	x0, 0xfffffff017005000
0xfffffff0170399cc:  00 fc 25 91   add	x0, x0, #0x97f ; "[code: 0x%08X | %u]"
```

## Annotation (bytes → claim)

- `bl 0xfffffff01703cfd0` returns the per-page frame-metadata **type** byte (the classifier reads
  `meta+2` from the managed-frame table). It is moved into `w19` and used as the switch key.
- The switch dispatches types `0x10` and `0xf` to their own handlers, then tests `cmp w19, #0xe`.
  **`b.ne loc_fffffff017030e10`** means: if the type is anything other than `0xe`, control leaves
  the exec/code handling entirely. The CODE path (W^X "allow executable") is the fall-through at
  `0xfffffff017030990`, reachable **only** when `type == 0xe`.
- The `b.ne` target `0xfffffff017030e10` loads violation code **`0x90`** and calls
  `FUN_0x17039970` — the monitor's fail-closed violation path, not a soft-return. A non-`0xe` frame
  is therefore *rejected*, never mapped executable.
- This is the concrete refutation of the uncovered-tail bypass: because a validated region's tail is
  retyped to `0x3b` (not `0xe`) by the validator's privileged `CallSupervisor(0)` write, and XNU
  cannot set a frame's type to `0xe` itself, an uncovered-tail page hitting this gate takes the
  `type != 0xe` branch into the `0x90` violation. The `+0x18` "validated-cache" fast-path only ever
  applies to pages that are already type `0xe` (covered code). **No code-signing / W^X bypass.**
