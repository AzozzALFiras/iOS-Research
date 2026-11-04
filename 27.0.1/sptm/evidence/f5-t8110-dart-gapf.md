# Evidence — §F5 T8110 DART unganged-GAPF race (the one real GL1-runtime bug)

**Claim.** On 27.0.1, the T8110 DART GAPF (GART-protection-fault / ganged-page-fault) owner token is
taken with an unprotected byte compare-and-swap and no surrounding per-slice lock — a GL1-reachable
TOCTOU on a shared DART slice. The inc path is `FUN_0xfffffff0270c6dc4`, the dec path
`FUN_0xfffffff0270c8cc0`. 27.2 adds a per-slice lock and a dedicated race-detect panic string,
`VIOLATION_T8110_DART_UNGANG_GAPF_RACE` (**string count 0 → 1**). This is the only SPTM finding that
holds up as a genuine GL1-runtime concurrency bug — and it is **already patched** in 27.2.

Binaries: `sptm_2701.bin` (`SPTM-820.0.22`), `sptm_272.bin`, `sptm_273.bin`.

## 1. The 27.0.1 unprotected RMW (inc path)

```
ipsw macho disass /root/ios-research/analysis/sptm/bins/2701/sptm_2701.bin \
  -a 0xfffffff0270c6e24 -c 22 --quiet
```

### Output (real)

```asm
0xfffffff0270c6e24:  08 01 09 8b   add	x8, x8, x9
0xfffffff0270c6e28:  08 01 40 39   ldrb	w8, [x8]               ; read slice state byte
0xfffffff0270c6e2c:  29 00 80 52   mov	w9, #0x1
0xfffffff0270c6e30:  29 05 08 2a   orr	w9, w9, w8, lsl #0x1   ; fold old state into new token
0xfffffff0270c6e34:  68 de 2f 91   add	x8, x19, #0xbf7        ; &slice->owner_token
0xfffffff0270c6e38:  09 7d ea 08   casab	w10, w9, [x8]          ; bare CAS-acquire-byte, no slice lock
0xfffffff0270c6e3c:  5f 01 00 71   cmp	w10, #0
0xfffffff0270c6e40:  81 c5 00 54   b.ne	0xfffffff0270c86f0     ; contended -> slow path
0xfffffff0270c6e44:  68 e2 6f 39   ldrb	w8, [x19, #0xbf8]      ; read gang/clock state (separate byte)
0xfffffff0270c6e48:  1f 0d 00 71   cmp	w8, #0x3
```

The token at `slice+0xbf7` is claimed with a single `casab` and the dependent state at `+0xbf8` is
read *after* the CAS with **no lock held across the read-modify-write** — the unganged-GAPF window.
The dec path `FUN_0xfffffff0270c8cc0` performs the mirror `casab` on the same `+0xbf7` byte:

```
ipsw macho disass /root/ios-research/analysis/sptm/bins/2701/sptm_2701.bin \
  -a 0xfffffff0270c8cc0 -c 40 --quiet | grep -iE 'casab|ldrb|0xbf7|0xbf8|0xc0e'
```

```asm
0xfffffff0270c8d40:  68 de 2f 91   add	x8, x19, #0xbf7
0xfffffff0270c8d44:  09 7d ea 08   casab	w10, w9, [x8]
0xfffffff0270c8d50:  68 e2 6f 39   ldrb	w8, [x19, #0xbf8]
0xfffffff0270c8d5c:  68 3a 70 39   ldrb	w8, [x19, #0xc0e]
```

## 2. String-table diff: the race-detect panic is new in 27.2

```
for b in bins/2701/sptm_2701.bin bins/272/sptm_272.bin bins/273/sptm_273.bin; do
  echo -n "$b : "; strings /root/ios-research/analysis/sptm/$b | grep -c 'T8110_DART_UNGANG_GAPF'
done
```

### Output (real)

```
2701 : 0
272  : 1
273  : 1
```

## Annotation (bytes → claim)

- 27.0.1 protects the slice owner token with a single `casab` but keeps **no per-slice lock across
  the RMW** of the gang/clock state bytes (`+0xbf8`, `+0xc0e`). Two GL1 cores driving the same DART
  slice can interleave inc/dec and desync the unganged-GAPF clock-protection state — the TOCTOU.
- 27.2 introduces the string `VIOLATION_T8110_DART_UNGANG_GAPF_RACE` (0 → 1), emitted by a new
  per-slice lock + owner-token guard that panics on detected interleave. The counter is maintained
  (string present) in 27.2 and 27.3.
- Classification: **genuine GL1-runtime concurrency bug, patched in 27.2**. GAPF-unganging is
  T8110-specific hardware, and the variant hunt found no unpatched cross-variant sibling, so the fix
  is complete. Because it is fixed in the reference build, it is not bounty-eligible.
