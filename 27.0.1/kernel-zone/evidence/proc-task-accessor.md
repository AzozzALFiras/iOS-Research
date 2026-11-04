# Evidence — `proc_task` layout via `get_bsdtask_info` (27.0.1)

**Claim.** The `proc_task` zone co-allocates `[ proc | task ]` in one element: `task = proc + 0x768`,
element size `0xe38`, zone-id `0x1a`. The accessor at unslid `0xfffffff00ac4b408` derives `proc` from
`task` and bounds-checks the element against the zone-range anchor `0xfffffff007de5de0`.

## (a) Reproduction

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00ac4b408 -c 12 --quiet"
```

## (b) Disassembly (pulled)

```asm
sub_fffffff00ac4b408:                                  ; get_bsdtask_info
0xfffffff00ac4b408:  bti  c
0xfffffff00ac4b40c:  subs x1, x0, #0x768               ; proc = task - 0x768
0xfffffff00ac4b410:  b.eq loc_fffffff00ac4b45c         ; task==0x768 -> NULL proc
0xfffffff00ac4b414:  adds x8, x1, #0xe38               ; proc + element_size(0xe38)
0xfffffff00ac4b418:  b.hs loc_fffffff00ac4b46c
0xfffffff00ac4b41c:  adrp x9, 0xfffffff007de5000
0xfffffff00ac4b420:  add  x9, x9, #0xde0               ; &anchor @ 0xfffffff007de5de0 (__DATA_CONST)
0xfffffff00ac4b424:  ldp  x10, x9, [x9]                ; x10=zone base, x9=zone bound
0xfffffff00ac4b428:  cmp  x1, x10
0xfffffff00ac4b42c:  ccmp x8, x10, #0, cs
0xfffffff00ac4b430:  ccmp x8, x9,  #0x2, cs
0xfffffff00ac4b434:  b.hi loc_fffffff00ac4b46c         ; element not in [base,bound] -> fail
```

## (c) Annotation

- `subs x1, x0, #0x768` fixes the intra-element offset: given `task` (x0), `proc = task − 0x768`.
- `adds x8, x1, #0xe38` forms `proc + 0xe38`, i.e. the element size is `0xe38`; the pair + `ccmp`
  sequence is the standard zone-range containment test against the `__DATA_CONST` anchor
  `0xfffffff007de5de0` (a `{base,bound}` pair, loaded with one `ldp`).
- The same anchor address is used by `zone_id_require` (see [`zone-id-require.md`](zone-id-require.md)),
  confirming it is the zone-map range pair. zone-id `0x1a` for this element is established at the
  `zone_id_require` sites.
- Layout is XNU-build-determined, so it holds for all 27.0.1 (24A446) devices; the kernelcache on
  hand is iPhone17,2. Cross-checked against the public Chollima/Calif.io 27.0.1 demo leak
  (`Δ(proc,task) = 0x768`).
