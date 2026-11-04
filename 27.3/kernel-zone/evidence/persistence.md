# Evidence — kernel-zone persistence in iOS 27.3 (24C5037i)

Pulled disassembly confirming `proc_task`, SPRR gating, and reader-gating persist from 27.0.1/27.2
with only address shifts. KC = `/root/ios-research/extracted/27.3/24C5037i__iPhone17,2/kernelcache.release.iPhone17,2`.

## proc_task accessor + re-resolved zone-range anchor — `0xfffffff00ad79fd8`

```sh
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00ad79fd8 -c 10 --quiet"
```

```asm
0xfffffff00ad79fd8:  bti  c
0xfffffff00ad79fdc:  subs x1, x0, #0x768            ; proc = task - 0x768   (identical to 27.0.1)
0xfffffff00ad79fe4:  adds x8, x1, #0xe38            ; element size 0xe38    (identical)
0xfffffff00ad79fec:  adrp x9, 0xfffffff007e1a000
0xfffffff00ad79ff0:  add  x9, x9, #0x1b0            ; zone-range anchor @ 0xfffffff007e1a1b0
0xfffffff00ad79ff4:  ldp  x10, x9, [x9]             ; {base,bound}
0xfffffff00ad79ff8:  cmp  x1, x10
0xfffffff00ad79ffc:  ccmp x8, x10, #0, cs
```

## SPRR flip in `pmap_ro_zone_memcpy` — `0xfffffff00ae6388c`

```sh
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00ae63884 -c 10 --quiet"
```

```asm
0xfffffff00ae63888:  bl   0xfffffff00ae63978        ; validate dst element  [BEFORE flip]
0xfffffff00ae6388c:  mrs  x8, sprr_pperm_el1
0xfffffff00ae63890:  mov  x9, #0xb                  ; RW
0xfffffff00ae63894:  bfi  x8, x9, #0x8, #0x4
0xfffffff00ae63898:  msr  sprr_pperm_el1, x8
0xfffffff00ae6389c:  isb
```

Whole-fileset invariants: `grep -c sprr_pperm_el1` → **30**; `grep -c 'strh\tw8, [x10, #0x2]$'` →
**2**; `grep -c 'bl.*0xfffffff00ad76e88$'` (zalloc_ro_mut) → **54**.

## Hot cred reader — `0xfffffff00ad7a170` (1069 callers)

```sh
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00ad7a170 -c 40 --quiet"
```

```asm
0xfffffff00ad7a170:  pacibsp
        ... mrs x0, tpidr_el1 ; ldr x1, [x0, #0x418]  (t_tro, same offset) ...
0xfffffff00ad7a1d8:  cmp  w8, #0x3                  ; thread_ro zone-id (identical)
0xfffffff00ad7a1e0:  ldr  x8, [x1]                  ; backref
0xfffffff00ad7a1e4:  cmp  x8, x0                    ; == current thread
```

`grep -cE '(bl|\bb)\t.*0xfffffff00ad7a170$'` → **1069**.

## Reading

Every structural element matches 27.0.1 ([`../../../27.0.1/kernel-zone/evidence/`](../../../27.0.1/kernel-zone/evidence/));
only addresses shifted (and by a larger, different delta than 27.2). No metadata-submap lockdown, no
`msr` trap, no `proc_task` change.
