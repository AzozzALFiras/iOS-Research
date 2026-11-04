# Evidence — kernel-zone persistence in iOS 27.2 (24B119)

Pulled disassembly confirming `proc_task`, SPRR gating, and reader-gating persist from 27.0.1 with
only address shifts. KC = `/root/ios-research/extracted/27.2/24B119__iPhone17,2/kernelcache.release.iPhone17,2`.

## proc_task accessor + re-resolved zone-range anchor — `0xfffffff00ac94938`

```sh
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00ac94938 -c 10 --quiet"
```

```asm
0xfffffff00ac94938:  bti  c
0xfffffff00ac9493c:  subs x1, x0, #0x768            ; proc = task - 0x768   (identical to 27.0.1)
0xfffffff00ac94944:  adds x8, x1, #0xe38            ; element size 0xe38    (identical)
0xfffffff00ac9494c:  adrp x9, 0xfffffff007df2000
0xfffffff00ac94950:  add  x9, x9, #0x40             ; zone-range anchor @ 0xfffffff007df2040
0xfffffff00ac94954:  ldp  x10, x9, [x9]             ; {base,bound}
0xfffffff00ac94958:  cmp  x1, x10
0xfffffff00ac9495c:  ccmp x8, x10, #0, cs
```

## SPRR flip in `pmap_ro_zone_memcpy` — `0xfffffff00ad7cd40`

```sh
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00ad7cd38 -c 10 --quiet"
```

```asm
0xfffffff00ad7cd3c:  bl   0xfffffff00ad7ce2c        ; validate dst element  [BEFORE flip]
0xfffffff00ad7cd40:  mrs  x8, sprr_pperm_el1
0xfffffff00ad7cd44:  mov  x9, #0xb                  ; RW
0xfffffff00ad7cd48:  bfi  x8, x9, #0x8, #0x4
0xfffffff00ad7cd4c:  msr  sprr_pperm_el1, x8
0xfffffff00ad7cd50:  isb
```

Whole-fileset invariants: `grep -c sprr_pperm_el1` → **30**; `grep -c 'strh\tw8, [x10, #0x2]$'` →
**2**; `grep -c 'bl.*0xfffffff00ac917e8$'` (zalloc_ro_mut) → **54**.

## Hot cred reader — `0xfffffff00ac94ad0` (1060 callers)

```sh
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00ac94ad0 -c 40 --quiet"
```

```asm
0xfffffff00ac94ad0:  pacibsp
        ... mrs x0, tpidr_el1 ; ldr x1, [x0, #0x418]  (t_tro, same offset) ...
0xfffffff00ac94b38:  cmp  w8, #0x3                  ; thread_ro zone-id (identical)
0xfffffff00ac94b40:  ldr  x8, [x1]                  ; backref
0xfffffff00ac94b44:  cmp  x8, x0                    ; == current thread
```

`grep -cE '(bl|\bb)\t.*0xfffffff00ac94ad0$'` → **1060**.

## Reading

Every structural element matches 27.0.1 ([`../../../27.0.1/kernel-zone/evidence/`](../../../27.0.1/kernel-zone/evidence/));
only addresses shifted. No metadata-submap lockdown, no `msr` trap, no `proc_task` change.
