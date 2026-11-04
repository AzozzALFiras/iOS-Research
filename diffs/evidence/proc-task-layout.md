# Evidence — `proc_task` zone layout stable through 27.3 beta (address shift only)

**Claim.** The `proc_task` zone parameters are unchanged across 27.0.1/27.2/27.3: element size
`0xe38`, flags `0x02000001`, zone-id `0x1a`, and `task = proc + 0x768`. Only the host VA of the
`zone_create_ext` call site shifts with the build. See
[kernel-zone proc-task-layout](../../27.0.1/kernel-zone/reports/proc-task-layout.md).

## (a) Reproduction

```sh
KC=extracted/27.3/24C5037i__iPhone17,2/kernelcache.release.iPhone17,2
# call site located by zone_create immediates (w1=elem, w3=zone-id), NOT by reusing a 27.0.1 VA:
ipsw macho disass -t com.apple.kernel --vaddr 0xfffffff00ad3e414 --count 12 -q "$KC"
ipsw macho disass -t com.apple.kernel --vaddr 0xfffffff00ad3e454 --count 1  -q "$KC"
```

## (b) Disassembly (pulled, 27.3 beta)

```asm
0xfffffff00ad3e414:  adrp x0, 0xfffffff00705a000
0xfffffff00ad3e418:  add  x0, x0, #0xb42              ; "proc_task"
0xfffffff00ad3e41c:  mov  w1, #0xe38                  ; element size   = 0xe38
0xfffffff00ad3e420:  mov  w2, #0x1
0xfffffff00ad3e424:  movk w2, #0x200, lsl #0x10       ; flags          = 0x02000001
0xfffffff00ad3e428:  mov  w3, #0x1a                   ; zone-id        = 0x1a
0xfffffff00ad3e42c:  mov  x4, #0
0xfffffff00ad3e430:  bl   0xfffffff00ad73254           ; zone_create_ext
...
0xfffffff00ad3e454:  add  x8, x0, #0x768              ; task = proc + 0x768
```

## (c) Annotation

- `w1=#0xe38`, `w2=0x02000001` (via `mov #1` + `movk #0x200,lsl16`), `w3=#0x1a`, and the
  `add x8,x0,#0x768` intra-element offset are identical to the 27.0.1 and 27.2 values — only the call
  site VA moved (27.0.1 `…ac58d7c` → 27.2 `…ac58d7c` → 27.3 `…ad3e414`; the "+0x768" add at
  27.3 `…ad3e454`). This is the "note the 27.3 address shift" caveat: structures were relocated by
  immediate-pattern search, never by reusing a prior build's address.
- zone-id `0x1a` stable confirms the zone-id-forgery reasoning in the trust boundary still applies
  unchanged (forgeable under full R/W; blocked at the RO-zone wall — see [sprr-ro-wall.md](sprr-ro-wall.md)).
</content>
