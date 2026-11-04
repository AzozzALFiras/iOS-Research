# Evidence — pmm_exclave XNU-boundary bounds (IPC register + conclave id)

Backs finding #3 in [`../README.md`](../README.md) and [`../reports/pmm.md`](../reports/pmm.md).

## Binary / tooling

- Binary: `exclavecore_bundle` → `APP/pmm_exclave` (C, 589824 B). On kd-app:
  `/root/ios-research/analysis/exclaves/2701/extracted/APP/pmm_exclave` with its `.a2s` name cache.
  Build 27.0.1.
- Disassembler: `ipsw macho disass -a <vaddr> -c <count>` (resolves VAs and panic-string references
  from the Mach-O itself). Decomp cross-ref: `/root/ios-research/analysis/exports/pmm_2701_decomp.c`.

## Claim

Every XNU-controlled scalar reaching a sink is dominated by a bound/overflow check that traps
(`brk #0x5519` = `SoftwareBreakpoint`, or a `panic`-string fatal). Two representative dominating
guards: (a) the Tightbeam IPC "set message register" index is bounded `< 0x37`; (b) a frame's
conclave id is bounded `<= 0x3f` (`b.hs #0x40` → fatal).

## Reproduction

```sh
PMM=/root/ios-research/analysis/exclaves/2701/extracted/APP/pmm_exclave
# (a) IPC set-message-register bound  (FUN_08019470)
ipsw macho disass -a 0x08019470 -c 12 $PMM
# (b) conclave-id bound + fatal  (inside FUN_07ffede0; see pmm_2701_decomp.c line ~1806)
ipsw macho disass -a 0x07ffee54 -c 10 $PMM
ipsw macho disass -a 0x07ffef00 -c 3  $PMM   # the fatal call + format string
```

## Disassembly (pulled 27.0.1)

(a) IPC message-register index bound — `FUN_08019470`:

```
0x08019470:  cmp   w0, #0x37
0x08019474:  b.hs  0x80194c0                 ; index >= 0x37 -> fatal
0x08019478:  mrs   x8, tpidrro_el0
0x0801947c:  add   x8, x8, w0, uxtw #0x3     ; &mr[index]  (only reached when index < 0x37)
...
0x080194c0:  (fatal) adrp/add x1 -> "set message register %d out of bounds (max %d)\n"; bl 0x8015730
```

(b) conclave-id bound and its fatal — `FUN_07ffede0`:

```
0x07ffee54:  ldrh  w8, [x8, #0x4]            ; 16-bit conclave id
0x07ffee58:  cmp   w8, #0x40
0x07ffee5c:  b.hs  0x7ffeee8                 ; id >= 0x40 (i.e. > 0x3f) -> fatal
0x07ffee60:  mov   w9, #0xc0
0x07ffee64:  umaddl x8, w8, w9, x0           ; base + id*0xc0  (reached only when id <= 0x3f)
0x07ffee68:  adds  x8, x8, #0x180
            ... ccmp/b.ls range-check, else:
0x07ffee8c:  brk   #0x5519                   ; SoftwareBreakpoint on range violation
...
0x07ffeee8:  (fatal) mov w9,#0x40 ; stp id,max
0x07ffef00:  adrp  x0, 0x8067000
0x07ffef04:  add   x0, x0, #0x632            ; "FrameTag_Conclave with ID greater than max. Requested: %hu Max: %hu"
0x07ffef08:  bl    0x8042890                 ; fatal handler
```

## Annotation

- (a) `cmp w0,#0x37; b.hs` dominates the `&mr[index]` address computation: the message-register index
  XNU supplies can never index past the 0x37-entry register window; a violation branches to a
  non-returning panic naming the exact bound (`max 0x37`).
- (b) `cmp w8,#0x40; b.hs` is the `id <= 0x3f` conclave bound (0x40 = 63+1); the id then scales the
  per-conclave `0xc0`-byte structure via a widening `umaddl`, and the resulting pointer is itself
  range-checked (`adds #0x180; ccmp; brk #0x5519`). The fatal path reconstructs `Max = 0x40` and
  references the `FrameTag_Conclave ... greater than max` panic string (confirmed by `ipsw`'s own
  symbol resolution), matching `pmm_2701_decomp.c:1806` `if (0x3f < id) fatal(...)`.

**Verdict:** hardened. No XNU-controlled index/count/id reaches a sink without a dominating trap.
