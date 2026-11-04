# Evidence — `sptm_retype` core & the type-descriptor table (27.0.1)

**Claim.** The retype core is `FUN_0xfffffff0270ece94`. It (a) rejects non-16KiB-aligned or
out-of-managed-window physical addresses, (b) bounds both the source and target type with
`type < 0x44` (i.e. `type ≤ 0x43`), (c) bumps an in-flight counter and claims a per-page exclusive
lock via a 16-bit CAS on the Frame Table Entry, (d) indexes the **type-descriptor table at
`0xfffffff027092230`** with a **0x90-byte stride**, and (e) special-cases **type `0x0b`
(`XNU_DEFAULT`)**. The descriptor table carries the sanity magic **`0xacce55ed`** at `+8` of each
entry.

Binary: `sptm_2701.bin` (`SPTM-820.0.22`).

## Reproduce — retype prologue / core

```
ipsw macho disass /root/ios-research/analysis/sptm/bins/2701/sptm_2701.bin \
  -a 0xfffffff0270ece94 -c 60 --quiet
```

### Output (real, trimmed to the load-bearing lines)

```asm
0xfffffff0270ece94:  7f 23 03 d5   pacibsp
...
0xfffffff0270ececc:  6a 36 40 92   and	x10, x19, #0x3fff        ; low 14 bits of paddr
0xfffffff0270eced0:  5f 01 00 f1   cmp	x10, #0
0xfffffff0270eced4:  60 02 48 fa   ccmp	x19, x8, #0, eq          ; paddr vs managed_start
0xfffffff0270eced8:  62 22 49 fa   ccmp	x19, x9, #0x2, cs        ; paddr vs managed_end
0xfffffff0270ecedc:  e2 2c 00 54   b.hs	0xfffffff0270ed478       ; fault: unaligned / out-of-window
0xfffffff0270ecee4:  e9 1e 00 12   and	w9, w23, #0xff
0xfffffff0270ecee8:  3f 11 01 71   cmp	w9, #0x44                ; target type < 0x44
0xfffffff0270eceec:  e2 2e 00 54   b.hs	0xfffffff0270ed4c8
0xfffffff0270ecef4:  a9 1e 00 12   and	w9, w21, #0xff
0xfffffff0270ecef8:  3f 11 01 71   cmp	w9, #0x44                ; source type < 0x44
0xfffffff0270ecefc:  a2 2e 00 54   b.hs	0xfffffff0270ed4d0
0xfffffff0270ecf08:  39 fb 3e d5   mrs	x25, tpidr_gl2
0xfffffff0270ecf10:  29 63 4b f9   ldr	x9, [x25, #0x16c0]
0xfffffff0270ecf14:  29 05 00 91   add	x9, x9, #0x1
0xfffffff0270ecf18:  29 63 0b f9   str	x9, [x25, #0x16c0]       ; bump in-flight retype depth
0xfffffff0270ecf1c:  68 02 08 cb   sub	x8, x19, x8              ; paddr - managed_start
0xfffffff0270ecf20:  08 fd 4e d3   lsr	x8, x8, #0xe             ; >> 14  => FTE index (16 KiB pages)
0xfffffff0270ecf24:  29 fd ff b0   adrp	x9, 0xfffffff027091000
0xfffffff0270ecf28:  29 91 42 f9   ldr	x9, [x9, #0x520]         ; frame-table base = DAT_...27091520
0xfffffff0270ecf2c:  34 51 28 8b   add	x20, x9, w8, uxtw #0x4   ; &FTE = base + index*0x10
0xfffffff0270ecf30:  28 00 80 52   mov	w8, #0x1
0xfffffff0270ecf34:  88 7e ea 48   casah	w10, w8, [x20]           ; CAS word0: claim in-flight lock
0xfffffff0270ecf38:  89 0a 40 39   ldrb	w9, [x20, #0x2]          ; w9 = current type (FTE+2)
0xfffffff0270ecf3c:  5f 01 00 71   cmp	w10, #0
0xfffffff0270ecf40:  e1 2e 00 54   b.ne	0xfffffff0270ed51c       ; already locked -> fault
0xfffffff0270ecf44:  28 0d 09 8b   add	x8, x9, x9, lsl #0x3     ; x8 = type * 9
0xfffffff0270ecf48:  3b fd ff d0   adrp	x27, 0xfffffff027092000
0xfffffff0270ecf4c:  7b c3 08 91   add	x27, x27, #0x230         ; type-desc table @ 0xfffffff027092230
0xfffffff0270ecf50:  78 13 08 8b   add	x24, x27, x8, lsl #0x4   ; &desc = table + (type*9)<<4 = + type*0x90
0xfffffff0270ecf78:  3f 2d 00 71   cmp	w9, #0xb                 ; type == 0x0b (XNU_DEFAULT)?
0xfffffff0270ecf7c:  e1 01 00 54   b.ne	0xfffffff0270ecfb8       ; 0x0b handled on a dedicated path
```

## Annotation (bytes → claim)

- **Alignment + window:** `and x10,x19,#0x3fff` + the two `ccmp`s fault any paddr that is not
  16 KiB-aligned or lies outside `[managed_start, managed_end)`.
- **Type bound:** both source and target are `and …,#0xff` then `cmp #0x44 / b.hs`, so only
  `type ∈ [0x00, 0x43]` reaches the lattice — the `0x44+` `VIOLATION_*` ids are unreachable through
  retype.
- **FTE index:** `(paddr − managed_start) >> 0xe` with `0x10`-byte entries → the 16-byte FTE at
  `DAT_…91520 + index*0x10`. The `casah` (16-bit CAS-acquire-half) on word0 is the per-page
  in-flight exclusive lock; the type byte is read from **FTE+2**.
- **0x90 stride:** `type*9` then `<< 4` = `type*0x90`, added to **`0xfffffff027092230`** — the
  type-descriptor table base and stride exactly as claimed.
- **Type 0x0b:** `cmp w9,#0xb / b.ne` routes `XNU_DEFAULT` to its own handler path (see
  [`retype-commit-handlers.md`](retype-commit-handlers.md)).

## Reproduce — the `0xacce55ed` descriptor magic

```
ipsw macho disass /root/ios-research/analysis/sptm/bins/2701/sptm_2701.bin \
  -a 0xfffffff027092230 -c 8 --quiet
```

### Output (real — the disassembler mis-decodes the data; read the bytes)

```asm
0xfffffff027092230:  01 06 00 00   ...        ; entry[0]: +1 class=0x01
0xfffffff027092234:  88 88 03 00   ...
0xfffffff027092238:  ed 55 ce ac   ...        ; +8: 0xacce55ed (little-endian) = the sanity magic
0xfffffff02709223c:  05 ff 46 08   ...
```

Entry[0] raw (first 0x30 of the 0x90-byte record), and the file-wide magic count:

```
entry0 bytes: 0106000088880300 ed55ceac 05ff4608 0000000000000000 0000000000000000 0000000000000000 ffffffffffffffff
first 0xacce55ed at file offset 0x8e238
total 0xacce55ed occurrences in file: 70
```

## Annotation

- The little-endian word at descriptor `+8` is **`0xacce55ed`** ("access-ed"), the per-entry sanity
  magic the retype path checks before trusting a descriptor.
- The retype bound (`type < 0x44`) makes **68 type indices (0x00–0x43)** reachable; the magic itself
  appears **70×** in the binary (the descriptor table plus two non-table occurrences), so "68
  reachable types" is a statement about the retype bound, not a raw magic count.
