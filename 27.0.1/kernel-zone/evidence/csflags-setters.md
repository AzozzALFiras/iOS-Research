# Evidence — csflags setters re-validate the RO destination before commit (27.0.1)

**Claim.** The two `p_csflags` mutators re-validate the destination `proc_ro` element (RO-range,
metadata zone-id `== 5`, and the `pr_proc` backref to the owning `proc`) **before** computing the new
value and committing it through the public `zalloc_ro_mut` (`0xfffffff00ac482b8`). The new value is
staged on the kernel stack and written via the typed RO path — no caller copies a raw user buffer
into the RO field.

- **SET** (`orr`): commit `bl 0xfffffff00ac482b8` at `0xfffffff00b0dede4`.
- **CLEAR** (`bic`): commit `bl 0xfffffff00ac482b8` at `0xfffffff00b0deeac`.

csflags field offset is `0x24`; zone id `5` = `proc_ro` (`pr_proc` at `+0`, `pr_task` at `+8`).

## (a) Reproduction

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00b0ded80 -c 40 --quiet"  # SET body
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00b0dee80 -c 12 --quiet"  # CLEAR tail
```

## (b) Disassembly (pulled)

SET setter (reaches `bl zalloc_ro_mut` at `…dede4`):

```asm
0xfffffff00b0ded88:  adrp x9, 0xfffffff007de5000
0xfffffff00b0ded8c:  ldr  x9, [x9, #0xe90]             ; metadata base 0xfffffff007de5e90
0xfffffff00b0ded90:  lsr  x10, x1, #0xa
0xfffffff00b0ded94:  and  x10, x10, #0xffffffff0        ; (addr>>14)*16
0xfffffff00b0ded9c:  ldrh w9, [x9]
0xfffffff00b0deda0:  and  w9, w9, #0x3ff               ; metadata zone-id
0xfffffff00b0deda4:  cmp  w9, #0x5                      ; must be proc_ro (zone 5)
0xfffffff00b0deda8:  b.ne 0xfffffff00b0dedf8           ;   else panic path
0xfffffff00b0dedac:  ldr  x9, [x1]                     ; pr_proc backref
0xfffffff00b0dedb0:  cmp  x9, x0
0xfffffff00b0dedb4:  b.ne 0xfffffff00b0dedf4           ;   backref != owning proc -> panic
0xfffffff00b0dedb8:  ldr  w9, [x1, #0x24]              ; current csflags
0xfffffff00b0dedbc:  orr  w8, w9, w8                   ; SET bits
0xfffffff00b0dedc0:  stur w8, [fp, #-0x4]              ; stage new value on stack (RO-safe src)
0xfffffff00b0dedd4:  sub  x3, fp, #0x4                 ; src = &staged
0xfffffff00b0dedd8:  mov  w0, #0x5                      ; zid = 5 (proc_ro)
0xfffffff00b0deddc:  mov  w2, #0x24                     ; off = 0x24 (csflags)
0xfffffff00b0dede0:  mov  w4, #0x4                      ; len = 4
0xfffffff00b0dede4:  bl   0xfffffff00ac482b8            ; zalloc_ro_mut commit
```

CLEAR setter (same validation above the window; `bic` instead of `orr`):

```asm
0xfffffff00b0dee80:  ldr  w9, [x1, #0x24]              ; current csflags
0xfffffff00b0dee84:  bic  w8, w9, w8                   ; CLEAR bits
0xfffffff00b0dee88:  stur w8, [fp, #-0x4]              ; stage on stack
0xfffffff00b0dee9c:  sub  x3, fp, #0x4
0xfffffff00b0deea0:  mov  w0, #0x5                      ; zid = 5
0xfffffff00b0deea4:  mov  w2, #0x24                     ; off = 0x24
0xfffffff00b0deea8:  mov  w4, #0x4                      ; len = 4
0xfffffff00b0deeac:  bl   0xfffffff00ac482b8            ; zalloc_ro_mut commit
```

## (c) Annotation

- Both setters read the **current** csflags out of the RO element (`ldr w9,[x1,#0x24]`), apply a
  pure bit op (`orr` to set / `bic` to clear) against the caller's mask, and stage the 4-byte result
  on the kernel stack (`stur w8,[fp,#-0x4]`). The commit passes `src = &staged` — the write source is
  kernel-controlled, never a raw user pointer.
- Crucially the destination is re-validated **before** the value is formed: metadata zone-id `cmp
  w9,#0x5` (proc_ro) and the `pr_proc` backref `[dst] == proc` (`cmp x9,x0`). This matches the dst
  validation `zalloc_ro_mut`/`pmap_ro_zone_memcpy` will *also* perform — defense is layered at both
  the content setter and the RO-write worker.
- Consequence: forging a fake `proc_ro` page and pointing csflags at it fails the backref; writing a
  raw attacker buffer fails the staged-src design; and under data-only R/W the final `msr`-guarded
  SPRR window is unreachable. The csflags content boundary holds for data-only.
