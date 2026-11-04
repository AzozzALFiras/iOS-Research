# Evidence — `zalloc_ro_mut` public API vs the internal cold worker (27.0.1)

**★ CORRECTION ★** The public RO-zone mutation entry point is **`0xfffffff00ac482b8`** (54 callers).
Earlier drafts of this repo called `0xfffffff00b4112cc` "`zalloc_ro_mut`" — that address is an
**internal, once-called cold worker**, not the public API. Both facts are shown below with their
call-site counts.

## (a) Reproduction

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
# the public API
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00ac482b8 -c 20 --quiet"
# the internal cold worker
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00b4112cc -c 30 --quiet"
# call-site counts (from a full-fileset disassembly dumped to /tmp/kc_2701_full.txt):
ssh kd-app "grep -c 'bl.*0xfffffff00ac482b8\$' /tmp/kc_2701_full.txt"   # -> 54
ssh kd-app "grep -c 'bl.*0xfffffff00b4112cc\$' /tmp/kc_2701_full.txt"   # -> 1
```

The full-fileset dump is reproduced with:
```sh
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel --quiet > /tmp/kc_2701_full.txt"
```

## (b) Disassembly (pulled)

Public `zalloc_ro_mut` — `0xfffffff00ac482b8` (full prologue, dispatches on the zone-id arg `w0`):

```asm
sub_fffffff00ac482b8:
0xfffffff00ac482b8:  pacibsp
0xfffffff00ac482bc:  sub  sp, sp, #0x80
0xfffffff00ac482c0:  stp  x26, x25, [sp, #0x30]
            ... full callee-saved save, frame setup ...
0xfffffff00ac482d8:  cmp  w0, #0xe                     ; zone-id argument dispatch
0xfffffff00ac482dc:  b.ne 0xfffffff00ac48320
0xfffffff00ac482e0:  str  wzr, [sp, #0x24]
0xfffffff00ac482e4:  mov  x19, x1
0xfffffff00ac482e8:  add  x1, sp, #0x24
0xfffffff00ac482ec:  mov  x20, x0
0xfffffff00ac482f4:  mov  x21, x4
0xfffffff00ac482f8:  mov  x23, x3
0xfffffff00ac482fc:  mov  x22, x2
0xfffffff00ac48300:  bl   0xfffffff00b11a998
            ... (signature: zalloc_ro_mut(zid w0, void* dst x1, size_t off x2, void* src x3, size_t len x4)) ...
```

Internal cold worker — `0xfffffff00b4112cc` (distinct function; loads the *current thread* from
`tpidr_el1` and does its own zone-range check — it is not the general-purpose API):

```asm
sub_fffffff00b4112cc:
0xfffffff00b4112cc:  pacibsp
0xfffffff00b4112d0:  sub  sp, sp, #0xa0
0xfffffff00b4112e8:  mov  x19, x2
0xfffffff00b4112ec:  mrs  x8, tpidr_el1                ; current thread (not an API arg)
0xfffffff00b4112f0:  ldr  x20, [x8, #0xf0]
0xfffffff00b4112fc:  adrp x22, 0xfffffff007de5000
0xfffffff00b411300:  add  x22, x22, #0xe30             ; RO-zone range anchor 0xfffffff007de5e30
0xfffffff00b411304:  adds x10, x2, x3
0xfffffff00b411308:  b.hs 0xfffffff00b411320
0xfffffff00b41130c:  ldp  x11, x12, [x22]              ; RO-zone {base,bound}
0xfffffff00b411310:  cmp  x19, x11
0xfffffff00b411314:  ccmp x10, x11, #0, cs
0xfffffff00b411318:  ccmp x10, x12, #0x2, cs
0xfffffff00b41131c:  b.ls 0xfffffff00b411370
            ...
```

## (c) Annotation

- `0xfffffff00ac482b8` has a full prologue, a zone-id dispatch (`cmp w0, #0xe`), and marshals five
  arguments `(zid, dst, off, src, len)` — the shape of a general mutation API. It is called from
  **54** sites, including the csflags setters (see [`csflags-setters.md`](csflags-setters.md), both
  `bl 0xfffffff00ac482b8`).
- `0xfffffff00b4112cc` is reached from exactly **1** call site and derives its subject from
  `tpidr_el1` (the current thread) rather than from a caller argument — i.e. a specialized cold path,
  not the public entry. Documents that call `0xb4112cc` "the public `zalloc_ro_mut`" are wrong and
  have been corrected.
- Both ultimately reach the pmap RO-write worker that performs the SPRR flip
  (`pmap_ro_zone_memcpy` `0xfffffff00ad31c08`, see [`pmap-ro-zone-memcpy.md`](pmap-ro-zone-memcpy.md)).
