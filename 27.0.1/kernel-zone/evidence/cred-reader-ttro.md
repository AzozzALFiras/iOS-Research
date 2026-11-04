# Evidence — the hot cred reader inline-validates `t_tro` (27.0.1)

**Claim.** The hottest thread-credential reader at `0xfffffff00ac4b5a0` (**1058** references = 1057
`bl` + 1 tail-call `b`) reads the cached `t_tro` pointer from `thread + 0x418` and inline-validates it
every time before returning it: RO-range check against `0xfffffff007de5e30`, metadata zone-id `cmp
w8,#0x3` (`thread_ro`), and backref `[t_tro] == thread`. A forged/overwritten `t_tro` is rejected
(panics via `zone_require_ro`).

## (a) Reproduction

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00ac4b5a0 -c 40 --quiet"
ssh kd-app "grep -c 'bl.*0xfffffff00ac4b5a0\$' /tmp/kc_2701_full.txt"               # -> 1057
ssh kd-app "grep -cE '\\bb\\s.*0xfffffff00ac4b5a0\$' /tmp/kc_2701_full.txt"          # -> 1  (tail call)
```

## (b) Disassembly (pulled)

```asm
sub_fffffff00ac4b5a0:
0xfffffff00ac4b5a0:  pacibsp
0xfffffff00ac4b5ac:  mrs  x0, tpidr_el1                ; current thread
0xfffffff00ac4b5b0:  ldr  x1, [x0, #0x418]             ; t_tro (cached thread_ro ptr)
0xfffffff00ac4b5b4:  adrp x8, 0xfffffff007de5000
0xfffffff00ac4b5b8:  add  x8, x8, #0xe30               ; RO-zone range anchor 0xfffffff007de5e30
0xfffffff00ac4b5bc:  ldp  x9, x8, [x8]
0xfffffff00ac4b5c0:  cmp  x9, x1
0xfffffff00ac4b5c4:  ccmp x8, x1, #0, ls
0xfffffff00ac4b5c8:  b.ls 0xfffffff00ac4b628           ; t_tro not in RO range -> panic
0xfffffff00ac4b5ec:  adrp x8, 0xfffffff007de5000
0xfffffff00ac4b5f0:  ldr  x8, [x8, #0xe90]             ; metadata base 0xfffffff007de5e90
0xfffffff00ac4b5f4:  lsr  x9, x1, #0xa
0xfffffff00ac4b5f8:  and  x9, x9, #0xffffffff0
0xfffffff00ac4b600:  ldrh w8, [x8]
0xfffffff00ac4b604:  and  w8, w8, #0x3ff               ; metadata zone-id
0xfffffff00ac4b608:  cmp  w8, #0x3                      ; must be thread_ro (zone 3)
0xfffffff00ac4b60c:  b.ne 0xfffffff00ac4b628           ;   else panic
0xfffffff00ac4b610:  ldr  x8, [x1]                     ; t_tro->thread backref
0xfffffff00ac4b614:  cmp  x8, x0
0xfffffff00ac4b618:  b.ne 0xfffffff00ac4b630           ;   backref != current thread -> panic
0xfffffff00ac4b61c:  mov  x0, x1                        ; return validated t_tro
0xfffffff00ac4b624:  retab
0xfffffff00ac4b628:  mov  w0, #0x3
0xfffffff00ac4b62c:  bl   0xfffffff00b411164            ; zone_require_ro(3, ...) -> panic
```

## (c) Annotation

- This is the reader-side counterpart to the RO write wall: even though `t_tro` is *cached* in the
  regular-zone `thread` struct (at `+0x418`), the reader does not trust the cached pointer. It
  re-derives trust on every read by (i) range-checking against the RO-zone anchor
  `0xfffffff007de5e30`, (ii) confirming the page's metadata zone-id is `3` (`thread_ro`), and (iii)
  checking the `thread_ro → thread` backref equals the current thread.
- So an attacker with data-only R/W who overwrites `thread+0x418` to point at a forged "thread_ro"
  gains nothing: a forged page in a regular zone fails the zone-id `== 3` check, and a real
  `thread_ro` belonging to another thread fails the backref. The attack would require a writable
  RO-zone page with a matching backref — which needs the RO wall already broken (code-exec).
- At 1058 call sites this is on essentially every credential/entitlement check path, so the gate is
  not bypassable by finding an unguarded reader. The `proc_ro` analogue is
  [`proc-ro-reader.md`](proc-ro-reader.md).
