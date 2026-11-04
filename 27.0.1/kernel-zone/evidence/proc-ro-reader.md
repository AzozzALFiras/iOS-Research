# Evidence — the `proc_ro` reader inline-validates `p_proc_ro` (27.0.1)

**Claim.** The `proc → proc_ro` reader at `0xfffffff00b0db174` reads the cached `p_proc_ro` pointer
from `proc + 0x18` and inline-validates it the same way the thread reader does: RO-range check
against `0xfffffff007de5e30`, metadata zone-id `cmp w8,#0x5` (`proc_ro`), and backref `[proc_ro] ==
proc`.

## (a) Reproduction

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel -a 0xfffffff00b0db174 -c 40 --quiet"
```

## (b) Disassembly (pulled)

```asm
0xfffffff00b0db174:  ldr  x1, [x0, #0x18]             ; p_proc_ro (cached) from proc+0x18
0xfffffff00b0db178:  adrp x8, 0xfffffff007de5000
0xfffffff00b0db17c:  add  x8, x8, #0xe30              ; RO-zone range anchor 0xfffffff007de5e30
0xfffffff00b0db180:  ldp  x9, x8, [x8]
0xfffffff00b0db184:  cmp  x9, x1
0xfffffff00b0db188:  ccmp x8, x1, #0, ls
0xfffffff00b0db18c:  b.ls 0xfffffff00b0db1f0          ; not in RO range -> panic
0xfffffff00b0db1b0:  adrp x8, 0xfffffff007de5000
0xfffffff00b0db1b4:  ldr  x8, [x8, #0xe90]            ; metadata base 0xfffffff007de5e90
0xfffffff00b0db1b8:  lsr  x9, x1, #0xa
0xfffffff00b0db1bc:  and  x9, x9, #0xffffffff0
0xfffffff00b0db1c4:  ldrh w8, [x8]
0xfffffff00b0db1c8:  and  w8, w8, #0x3ff              ; metadata zone-id
0xfffffff00b0db1cc:  cmp  w8, #0x5                     ; must be proc_ro (zone 5)
0xfffffff00b0db1d0:  b.ne 0xfffffff00b0db1f0          ;   else panic
0xfffffff00b0db1d4:  ldr  x8, [x1]                    ; pr_proc backref
0xfffffff00b0db1d8:  cmp  x8, x0
0xfffffff00b0db1dc:  b.ne 0xfffffff00b0db1ec          ;   backref != proc -> fail
0xfffffff00b0db1e0:  ldr  x0, [x1, #0x10]             ; return proc_ro field (+0x10)
0xfffffff00b0db1e8:  retab
0xfffffff00b0db1f0:  mov  w0, #0x5
0xfffffff00b0db1f4:  bl   0xfffffff00b411164           ; zone_require_ro(5, ...) -> panic
```

## (c) Annotation

- Identical structure to the thread reader ([`cred-reader-ttro.md`](cred-reader-ttro.md)) but keyed
  to zone `5` (`proc_ro`) and the `proc_ro → proc` backref at offset `0`. `p_proc_ro` is cached in the
  regular-zone `proc` (at `+0x18`), yet trust is re-derived on read: RO-range, zone-id `== 5`,
  backref.
- Together the two readers close the loop: the RO substrate is immutable to data-only writes (SPRR),
  *and* the cached pointers into it are re-validated so that corrupting the cache in a regular zone
  does not redirect a reader to attacker-controlled "credentials".
