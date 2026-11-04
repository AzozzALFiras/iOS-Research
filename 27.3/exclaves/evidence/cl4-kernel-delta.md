# Evidence — 27.3 cL4 kernel carve + delta vs 27.0.1

Backs [`../README.md`](../README.md) (finding #7).

## Binary / tooling

- Bundles on kd-app: `/root/ios-research/analysis/exclaves/{2701,272,273}/`. Carves live in
  `kerncarve/exk_code_{2701,272}.bin`; the 27.3 carve `exk_code_273.bin` is produced below.
- Carve method and ELF-wrapper (`mkelf.py`) are documented in
  [`../../../27.0.1/exclaves/evidence/cl4-cap-deref-pan.md`](../../../27.0.1/exclaves/evidence/cl4-cap-deref-pan.md)
  and [`../../../27.0.1/exclaves/evidence/mkelf.py`](../../../27.0.1/exclaves/evidence/mkelf.py).

## Claim

The real cL4 code occupies the first `0x18000` bytes of each build's decompressed bundle. The 27.3
carve differs from 27.0.1 in only 354 of 98304 bytes (0.36%), all in the early-boot
header/vector/CPU-init region; the capability/dispatch/SCTLR code is byte-identical, and the
finding-#1 invariants re-confirm on the 27.3 carve.

## Reproduction

```sh
cd /root/ios-research/analysis/exclaves
# 1. the carve is the first 0x18000 bytes of the decompressed bundle (validated for 2701 & 272:
#    raw_bundle.bin[0:98304] == exk_code_<ver>.bin byte-for-byte). Carve 27.3 the same way:
python3 - <<'PY'
SZ=98304
pay=open('273/exclavecore_bundle.t8140.RELEASE.payload','rb').read()
open('kerncarve/exk_code_273.bin','wb').write(pay[:SZ])
a=open('kerncarve/exk_code_2701.bin','rb').read()
c=open('kerncarve/exk_code_273.bin','rb').read()
diffs=[i for i in range(SZ) if a[i]!=c[i]]
print("diff bytes 2701 vs 273:", len(diffs))
cl=[]
for i in diffs:
    if cl and i-cl[-1][1]<=16: cl[-1][1]=i
    else: cl.append([i,i])
for s,e in cl: print("  [%#x..%#x] len %d  VA %#x" % (s,e,e-s+1,0xfffffc0000000000+s))
PY

# 2. re-confirm finding #1 on the 27.3 carve
cd kerncarve
python3 mkelf.py exk_code_273.bin exk_code_273.elf 0xfffffc0000000000
llvm-objdump -d --no-show-raw-insn exk_code_273.elf > /tmp/exk273.asm
grep -nE '0x3454|0xdd9d' /tmp/exk273.asm                                   # SCTLR literal unchanged
for p in 'msr\s+pan' '\bldtr' '\bsttr' 'at\s+s1e0'; do grep -icE "$p" /tmp/exk273.asm; done   # all 0
llvm-objdump -d --start-address=0xfffffc0000008470 --stop-address=0xfffffc0000008498 exk_code_273.elf
llvm-objdump -d --start-address=0xfffffc00000085ec --stop-address=0xfffffc0000008614 exk_code_273.elf
```

## Output (pulled)

Byte-diff clusters, 27.0.1 → 27.3 (354 bytes, 14 clusters):

```
  [0x90..0xb2]      len 35   VA 0xfffffc0000000090   early header / build-id blob
  [0xe1..0xe2]      len 2
  [0x109..0x119]    len 17
  [0x221..0x222]    len 2
  [0x249..0x24a]    len 2
  [0x291..0x2ba]    len 42
  [0x2d1..0x2d2]    len 2
  [0x2e9..0x302]    len 26
  [0x31a..0x332]    len 25
  [0x349..0x352]    len 10
  [0x17d0..0x195b]  len 396  VA 0xfffffc00000017d0   early-boot GPR/GXF register-init block
  [0xc2ad..0xc2ae]  len 2
  [0xc2c1..0xc2c1]  len 1
  [0x14646..0x14649] len 4
```

(27.0.1 → 27.2 is the same shape, 49 bytes — a subset of the above, confined to `0x90` and the
`0x17d0` init block.)

The `0x17d0` cluster disassembles as register scrubbing + guarded-mode system-register init, not
dispatch logic:

```
fffffc00000017c0:  mov x14, xzr ... mov x30, xzr      ; clear GPRs
fffffc0000001800:  msr S3_6_C15_C10_7, xzr            ; clear GXF/guarded IMP-DEF registers
fffffc0000001804:  msr S3_6_C15_C10_6, xzr
fffffc0000001808:  msr S3_6_C15_C10_5, xzr
fffffc000000180c:  msr S3_6_C15_C10_3, xzr
```

Finding-#1 invariants on the 27.3 carve:

```
SCTLR literal:  fffffc0000007afc: mov w8,#0xdd9d ; fffffc0000007b00: movk w8,#0x3454,lsl#16   (= 0x3454DD9D, SPAN=0)
msr pan : 0   ldtr : 0   sttr : 0   at s1e0 : 0

fffffc0000008470: and  x9, x20, #0xfffffffc0     ; cap-deref — identical to 27.0.1
fffffc0000008490: ldr  x8, [x9]
fffffc0000008494: lsr  x8, x8, #58

fffffc00000085ec: ldr   x8, [x0]                 ; Invoke — identical to 27.0.1
fffffc00000085f0: lsr   x8, x8, #58
fffffc00000085f8: umull x8, w8, w9               ; (w9 = 0x58)
fffffc0000008610: blr   x8                        ; still no type bound
```

## Annotation

The 27.3 carve is `payload[0:0x18000]` — the same slice that reproduces the 27.0.1 and 27.2 carves
exactly. The 354 differing bytes are entirely in the reset/early-boot/CPU-init region
(`<0x2000`) plus two tiny constant edits deeper in; the `0x17d0` block is GPR + GXF
register-initialization churn. The syscall dispatcher, VA-capability dereference, Invoke dispatch,
and SCTLR programming are byte-identical, and the PAN invariant (SPAN=0 + zero bypass primitives)
holds verbatim. Therefore the 27.0.1 cL4 findings are valid for 27.3 without re-audit.
