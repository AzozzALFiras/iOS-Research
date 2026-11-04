# Evidence — AppleJPEGDriver dispatch table, fixed struct sizes (27.0.1)

**Claim.** `AppleJPEGDriver` uses an `IOExternalMethodDispatch2022` table at `0xfffffff00807d7d0`,
stride `0x28`, 10 selectors. **Every selector has a fixed (non-variable) `checkStructureInputSize`** —
there is no `VAR(0xffffffff)` struct-input selector — so the `IOUserClient2022` wrapper rejects any
mis-sized input before the parser runs. The parse selectors are 1/3 (`0x58`), 4/5 (`0x1000`),
6/7 (`0xda0`), 8 (`0x4`); 0/2/9 take no struct input.

Binary: kernelcache FILESET `kernelcache.release.iPhone17,2` (24A446), entry
`com.apple.driver.AppleJPEGDriver`. Handlers decoded from raw bytes with
`vaddr = 0xfffffff007004000 + (raw & 0xffffffff)`.

## Reproduce

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
ipsw macho dump "$KC" 0xfffffff00807d7d0 --bytes --size 0x1a0 > /tmp/jpeg_tbl.bin
python3 -I - <<'PY'
import struct
d = open("/tmp/jpeg_tbl.bin","rb").read()
base = 0xfffffff007004000
print("sel  handlerVA            scalarIn  structIn   scalarOut structOut")
for i in range(len(d)//0x28):
    e = d[i*0x28:(i+1)*0x28]
    raw = struct.unpack_from("<Q", e, 0)[0]
    h = base + (raw & 0xffffffff)
    sIn, stIn, sOut, stOut = struct.unpack_from("<IIII", e, 8)
    f = lambda v: "VAR" if v == 0xffffffff else hex(v)
    print(f"{i:<4} 0x{h:012x}   {f(sIn):<9} {f(stIn):<10} {f(sOut):<9} {f(stOut)}")
PY
```

## Output (real)

```
sel  handlerVA            scalarIn  structIn   scalarOut structOut
0    0xfffffff00902f218   0x0       0x0        0x0       0x0
1    0xfffffff00902f224   0x0       0x58       0x0       0x58
2    0xfffffff00902f258   0x0       0x0        0x0       0x0
3    0xfffffff00902f264   0x0       0x58       0x0       0x58
4    0xfffffff00902f298   0x0       0x1000     0x0       0x1000
5    0xfffffff00902f2cc   0x0       0x1000     0x0       0x1000
6    0xfffffff00902f300   0x0       0xda0      0x0       0xda0
7    0xfffffff00902f334   0x0       0xda0      0x0       0xda0
8    0xfffffff00902f368   0x0       0x4        0x0       0x0
9    0xfffffff00902f398   0x0       0x0        0x0       0x0
```

## Annotation (bytes → claim)

- No selector carries `VAR`/`0xffffffff` in the structInput column. Selectors 4/5 require exactly
  `0x1000` (4096) input bytes, 6/7 exactly `0xda0` (3488), 1/3 exactly `0x58` (88), 8 exactly `0x4`.
  The `IOExternalMethodDispatch2022` wrapper enforces this fixed size and returns
  `kIOReturnBadArgument` for any other size — the parser body is only ever entered with a
  fixed-length, fully-present input buffer.
- Selectors 4/5/6/7 are the encoder/decoder entry points (`startEncoder` /
  `startDecoder`-family). They tail-call fixed workers; the dimension/quality range checks inside
  one of those workers are shown in `applejpeg-dimension-bound.md`.
- Because the struct size is fixed and the dimension fields are range-checked downstream, the classic
  "short struct → OOB field read" and "giant dimension → integer-overflow allocation" classes are
  both closed at this surface.
