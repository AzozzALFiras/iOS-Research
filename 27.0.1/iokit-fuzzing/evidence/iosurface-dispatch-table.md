# Evidence — IOSurfaceRootUserClient dispatch table, decoded from raw bytes (27.0.1)

**Claim.** `IOSurfaceRootUserClient` uses an `IOExternalMethodDispatch2022` table at
`0xfffffff00831db30`, stride `0x28`, 60 selectors. Each entry is
`{ q0 = handler, [+8] = checkScalarInputCount, [+0xc] = checkStructureInputSize,
[+0x10] = checkScalarOutputCount, [+0x14] = checkStructureOutputSize }`. The handler pointer must be
decoded from the **raw** table bytes with `vaddr = 0xfffffff007004000 + (raw & 0xffffffff)`
(the kernelcache chained-fixup rebase base) — `ipsw macho dump --addr` applies a symbolication that
can mis-resolve these, so the raw-byte decode is authoritative.

Binary: kernelcache FILESET `kernelcache.release.iPhone17,2` (24A446, iPhone17,2),
fileset entry `com.apple.iokit.IOSurface`. All addresses are unslid kernel VAs.

## Reproduce

```sh
KC=/root/ios-research/extracted/27.0.1/24A446__iPhone17,2/kernelcache.release.iPhone17,2
# Pull the raw table bytes (60 entries * 0x28 = 0x960):
ipsw macho dump "$KC" 0xfffffff00831db30 --bytes --size 0x960 > /tmp/iosurf_tbl_full.bin
# Decode each entry from the raw bytes:
python3 -I - <<'PY'
import struct
d = open("/tmp/iosurf_tbl_full.bin","rb").read()
base = 0xfffffff007004000
print("sel  handlerVA            scalarIn  structIn        scalarOut structOut")
for i in range(len(d)//0x28):
    e = d[i*0x28:(i+1)*0x28]
    raw = struct.unpack_from("<Q", e, 0)[0]
    h = base + (raw & 0xffffffff)
    sIn, stIn, sOut, stOut = struct.unpack_from("<IIII", e, 8)
    f = lambda v: "VAR(0xffffffff)" if v == 0xffffffff else hex(v)
    print(f"{i:<4} 0x{h:012x}   {f(sIn):<9} {f(stIn):<15} {f(sOut):<9} {f(stOut)}")
PY
```

## Output (real) — first three entries, raw hexdump

```
00000000: d47a 3403 adbc 5080 0100 0000 ffff ffff  .z4...P.........   ; sel 0
00000010: 0000 0000 680c 0000 0000 0000 0000 0000  ....h...........
00000020: 0000 0000 0000 0000 a47c 3403 adbc 5080  .........|4...P.   ; sel 1
00000030: 0100 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000
00000050: b47c 3403 adbc 5080 0000 0000 0c00 0000  .|4...P.........   ; sel 2
00000060: 0000 0000 680c 0000 0000 0000 0000 0000  ....h...........
```

Decoder output (all 60 selectors):

```
sel  handlerVA            scalarIn  structIn        scalarOut structOut
0    0xfffffff00a34bad4   0x1       VAR(0xffffffff) 0x0       0xc68
1    0xfffffff00a34bca4   0x1       0x0             0x0       0x0
2    0xfffffff00a34bcb4   0x0       0xc             0x0       0xc68
3    0xfffffff00a34bcd0   0x0       0xc             0x0       0x4
4    0xfffffff00a34bcec   0x1       0x0             0x0       0xc68
5    0xfffffff00a34bd00   0x2       0x0             0x0       0x0
6    0xfffffff00a34bd14   0x0       0x20            0x0       0xc68
7    0xfffffff00a34bd24   0x2       0x0             0x0       0xc68
8    0xfffffff00a34bd3c   0x1       0x0             0x1       0x0
9    0xfffffff00a34bd74   0x0       VAR(0xffffffff) 0x0       0x4
10   0xfffffff00a34be8c   0x0       VAR(0xffffffff) 0x0       VAR(0xffffffff)
11   0xfffffff00a34c09c   0x0       VAR(0xffffffff) 0x0       0x4
12   0xfffffff00a34c1b4   0x3       0x0             0x0       0x0
13   0xfffffff00a34c1cc   0x0       0x0             0x0       0x28
14   0xfffffff00a34c214   0x2       0x0             0x0       0x0
15   0xfffffff00a34c228   0x2       0x0             0x0       0x0
16   0xfffffff00a34c23c   0x1       0x0             0x1       0x0
17   0xfffffff00a34c2b4   0x0       0x18            0x0       0x0
18   0xfffffff00a34c2dc   0x0       0x18            0x0       0x0
19   0xfffffff00a34c2f4   0x0       VAR(0xffffffff) 0x0       0x0
20   0xfffffff00a34c370   0x2       0x0             0x1       0x0
21   0xfffffff00a34c3ec   0x4       0x0             0x0       0x0
22   0xfffffff00a34c474   0x2       0x0             0x0       0x0
23   0xfffffff00a34c490   0x1       0x0             0x1       0x0
24   0xfffffff00a34c508   0x0       VAR(0xffffffff) 0x0       0x0
25   0xfffffff00a34c618   0x1       0x0             0x1       0x0
26   0xfffffff00a34c690   0x0       VAR(0xffffffff) 0x0       VAR(0xffffffff)
27   0xfffffff00a34c89c   0x0       0xa0            0x0       0x0
28   0xfffffff00a34c8a8   0x1       0x0             0x0       0xa0
29   0xfffffff00a34c8c4   0x2       0x0             0x0       0x0
30   0xfffffff00a34c8d4   0x1       0x0             0x0       VAR(0xffffffff)
31   0xfffffff00a34c990   0x3       0x0             0x0       0x0
32   0xfffffff00a34c9a8   0x0       0x0             0x1       0x0
33   0xfffffff00a34ca0c   0x3       0x0             0x0       0x0
34   0xfffffff00a34ca20   0x1       0x0             0x0       0xc68
35   0xfffffff00a34ca34   0x2       0x0             0x1       0x0
36   0xfffffff00a34cab0   0x1       0x0             0x2       0x0
37   0xfffffff00a34cb38   0x2       0x0             0x0       0x0
38   0xfffffff00a34cb4c   0x1       0x0             0x4       0x0
39   0xfffffff00a34cb6c   0x5       0x0             0x0       0x0
40   0xfffffff00a34cb84   0x0       0x0             0x0       0x0
41   0xfffffff00a34cba0   0x1       0x0             0x0       0x0
42   0xfffffff00a34cbb0   0x4       0x0             0x0       0x0
43   0xfffffff00a34cbcc   0x4       0x0             0x0       0x0
44   0xfffffff00a34cbe4   0x4       0x0             0x0       0x0
45   0xfffffff00a34ccac   0x3       0x0             0x0       0x0
46   0xfffffff00a34ccc0   0x0       VAR(0xffffffff) 0x2       0x0
47   0xfffffff00a34ce24   0x1       VAR(0xffffffff) 0x0       0x0
48   0xfffffff00a34cf3c   0x1       VAR(0xffffffff) 0x0       0x0
49   0xfffffff00a34d054   0x1       0x0             0x0       VAR(0xffffffff)
50   0xfffffff00a34d100   0x2       VAR(0xffffffff) 0x0       0x0
51   0xfffffff00a34d134   0x2       0x0             0x2       VAR(0xffffffff)
52   0xfffffff00a34d170   0x1       0x0             0x0       0x0
53   0xfffffff00a34d194   0x1       0x0             0x0       0x0
54   0xfffffff00a34d1a4   0x0       VAR(0xffffffff) 0x0       0x0
55   0xfffffff00a34d2b4   0x1       0x0             0x1       0x0
56   0xfffffff00a34d33c   0x2       0x0             0x0       0x0
57   0xfffffff00a34d350   0x4       0x0             0x0       0x0
58   0xfffffff00a34d370   0x5       0x0             0x3       0x0
59   0xfffffff00a34d414   0x1       0x0             0x0       0x0
```

## Annotation (bytes → claim)

- **Decode worked example, sel 0.** Raw q0 = `d4 7a 34 03 ad bc 50 80` (LE) = `0x8050bcad03347ad4`.
  Low 32 bits = `0x03347ad4`; handler VA = `0xfffffff007004000 + 0x03347ad4 = 0xfffffff00a34bad4`.
  `[+8]` = `01 00 00 00` = scalarIn **1**; `[+0xc]` = `ff ff ff ff` =
  `kIOUCVariableStructureSize` (variable struct input); `[+0x14]` = `68 0c 00 00` =
  structOut `0xc68`.
- **The parse surface is the `VAR(0xffffffff)` structInput rows** — the only selectors that accept
  an attacker-sized struct blob: sel **0, 9, 10, 11, 19, 24, 26, 46, 47, 48, 50, 54**. Every other
  selector has a **fixed** `checkStructureInputSize` (e.g. sel 2/3 = `0xc`, 17/18 = `0x18`,
  6 = `0x20`, 27 = `0xa0`), which the `IOExternalMethodDispatch2022` wrapper enforces *before* the
  handler runs — a mismatched size is rejected pre-parse (this is the arg-shape gate the blind
  fuzzer measured at ~89% bounce rate).
- The handler VAs recovered here are the entry points audited in the sibling evidence files:
  sel 9 → `0xfffffff00a34bd74` (`iosurface-sel9-deserializer.md`), sel 26 → `0xfffffff00a34c690`
  (`iosurface-sel26-lastbyte.md`).
- A second, restricted dispatch table exists at `0xfffffff00831e490`, reached only when
  `[this+0x127] & 1` is set; its true VA / gating entitlement was **not** resolved here and remains
  an honest residual.
