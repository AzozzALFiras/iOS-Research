# Evidence — §F2 is defense-in-depth, not a 27.0.1 bug (IOMMU refcount engine)

**Claim.** The IOMMU page-refcount engine `iommu_update_page_refcount` is
`FUN_0xfffffff0270e44fc` in 27.0.1 and `FUN_0xfffffff0270e5414` in 27.2. In **27.0.1 it touches only
the two word counters at FTE `+8` (`read_refcnt`) and `+0xc` (`wx_refcnt`)** via word `ldadd`. In
**27.2 it additionally does a byte `ldaddb` on FTE `+5`** — a brand-new "IOMMU read" subset counter
(`iommu_read_refcnt`). The `iommu_read_refcnt` symbol/panic **does not exist in 27.0.1**
(string count 0) and **appears in 27.2** (count 2). Therefore the §F2 invariant panic
(`read_refcnt < iommu_read_refcnt → PANIC`) guards a counter that **27.2 itself introduced**; it is
not fixing a 27.0.1 defect. **§F2 is a 27.2 feature / defense-in-depth, not a patched 27.0.1 bug.**

Binaries: `sptm_2701.bin` (`SPTM-820.0.22`), `sptm_272.bin` (`SPTM-820.40.24`).

## 1. The 27.0.1 engine — only +8 and +0xc

```
ipsw macho disass /root/ios-research/analysis/sptm/bins/2701/sptm_2701.bin \
  -a 0xfffffff0270e44fc -c 200 --quiet | grep -iE 'ldadd|ldaddb|mov\s+w1[01], #|ret'
```

### Output (real)

```asm
0xfffffff0270e462c:  8a 01 80 52   mov	w10, #0xc              ; offset 0xc (wx_refcnt)
0xfffffff0270e4630:  0b 01 80 52   mov	w11, #0x8              ; offset 0x8 (read_refcnt)
0xfffffff0270e4650:  2a 00 80 52   mov	w10, #0x1
0xfffffff0270e4654:  6a 01 2a b8   ldadd	w10, w10, [x11]        ; WORD atomic add on FTE+8/+0xc
0xfffffff0270e46f0:  ff 0f 5f d6   retab
```

There is **no `ldaddb`** (byte atomic) anywhere in the 27.0.1 engine — only the word `ldadd`
addressing the `+8` / `+0xc` counters.

## 2. The 27.2 engine — adds a byte `ldaddb` on FTE+5

```
ipsw macho disass /root/ios-research/analysis/sptm/bins/272/sptm_272.bin \
  -a 0xfffffff0270e5538 -c 20 --quiet
```

### Output (real)

```asm
0xfffffff0270e5548:  0a 20 00 91   add	x10, x0, #0x8          ; &FTE[+8]  read_refcnt
0xfffffff0270e5550:  0b 14 00 91   add	x11, x0, #0x5          ; &FTE[+5]  iommu_read_refcnt  (NEW)
0xfffffff0270e5554:  2c 00 80 52   mov	w12, #0x1
0xfffffff0270e5558:  6b 01 2c 38   ldaddb	w12, w11, [x11]        ; BYTE atomic add on FTE+5  (NEW in 27.2)
0xfffffff0270e5560:  0a 30 00 91   add	x10, x0, #0xc          ; &FTE[+0xc] wx_refcnt
0xfffffff0270e5568:  2b 00 80 52   mov	w11, #0x1
0xfffffff0270e556c:  4a 01 2b b8   ldadd	w11, w10, [x10]        ; WORD atomic add on FTE+8/+0xc
```

The `add x11,x0,#0x5` + `ldaddb` pair — a byte-width atomic on **FTE+5** — is present only in 27.2.

## 3. String-table diff: `iommu_read_refcnt` is new in 27.2

```
for b in bins/2701/sptm_2701.bin bins/272/sptm_272.bin bins/273/sptm_273.bin; do
  echo -n "$b : "; strings /root/ios-research/analysis/sptm/$b | grep -c 'iommu_read_refcnt'
done
```

### Output (real)

```
2701 : 0
272  : 2
273  : 2
```

## Annotation (bytes → claim)

- FTE `+8` = `read_refcnt` (u32) and `+0xc` = `wx_refcnt` (u32) are the pre-existing word counters,
  incremented with word `ldadd` in **both** versions.
- FTE `+5` = `iommu_read_refcnt` (u8) is a **new 27.2 subset counter**: the `ldaddb` that maintains
  it exists only in `FUN_0xfffffff0270e5414`, and the `iommu_read_refcnt` string (used by the §F2
  consistency panic) has **zero** occurrences in 27.0.1.
- Consequence: the §F2 panic `read_refcnt < iommu_read_refcnt → PANIC` cannot describe a 27.0.1 bug,
  because 27.0.1 has no `iommu_read_refcnt` field at all. 27.2 added both the counter and its
  invariant check together — **defense-in-depth around a new accounting field**, correctly
  classified as "not a 27.0.1 vulnerability."
