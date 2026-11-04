# Kernel-zone trust architecture across 27.0.1 → 27.2 → 27.3

Did Apple change anything that moves the kernel credential walls from *data-only* to *code-exec*
between 27.0.1 (24A446), 27.2 (24B119) and 27.3 (24C5037i)? The three candidate changes flagged as
open in earlier drafts were: (a) make the **zone-metadata submap** read-only, (b) **trap `msr
sprr_pperm_el1`** to a guarded (GL/GXF) transition, (c) change the **`proc_task`** layout / zone-id.

**Answer: none of the three changed.** The architecture is structurally identical across all three
builds; only addresses shifted (the `__TEXT` and `__DATA_CONST` segments move by different,
non-uniform deltas, so each structure was re-resolved independently by instruction/anchor fingerprint
rather than by a single slide). Each kernelcache is `kernelcache.release.iPhone17,2`.

## Re-resolution method

Addresses are not a fixed offset apart between builds (`get_bsdtask_info` moves `+0x49530`
27.0.1→27.2 but `+0x12ebd0` 27.0.1→27.3; `__DATA_CONST` moves differently again). Each structure was
therefore anchored on a build-invariant fingerprint:

| structure | fingerprint used to re-resolve |
|---|---|
| `proc_task` accessor | `subs x1, x0, #0x768` immediately followed by `adds x8, x1, #0xe38` |
| zone-range anchor | the `adrp/add; ldp` pair loaded by that accessor |
| SPRR flip / `pmap_ro_zone_memcpy` | `mov x9,#0xb; bfi x8,x9,#0x8,#0x4; msr sprr_pperm_el1,x8` |
| public `zalloc_ro_mut` | `bl` target of the csflags commit `mov w2,#0x24; mov w4,#0x4; bl …` |
| hot cred reader | `mrs x0,tpidr_el1; ldr x1,[x0,#0x418]; … cmp w8,#0x3; ldr x8,[x1]; cmp x8,x0` |

All counts below are exact greps against full-fileset disassemblies
(`ipsw macho disass <kc> -t com.apple.kernel --quiet`).

## Side-by-side

| property | 27.0.1 (24A446) | 27.2 (24B119) | 27.3 (24C5037i) | changed? |
|---|---|---|---|---|
| `proc_task`: `task = proc + 0x768` | yes | yes | yes | **no** |
| `proc_task` element size `0xe38` | yes | yes | yes | **no** |
| `get_bsdtask_info` (addr) | `0xfffffff00ac4b408` | `0xfffffff00ac94938` | `0xfffffff00ad79fdc` | addr only |
| regular zone-range anchor (`__DATA_CONST`) | `0xfffffff007de5de0` | `0xfffffff007df2040` | `0xfffffff007e1a1b0` | addr only |
| runtime metadata writer `strh w8,[x10,#0x2]` | 2 sites | 2 sites | 2 sites | **no** → metadata still writable |
| `sprr_pperm_el1` refs (msr+mrs) | 30 | 30 | 30 | **no** |
| 3-insn SPRR flip (`#0xb`/`#0xa`, `bfi #8,#4`) | present | present | present | **no** |
| `sprr_pperm_el1` GXF-gated? | no | no | no | **no** → still data-only |
| public `zalloc_ro_mut` (addr) | `0xfffffff00ac482b8` | `0xfffffff00ac917e8` | `0xfffffff00ad76e88` | addr only |
| `zalloc_ro_mut` callers | 54 | 54 | 54 | **no** |
| internal cold worker `0xb4112cc`-equiv | 1 caller | — | — | n/a |
| csflags setter (zone-id `#5` + backref + staged src) | present | present | present | **no** |
| hot cred reader (addr) | `0xfffffff00ac4b5a0` | `0xfffffff00ac94ad0` | `0xfffffff00ad7a170` | addr only |
| cred reader callers | 1058 | 1060 | 1069 | grew (same mechanism, wider use) |
| cred reader validation (`cmp w8,#0x3` + backref) | present | present | present | **no** |
| `t_tro` offset in `thread` | `+0x418` | `+0x418` | `+0x418` | **no** |

## Reading of the three candidate changes

1. **Zone-metadata submap made read-only? No.** The runtime metadata writer (`strh w8,[x10,#0x2]`,
   the `zalloc`/`zfree` fast-path update to the same VA `zone_id_require` reads) is present and
   identical (2 sites) in all three builds. The zone-id halfword remains forgeable under full kernel
   R/W in every version. The anchor (base ptr + range) stays in `__DATA_CONST`; the metadata *array*
   stays a writable submap. `zone_id_require` is still a pre-R/W bar, not a post-R/W boundary.

2. **`msr sprr_pperm_el1` trapped to GL? No.** 30 `sprr_pperm_el1` references in all three, none
   GXF-gated, with the same bare `mrs/bfi/msr/isb` flip inside `pmap_ro_zone_memcpy`. The RO wall
   remains a **data-only** boundary: immutable to data-only R/W (a register is not memory), defeated
   by EL1 **code execution** in three instructions. Apple did not move this wall to code-exec in
   27.2 or 27.3.

3. **`proc_task` layout changed? No.** `task = proc + 0x768`, element `0xe38`, same accessor shape in
   all three. The co-allocated `[proc|task]` layout is build-stable across the point releases.

Additionally, the **content** and **reader** gates persist unchanged: the csflags setters still
re-validate the RO dst (zone-id `5` + `pr_proc` backref) and stage the value on the stack before
committing through `zalloc_ro_mut` (still 54 callers); the hot cred reader still inline-validates the
cached `t_tro` (`thread+0x418`) with an RO-range + zone-id `3` + backref check (caller count actually
grew 1058 → 1060 → 1069, i.e. the gate is applied *more* widely, not less).

## Conclusion

Across 27.0.1, 27.2 and 27.3 the kernel-zone trust chain is the same wall in the same place:

```
corruption → zone_id_require (bar, forgeable under R/W)
           → data-only kernel R/W
           → RO-zone SPRR wall  HOLDS vs data-only  (write + content + reader gates all intact)
           → crossing it needs EL1 CODE EXECUTION
           → denied by PAC + CTRR + SPTM
```

The only residual data-only lead — reader-side re-validation of `fileglob.fg_cred` /
`socket.so_cred` — was not closed in any of the three builds (it is a structural question about those
cached `ucred` pointers, not a per-version change); see [`reader-gating.md`](reader-gating.md). The
persistence of this architecture across two point releases is documented per-version in
[`../../27.2/kernel-zone/README.md`](../../../27.2/kernel-zone/README.md) and
[`../../27.3/kernel-zone/README.md`](../../../27.3/kernel-zone/README.md).

## Reproduction (counts)

```sh
# per build b in {24A446(27.0.1), 24B119(27.2), 24C5037i(27.3)}:
KC=/root/ios-research/extracted/<ver>/<b>__iPhone17,2/kernelcache.release.iPhone17,2
ssh kd-app "ipsw macho disass $KC -t com.apple.kernel --quiet > /tmp/kc_${b}_full.txt"
grep -c 'sprr_pperm_el1'                /tmp/kc_${b}_full.txt    # 30 / 30 / 30
grep -c 'strh	w8, \[x10, #0x2\]$'      /tmp/kc_${b}_full.txt    #  2 /  2 /  2
grep -c 'ldr	x1, \[x0, #0x418\]$'      /tmp/kc_${b}_full.txt    # t_tro offset persists
# zalloc_ro_mut address re-resolved per build via the csflags commit, then:
grep -c 'bl.*0xfffffff00ac482b8$'       /tmp/kc_24A446_full.txt  # 54  (0xac917e8 -> 54 ; 0xad76e88 -> 54)
```
