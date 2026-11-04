# The post-R/W trust boundary — what iOS 27.0.1 still denies you after kernel read/write

The sharpest exploitation-reasoning result in the repo. Assume a memory-corruption bug has given a
**data-only kernel read/write** primitive. What do 27.0.1's mitigations still deny, and where is the
real wall? Static analysis of `kernelcache.release.iPhone17,2` (build 24A446). Cross-checked against
the public **Chollima / Calif.io** 27.0.1 jailbreak demo (a capability demo with kernel R/W — not
the entry bug).

This mixes a **"road-blocked"** proof (the RO-zone wall holds vs data-only) with a precise statement
of **where the block ends** (it is a data-only boundary, not a code-exec one).

## Layer 1 — `zone_id_require`: forgeable under full R/W

`zone_require` (`0xfffffff00b41101c`) / inlined `zone_id_require` guard ≥12 zone types at **165
sites**. Algorithm: range-check the pointer in `[base, bound]`, then read the per-16KiB-page
metadata entry `meta_base + (addr >> 14) * 16` and compare its low-10-bit zone id to the expected.

| backing data | protection | writable under kernel R/W? |
|---|---|---|
| **anchor**: metadata base ptr + zone range (`0xfffffff007de5de0`, `…5e90`) | `__DATA_CONST` = `xnu_ro_data` = SPTM region `BootKC-rs`, inside **CTRR-D**, locked by **SPTM** at boot | **No** (hardware) |
| **metadata array** (what the base points to) | ordinary RW kernel submap (`ksubmap[metadata]`); runtime `zalloc/zfree` write it with a plain `strh` to the *same* VA the check reads | **Yes** |

So `zone_id_require` **defeats constrained primitives** (type-confusion *before* full R/W) but is
**bypassable once you have kernel R/W** — forge a page's zone-id halfword (e.g. stamp `0x1a` to fake
a `proc_task`). It raises the bar; it is not a post-R/W boundary. A zone-id forge buys
**type-confusion on regular objects, not a credential overwrite**, because credentials live
elsewhere → Layer 2.

## Layer 2 — RO zones: the real wall, holds vs data-only (road blocked)

Credentials and process security state live in **read-only (`ZC_READONLY`) zones**: `proc_ro`,
`ucred`/`kauth_cred` (uid/gid/groups + MAC label + audit), `cs_blob` (code signing). These are
immutable under **data-only** R/W. The sink we must deny is "write to a `proc_ro`/`ucred` page"; the
guard is **SPRR**.

Mutation funnels through `zalloc_ro_mut` (`0xfffffff00b4112cc`) → the pmap RO-write worker
`sub_fffffff00ad31c08`, which brackets the write with IRQs off and an SPRR permission flip:

```asm
; --- make the RO-zone domain writable, just for this memcpy ---
0x...31c98  mrs  x8, sprr_pperm_el1
0x...31c9c  mov  x9, #0xb
0x...31ca0  bfi  x8, x9, #0x8, #0x4        ; perm index field [8:11] = 0xb  (READ-WRITE)
0x...31ca4  msr  sprr_pperm_el1, x8
0x...31ca8  isb
            ... (bl copy helpers) ...
; --- restore read-only ---
0x...31cd4  mrs  x8, sprr_pperm_el1
0x...31cd8  mov  x9, #0xa
0x...31cdc  bfi  x8, x9, #0x8, #0x4        ; perm index field [8:11] = 0xa  (READ-ONLY)
0x...31ce0  msr  sprr_pperm_el1, x8
0x...31ce4  isb
```

RO-zone pages carry an SPRR protection index whose entry is `0xa` (read-only) in the normal domain;
only inside this window is it `0xb` (read-write). **A data-only arbitrary write to a `proc_ro`/
`ucred` page therefore faults** — it is not in the writable window. Additionally, `proc_task` (id
`0x1a`) has an RO companion `proc_ro` with **panic-enforced** bidirectional backrefs
("proc_ro->task backref mismatch"), so forging a `proc_task` alone is insufficient.

→ **Road blocked for data-only R/W:** credentials stay immutable.

## Layer 3 — where the block ends: the RO wall is a *data-only* boundary, not a *code-exec* one

The block above assumed the attacker cannot *execute instructions* at EL1 — because `sprr_pperm_el1`
is a **register**, not memory, so a data-only write can't touch it. But is it locked against code
execution? **No.** `sprr_pperm_el1` is a plain EL1 system register; XNU's own worker (above) flips it
with a bare `msr`, in normal EL1 code, with **no GXF/SPTM transition**. Whole-kernel count:

```
msr/mrs sprr_pperm_el1 in com.apple.kernel EL1 text : 30 sites, none GXF-gated
```

(The `sprr_config_el12` / `gxf_config_el12` registers are boot/CPU-init only.) So an attacker with
**EL1 code execution** defeats the RO wall in three instructions:

```asm
mrs  x8, sprr_pperm_el1 ; mov x9, #0xb ; bfi x8, x9, #8, #4 ; msr sprr_pperm_el1, x8 ; isb
```

— now every RO-zone page is writable in the normal domain → overwrite credentials/csflags. A subtler
path *without* crafting the `msr`: a PAC-defeating call-primitive that invokes `zalloc_ro_mut` with
`dst` = a legitimate RO element you own + a forged `src` (it does the SPRR flip internally, but
validates "same zone / from RO zone map" at entry, `bl 0xfffffff00b41dce0`).

## The full chain (27.0.1)

```
corruption bug
  → constrained primitive        zone_id_require raises the bar (Layer 1)
  → data-only kernel R/W
  → RO-zone SPRR wall             HOLDS vs data-only: credentials immutable (Layer 2)
  → to cross it you need EL1 CODE EXECUTION                              (Layer 3)
  → blocked by:  PAC            (resist control-flow hijack to a crafted msr / call-primitive)
              +  CTRR-A/B       (kernel __TEXT read-only, iBoot-locked — can't patch code)
              +  SPTM PAPT/W^X  (can't map RWX, can't edit PTEs — the exclave/SPTM layer)
```

**Conclusion:** on 27.0.1 the real wall protecting credentials is **"prevent EL1 code execution"**,
enforced by the PAC + CTRR + SPTM triad — *not* SPRR by itself. This is precisely why the SPTM /
exclave work elsewhere in this repo matters: it is the floor the whole chain stands on. See
[`../../exclaves/`](../../exclaves/) and [`../../sptm/`](../../sptm/).

## Open

- Does a *practical* PAC-defeating call-primitive to `zalloc_ro_mut` exist? (the subtler Layer-3
  path) — unresolved, in [`../../../STATUS.md`](../../../STATUS.md).
- Did 27.2 trap `msr sprr_pperm_el1` to GL or make the metadata submap read-only? That would move
  these walls from data-only to code-exec. Not yet diffed.

## Evidence

`zone_require` `0xfffffff00b41101c`; `zone_require_ro` `0xfffffff00b411164`; `zalloc_ro_mut`
`0xfffffff00b4112cc`; RO-write worker `0xfffffff00ad31c08` (flips @ `…31c98`/`…31cd4`); anchors
`0xfffffff007de5de0` (range) / `…5e90` (meta base). `proc_task`: `task = proc + 0x768`, elem `0xe38`,
zone-id `0x1a` (see [`proc-task-layout.md`](proc-task-layout.md)). Disasm excerpts in
[`../evidence/`](../evidence/).
