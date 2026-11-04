# Kernel-zone trust architecture — iOS 27.3 (24C5037i): persistence check

27.3 (beta, build 24C5037i) carries the kernel-zone trust architecture forward **unchanged** from
27.0.1 and 27.2: `proc_task` layout, forgeable zone-metadata, the SPRR RO-wall and its ungated flip,
and the content/reader gates are all structurally identical. Only addresses shifted. Full analysis:
[`../../27.0.1/kernel-zone/`](../../27.0.1/kernel-zone/); cross-version table:
[`../../27.0.1/kernel-zone/reports/three-version-diff.md`](../../27.0.1/kernel-zone/reports/three-version-diff.md).

Kernelcache: `kernelcache.release.iPhone17,2` (24C5037i). Addresses re-resolved by
instruction/anchor fingerprint — segments shift non-uniformly, and more so than 27.2
(`get_bsdtask_info` is `+0x12ebd0` from 27.0.1 vs `+0x49530` for 27.2), so a single slide does not map
between builds.

## Re-resolved addresses (27.3)

| structure | 27.0.1 | **27.3** | persistence |
|---|---|---|---|
| `get_bsdtask_info` (`proc_task` accessor) | `0xfffffff00ac4b408` | `0xfffffff00ad79fd8` | `task=proc+0x768`, elem `0xe38` — identical |
| regular zone-range anchor (`__DATA_CONST`) | `0xfffffff007de5de0` | `0xfffffff007e1a1b0` | same `{base,bound}` role |
| public `zalloc_ro_mut` | `0xfffffff00ac482b8` | `0xfffffff00ad76e88` | **54 callers** (unchanged) |
| `pmap_ro_zone_memcpy` SPRR flip | `0xfffffff00ad31c98` | `0xfffffff00ae6388c` | identical 3-insn flip, validate-before-flip |
| hot cred reader (`t_tro`) | `0xfffffff00ac4b5a0` | `0xfffffff00ad7a170` | **1069 callers**; `cmp w8,#0x3` + backref |
| `t_tro` offset in `thread` | `+0x418` | `+0x418` | unchanged |

Invariants (exact greps over the full-fileset disassembly): `sprr_pperm_el1` sites = **30** (none
GXF-gated); runtime metadata writer `strh w8,[x10,#0x2]` = **2**; `zalloc_ro_mut` callers = **54**.

## Evidence

[`evidence/persistence.md`](evidence/persistence.md) — pulled disasm for the 27.3 `proc_task`
accessor (with re-resolved anchor), the SPRR flip, and the cred reader, each with its reproduction
command.

## Verdict

As in 27.2: the zone-metadata submap is **not** read-only, `msr sprr_pperm_el1` is **not** trapped to
GL, and `proc_task` is **unchanged**. Two point releases on, the kernel credential wall is still the
same data-only boundary, defeated only by EL1 code execution (PAC + CTRR + SPTM). The one open
data-only lead (`fg_cred`/`so_cred` reader-side) is unchanged and still open — see
[`../../27.0.1/kernel-zone/reports/reader-gating.md`](../../27.0.1/kernel-zone/reports/reader-gating.md).
