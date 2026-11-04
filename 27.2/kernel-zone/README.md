# Kernel-zone trust architecture — iOS 27.2 (24B119): persistence check

27.2 is the "fixed" build in this repo's media-parser diff track, but on the **kernel-zone** surface
nothing moved: the `proc_task` layout, the forgeable zone-metadata, the SPRR RO-wall gating, and the
content/reader gates are all structurally identical to 27.0.1. Only addresses shifted. This file
records the re-resolved 27.2 addresses and the persistence evidence; the full analysis lives in
[`../../27.0.1/kernel-zone/`](../../27.0.1/kernel-zone/) and the cross-version table in
[`../../27.0.1/kernel-zone/reports/three-version-diff.md`](../../27.0.1/kernel-zone/reports/three-version-diff.md).

Kernelcache: `kernelcache.release.iPhone17,2` (24B119). Addresses re-resolved by instruction/anchor
fingerprint (segments shift non-uniformly from 27.0.1).

## Re-resolved addresses (27.2)

| structure | 27.0.1 | **27.2** | persistence |
|---|---|---|---|
| `get_bsdtask_info` (`proc_task` accessor) | `0xfffffff00ac4b408` | `0xfffffff00ac94938` | `task=proc+0x768`, elem `0xe38` — identical |
| regular zone-range anchor (`__DATA_CONST`) | `0xfffffff007de5de0` | `0xfffffff007df2040` | same `{base,bound}` role |
| public `zalloc_ro_mut` | `0xfffffff00ac482b8` | `0xfffffff00ac917e8` | **54 callers** (unchanged) |
| `pmap_ro_zone_memcpy` SPRR flip | `0xfffffff00ad31c98` | `0xfffffff00ad7cd40` | identical 3-insn flip, validate-before-flip |
| hot cred reader (`t_tro`) | `0xfffffff00ac4b5a0` | `0xfffffff00ac94ad0` | **1060 callers**; `cmp w8,#0x3` + backref |
| `t_tro` offset in `thread` | `+0x418` | `+0x418` | unchanged |

Invariants (exact greps over the full-fileset disassembly): `sprr_pperm_el1` sites = **30** (none
GXF-gated); runtime metadata writer `strh w8,[x10,#0x2]` = **2**; `zalloc_ro_mut` callers = **54**.

## Evidence

[`evidence/persistence.md`](evidence/persistence.md) — pulled disasm for the 27.2 `proc_task`
accessor (with re-resolved anchor), the SPRR flip, and the cred reader, each with its reproduction
command.

## Verdict

None of the three candidate 27.2 hardening changes happened: the zone-metadata submap is **not**
read-only, `msr sprr_pperm_el1` is **not** trapped to GL, and `proc_task` is **unchanged**. The
kernel credential wall in 27.2 is the same data-only boundary as 27.0.1 — it still reduces to
"prevent EL1 code execution" (PAC + CTRR + SPTM).
