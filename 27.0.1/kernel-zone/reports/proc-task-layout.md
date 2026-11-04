# proc_task zone layout (XNU 27.0.1, iPhone17,2)

Confirmed offsets for the co-allocated `proc_task` element, from static disassembly of the
`task → proc` accessor (`get_bsdtask_info`) at unslid VA `0xfffffff00ac4b408` in the
`com.apple.kernel` fileset entry (kernelcache 24A446).

## Layout

The `proc_task` zone allocates a single element holding **both** structures: `[ proc | task ]`.

| field | value | source |
|---|---|---|
| `task = proc + 0x768` | accessor does `subs x1, x0, #0x768` → `proc = task − 0x768` | `get_bsdtask_info` |
| element size | `0xe38` (bound check `proc + 0xe38`); task portion ≈ `0x6d0` | |
| zone-id | **`0x1a`** (validated via `(addr >> …)` index into zone metadata, `cmp #0x1a`) | `zone_id_require` sites |
| task "active" flag | `[task + 0x6c8] & 1` (NULL proc if clear) | accessor |
| `proc->p_pid` | `+0x60` | `pid_for_task_trap` `0xfffffff00b0e54c4` |

Zone-validation globals (`__DATA_CONST`): zone range pair `0xfffffff007de5de0`; zone metadata base
`0xfffffff007de5e90`. The layout is XNU-build-determined → it holds for other 27.0.1 devices on the
same build (the kernelcache on hand is iPhone17,2).

## Cross-check against the public Chollima / Calif.io demo

The public jailbreak demo on iPhone 18 Pro Max / 27.0.1 leaked `proc = 0x…d540`, `task = 0x…dca8`
→ **Δ = 0x768**, exactly matching the static layout above. That confirms the tool resolves the live
`proc_task` element (i.e. it already has kernel R/W), and validates our static offsets against a
real device. The demo also leaked a vm_map (zone tag `a`) and pmap (tag `6`) as separate zones —
consistent with pmap reach on 27.0.1 being SPTM-mediated. The demo shows the *capability*
(post-exploitation state + per-boot KASLR), not the entry bug.

## Why it matters

`proc_task` (id `0x1a`) is the prime target for a zone-id *forge* (it is a regular, forgeable zone —
see [`trust-boundary.md`](trust-boundary.md)), but forging a fake `proc_task` alone does **not** yield
credentials: those live in the read-only companion `proc_ro`/`ucred` behind the SPRR wall, with
panic-enforced `proc_ro ↔ task` backrefs. So this layout is the entry to the type-confusion
reasoning, and the RO wall is where that reasoning stops.
