# Kernel zone-pointer validation & the post-R/W trust boundary (iOS 27.0.1)

This is the sharpest part of the research for *exploitation reasoning*: given a memory-corruption
bug that yields a kernel read/write primitive, **what do iOS 27.0.1's mitigations still deny you**,
and where is the real wall? Static analysis of `kernelcache.release.iPhone17,2` (build 24A446).

Cross-checked against the public **Chollima / Calif.io** 27.0.1 jailbreak demo (a capability demo,
post-exploitation state — it shows a tool that already has kernel R/W; it does not reveal the entry
bug).

## proc_task zone layout (confirmed)

From the `task → proc` accessor (`get_bsdtask_info`) at unslid `0xfffffff00ac4b408`:

- `task = proc + 0x768` (co-allocated `[proc | task]` element)
- element size `0xe38`; zone-id `0x1a`; `task.active` flag at `[task + 0x6c8] & 1`
- `proc->p_pid` at `+0x60`
- Layout is XNU-build-determined → holds for other 27.0.1 devices.

The Chollima demo leaked `proc`/`task` with Δ = 0x768 → confirms our static layout matches the
live element on a real jailbroken 27.0.1 device.

## The mitigation: `zone_require` / `zone_id_require`

Deployed at **165 sites**, guarding ≥ 12 zone types against type-confusion:

- `zone_require(zone_t, void*)` @ `0xfffffff00b41101c`; inlined fast path
  `zone_id_require(zid, elem_size, addr)` with compile-time constants.
- Algorithm: range-check the pointer in `[base, bound]`; then read the per-page metadata entry
  `meta_base + (addr >> 14) * 16`; the halfword's low 10 bits are the zone id, compared to the
  expected id. `proc_task` is id `0x1a` (12 guard sites).

## Trust boundary (the key result)

Two data structures back the check — and they have **very different** protection:

| | Protection | Attacker (kernel R/W) can change it? |
|---|---|---|
| **Anchor** — metadata base ptr + zone range (`0xfffffff007de5de0`, `…5e90`) | in `__DATA_CONST` = `xnu_ro_data` = SPTM region `BootKC-rs`, inside **CTRR-D**, **locked by SPTM at boot** | **No** — hardware-immutable |
| **Metadata array** (what the base points to) | ordinary RW kernel submap (`ksubmap[metadata]`), reserved RW/RW; runtime writers use plain `strh` to the *same* VA the check reads; **not** in any SPTM-protected range | **Yes** — forgeable |

So `zone_id_require` **defeats constrained primitives** (type-confusion *before* you have full
R/W), but **is bypassable under full kernel R/W** by forging a page's zone-id halfword (e.g. stamp
`0x1a` to fake a `proc_task`). It raises the bar; it is **not** a post-R/W boundary.

## The real post-R/W wall: read-only (`ZC_READONLY`) zones

Credentials and process security state do **not** live in the forgeable regular zones. They live in
RO zones — `proc_ro`, `ucred`/`kauth_cred` (uid/gid/groups + MAC label + audit), `cs_blob` (code
signing) — which are genuinely immutable under **data-only** R/W:

- `zone_require_ro` @ `0xfffffff00b411164` (separate id namespace).
- Mutation funnels through `zalloc_ro_mut` @ `0xfffffff00b4112cc` → pmap worker
  `sub_fffffff00ad31c08`, which brackets the write with IRQs off and an **SPRR permission flip**
  (`msr sprr_pperm_el1`, index `0xa`→`0xb`→`0xa`). RO-zone pages are read-only in the normal SPRR
  domain → a data-only arbitrary write **faults**.
- `proc_task` (id `0x1a`) has an RO companion `proc_ro` with **panic-enforced** bidirectional
  backrefs ("proc_ro->task backref mismatch") → forging a `proc_task` alone is insufficient.

⟹ a zone-id forge buys **type-confusion on regular objects, not a direct credential overwrite**.

## Is the RO wall itself final? (the `sprr_pperm_el1` question — resolved)

**No — the RO wall is a *data-only* boundary, not a *code-exec* boundary.** `sprr_pperm_el1` (the
per-index SPRR permission *remap* register that decides whether the RO-zone index maps to RO or RW)
is **freely EL1-writable** — XNU's own RO-write worker flips it inline:

```asm
mrs x8, sprr_pperm_el1 ; mov x9, #0xb ; bfi x8, x9, #8, #4 ; msr sprr_pperm_el1, x8 ; isb   ; → RW
...   (the RO-zone memcpy)
mrs x8, sprr_pperm_el1 ; mov x9, #0xa ; bfi x8, x9, #8, #4 ; msr sprr_pperm_el1, x8 ; isb   ; → RO
```

There are **30** `msr/mrs sprr_pperm_el1` sites in the EL1 kernel text and **none** is GXF-gated
(the `sprr_config_el12` / `gxf_config_el12` registers are boot/CPU-init only). So an attacker with
**EL1 code execution** flips RO→RW globally in three instructions and the RO wall is gone. A subtler
path without crafting the `msr`: a PAC-defeating call-primitive that invokes `zalloc_ro_mut` with
`dst` = a legitimate RO element you own + a forged `src` (it does the SPRR flip internally, but
validates "same zone / from RO zone map" at entry).

## The full trust chain (27.0.1)

```
corruption bug
  → constrained primitive        (zone_id_require raises the bar)
  → data-only kernel R/W
  → RO-zone SPRR wall            (holds vs data-only: credentials stay immutable)
  → to cross it you need EL1 CODE EXECUTION
  → blocked by:  PAC  +  CTRR-A/B (kernel __TEXT read-only, iBoot-locked)
                      +  SPTM  (PAPT / W^X: can't map RWX, can't edit PTEs)
```

So on 27.0.1 the real wall protecting credentials is **"prevent EL1 code execution"**, enforced by
the PAC + CTRR + SPTM triad — *not* SPRR by itself. This is exactly why the SPTM / exclave layer
(documented elsewhere in this repo) matters: it is the floor the whole chain rests on.

Addresses & details: [`zone_validation_trust_boundary.md`](zone_validation_trust_boundary.md).
