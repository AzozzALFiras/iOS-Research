# `zone_require` / `zone_id_require` — the anti-type-confusion mitigation

Full RE of XNU 27.0.1's zone-pointer validation (build 24A446, iPhone17,2). This is the mechanism
whose *trust boundary* is analysed in [`trust-boundary.md`](trust-boundary.md); here is how the check
itself works and where its data lives.

## The check

Deployed at **165 sites**, guarding ≥ 12 zone types:

- `zone_require(zone_t, void*)` @ `0xfffffff00b41101c` — reads `z_elem_size` from `[x0, #0x34]`.
- Inlined fast path `zone_id_require(zid, elem_size, addr)` with compile-time constants.
- id→zone thunk @ `0xfffffff00b411140` (`zone_array` @ `0xfffffff00b747f80`, `sizeof(zone)=0xc0`).
- RO variant `zone_require_ro` @ `0xfffffff00b411164`.

Algorithm:
1. Range-check `addr ∈ [base, bound]` (the zone-map range).
2. Metadata entry = `metadata_base + (addr >> 14) * 16` — one 16-byte entry per 16 KiB page.
3. The entry's halfword: bits `[0:9]` = zone id (`and #0x3ff`), bit `[10]` = a flag, bits `[12:15]`
   = page-state (`0xe` = `ZM_SECONDARY_PAGE`).
4. Compare the id to the expected zone id (e.g. `0x1a` for `proc_task`).

## The two backing structures (different trust)

- **Anchors** (`__DATA_CONST.__const`): `0xfffffff007de5de0` = zone-map range `[base, bound]`;
  `0xfffffff007de5e90` = metadata base ptr (+ `…de5e30`/`…debdd0` = RO-zone range / RO-id table).
  `__DATA_CONST` = `xnu_ro_data` = SPTM region `BootKC-rs`, inside **CTRR-D**, **programmed and
  locked by SPTM at boot** (`ctrr_lock_sptm`); SPTM panics if `__DATA_CONST ⊄ BootKC-rs`. XNU only
  *reads* `ctrr_d_{lwr,upr}_el2` into `rorgn_begin/end` (`0xfffffff007e10c20/c28`) for a software
  `rorgn_contains`. ⟹ even with kernel R/W the attacker **cannot** redirect the metadata base ptr
  or resize the zone range.
- **Metadata array** (what the base points to): an ordinary RW kernel submap
  (`ksubmap[metadata]`), reserved cur/max = RW/RW via `vm_map_enter` at perm-init
  `sub_fffffff00b40f8d0`. Runtime writers (`zalloc`/`zfree` fast path `sub_fffffff00abcf938`) update
  the zone-page metadata with a plain `strh w8,[x10,#0x2]` (`@0xabcfac4`) to the **same VA**
  `zone_require` reads (`ldrh @0xabcfaac`). **No RO-alias, no privileged write path, not in any
  SPTM-protected range** (SPTM installed those PTEs writable).

## Consequence

- Against a **constrained** primitive (type confusion without full R/W), `zone_id_require` is
  effective — you cannot make a fake object pass the id check.
- Against **full kernel R/W**, the metadata array is writable, so the id halfword is **forgeable**
  (stamp `0x1a` onto a controlled page to fake a `proc_task`). Only the anchor (base + range) is
  immutable. The metadata base ptr is **not** PAC-signed and entries have no checksum/canary (V3).

So `zone_id_require` **raises the bar before R/W** but is **not a post-R/W boundary**. A forge buys
type-confusion on regular zones only; the credential substrate is in RO zones — continue to
[`trust-boundary.md`](trust-boundary.md).
