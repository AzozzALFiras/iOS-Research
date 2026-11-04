# SPTM 27.0.1 — architecture & GL1 attack surface

Evidence-cited reconstruction of the Secure Page Table Monitor from the stripped `sptm.t8140` Mach-O
(`SPTM-820.0.22`, iPhone17,2). Recovered by string-xref (assert messages name functions/fields) +
disassembly. This is the map a reader needs before the findings in [`findings.md`](findings.md); it
claims **no** bug — it is an attack-surface document.

## Privilege model
- SPTM runs at **GL2**; XNU/kernel at GL1; userspace effectively GL0. Exception vectors
  `@0xfffffff0270f8000`.
- GL1 reaches SPTM through **40 enumerated `SPTM_FUNCTIONID` endpoints**.

## Dispatch (two-stage, PAC-authenticated)
- State machine `@0xfffffff0270e5b2c`: `state < 0x17`, `event ≤ 0xe`, transition table at
  `base + state*0x1e0 + event*0x20`.
- Per-domain endpoint lookup `@0xfffffff0270e62c0`: `endpoint*0x18`, with a permission bit.

## Frame Table (the physical-page type/refcount database)
- 16-byte FTE per physical page, indexed `(paddr − managed_start) >> 0xe` (16 KiB pages). Base
  `DAT_…27091520`; window bounds `…21f8 / …2200`.
- FTE layout (refined via the §F2 trace): `+0` word0 (bit0 = in-flight exclusive lock), `+2` type,
  `+4` flags, `+5` iommu_read_refcnt (u8), `+8` read_refcnt (u32), `+0xc` write/exec_refcnt (u32).
- **56 / 56 FTE-indexing functions** re-check `managed_end` before use (verified in the cold audit).

## Retype & the type lattice (the core invariant engine)
- Retype core `@0xfffffff0270ece94`: align + managed + `type ≤ 0x43` + atomic exclusive claim +
  allowed-transition check (128-bit bitmap in the 0x90-byte per-type descriptor
  `@DAT_…27092230 +0x40/+0x48`) + owner-domain check + per-type handler (`PTR_FUN_…270922a0`,
  stride 0x12).
- Type-descriptor table: 68 entries, stride 0x90, magic `0xacce55ed@+8`, class@+1, handler ptrs
  @+0x38/+0x68/+0x70 (chained-fixups). Type **names** recovered from a parallel array (file
  `0x1a6b8`): `0x00 SPTM_UNTYPED`, `0x0b XNU_DEFAULT`, `*_ROOT_TABLE`, `*_PAGE_TABLE`, `0x2a
  TXM_DEFAULT`, `0x3f SK_DEFAULT`, `0x43 SK_XNU_CONTENT`; `0x44+ = VIOLATION_*` (unreachable, retype
  bounds `type ≤ 0x43`).

## Verified invariants (why the type system is sound)
1. **W^X** — every →page-table-type transition dispatches the target's `+0x38` handler =
   `FUN_…e0a08 → bzero(page, 0x4000)`; a new page table is always zeroed, regardless of source, so
   no attacker stale PTEs survive. Data/default types use a no-op `+0x38` handler (correct — don't
   zero data pages).
2. **Owner-domain gate** — a cross-domain transition can only be initiated by the current type's
   owner domain.
3. **PT-free safety** — freeing a page table requires `mapping_refcnt == 0 && nested_refcnt == 0`
   (`FUN_…dfac8`); link/unlink refcounts are overflow/underflow-guarded (`FUN_…e1400`).
4. **PAPT perm invariant** `@0xfffffff0270d4720` — a page is writable only during an in-flight
   retype.

## Input discipline
GL1 scalars arrive as `X_U.UNSAFE_VALUE`, are `sanitize_integer`'d inline and `__builtin_*_overflow`-
checked before use. Static regions (`__DATA_CONST` = `xnu_ro_data` = `BootKC-rs`) are inside CTRR-D,
**locked by SPTM at boot** (SPTM panics if `__DATA_CONST ⊄ BootKC-rs`). iBoot locks CTRR-A/B (text);
SPTM locks CTRR-C/D (data).

## Cold audit result (the "road blocked" summary)
Across the crown-jewel GL1 surfaces — DART map/unmap + SID/IOVA validation, retype + type lattice,
PT map/update/PAPT + multi-segment, guest/stage-2, shared-region indexing, VMID bitmap, guest
VA→IPA — **no confirmed post-boot exploitable bug**. The bounds/arithmetic/invariant layer is solid
and consistent; every indexing path re-checks its bound, every table is sized to the full index-type
range, every GL1 scalar is sanitized + overflow-checked. The confirmable defect *class* on 27.0.1 is
**concurrency / TLB-coherence / invariant** (the findings in [`findings.md`](findings.md)), not
spatial safety.
