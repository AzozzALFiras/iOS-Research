# pmm_exclave — physical-memory manager (C, the direct XNU boundary)

**Verdict:** hardened. `pmm_exclave` (an L4 frame manager, written in C) sits directly on the XNU
boundary — it creates frames from untyped memory XNU donates, and returns pages to XNU — so it is
the highest-priority memory-safety target in the exclave world. Every XNU-controlled value reaching
a sink is dominated by a bound/overflow check. Proven to the "road-blocked" bar.

- Binary: `exclavecore_bundle` → `APP/pmm_exclave` (512 KB code), base `0x07ffc000`. Build 27.0.1.
- Sources (from panic `file:line`): `pmm-server/src/{frame,frame_manager,bitmap,client}.c`,
  `libvas/Source/{vas,span,shadow}.c`, `DerivedSources/exclaves_upcalls_v2_C.c`.
- Ghidra full decompile: 1659 functions (used for the diff below too).

## The two XNU-facing channels (both audited incl. transitive callees)

1. **Tightbeam stats-delegate** — dispatcher `FUN_080057e0` reads a 64-bit selector, decodes u32
   args, and calls one of 4 handlers via a `__DATA_CONST` vtable (`0x807c170/1b0/1f0/250`,
   registered by `FUN_08000b44`). The data-bearing ones:
   - `FUN_08000cc8` (`stats_describe`, 1 u32 `statId`): bounded `statId < total`, with a `+199 < x`
     overflow guard and a fixed-0x100 copy guard.
   - `FUN_08000f3c` (`stats_get`, 2 u32 `startIdx,count`): bounded
     `count != 0 && startIdx < total && startIdx + count <= total` (the add can't wrap because
     `startIdx < total` small is required first).
2. **L4 IPC opcode handler** `FUN_08002e3c` (runtime-dispatched; opcode `= (param_2 >> 0x10) &
   0xffff`) + its callees (map `FUN_080036d8`, radix lookup `FUN_07ffdfc8`, scrub `FUN_07ffdc98`,
   batch `FUN_08003a58`, …).

## Guards verified (the dominating checks)

- IPC marshalling: message registers bounded `< 0x37` (`FUN_08019470/194e8`), src/dst cap registers
  `< 4` (`FUN_08019568/195fc`), each with a trap; subrange access overflow-checked
  (`offset ≤ MRs`, `size ≤ available`).
- `raw_frame_create` (`FUN_08004798`): `paddr ∈ [phys_base, phys_base+size)` ("too small"/"too big"
  fatals); the per-type untyped-cap index is array-bounds-checked.
- `untypeds_init` (`FUN_08003f78`, boot): ftid `< 3` ("invalid ftid" fatal) + overlap detection
  ("two untypeds that cover the same type").
- Conclave IDs: `0x3f <` → fatal (`FrameTag_Conclave`, `PMMTag_Conclave`); shmem group `7 <` → fatal.
- Return-pages-to-XNU batch: bounded `≤ 0x40` frames/batch, pointer-range-checked per element.
- Universal idiom: `lo ≤ x && x+sz ≤ hi && x ≤ x+sz` else `SoftwareBreakpoint(0x5519)`.

No XNU-controlled frame index / count / shmem group / shift / `CallSupervisor` frame-offset reaches
a sink without such a check. **No XNU-reachable memory-safety bug.**

## One residual, resolved in the kernel

`frame_free` (`FUN_08004a98`) / the cap-offset helper (`FUN_08004774`) compute a capability slot as
`((int)param_1 − (int)base) * 4 & 0xffffffc0 + cap_base`, masking low bits but not the high 32. But
`param_1` is an internal validated frame-object pointer (callers pass allocator objects; a paddr
only reaches here after `FUN_07ffdfc8` validation), and the `CallSupervisor(4)/(5)` target is a
**capability reference validated by the cL4 kernel** — so the real bound lives in the kernel's cap
handling, which is itself hardened by PAN (see
[`cl4-kernel-pan.md`](cl4-kernel-pan.md)). Not an XNU-controlled scalar; non-issue in pmm.

## 27.0.1 → 27.2 body-diff

Same binary size (589,824 B) but content changed in-place. **1507 / 1659 functions (91%)
byte-identical.** The changes are **not** added security checks — they are a refactor of the
fault-handler / memory subsystem: several large functions shrank drastically (696→69, 464→8,
304→99 insns) with logic pulled into 17 new helper functions = a new copy-on-write "delta page"
mechanism (strings `_delta_page_against_original`, `applyFixups: rebase failed`, RO scratch span).
One allocator function grew +19 insns = an added `os_add_overflow`/`round_bytes >= alloc_bytes`
guard — defense-in-depth, with doubtful reachability (needs a ~2^60-unit size). So the pmm diff
*supports* "Apple closed nothing exploitable here" — it is a feature refactor, not a bug fix.
