# Exclaves — the Secure-Kernel (cL4) world (iOS 27.0.1)

"Exclaves" are Apple's secure-world services, designed to protect secrets **even if XNU is fully
compromised**. They run under an L4/cL4/seL4-derived **Secure Kernel (SK)**, talk to XNU through
the **XnuProxy / Tightbeam** IPC+serialization layer, and are the newest and least-combed system-
security surface on the device. This is (as far as the author knows) the first full teardown of the
bundle in a public learning context.

## The bundle

`Firmware/image4/exclavecore_bundle.t8140.RELEASE.im4p` (32 MB, img4 type `excl`). Decompress with
`ipsw img4 im4p extract`, map with `ipsw fw exclave -i`, extract with `ipsw fw exclave -o`:

| Compartment | Size | Language | Role |
|---|---|---|---|
| `SYSTEM/kernel` | 96 KB code | asm/C (cL4) | the Secure Kernel micro-kernel (the TCB) |
| `APP/roottask` | 7.2 MB | Swift | the root task / supervisor |
| `APP/pmm_exclave` | 512 KB code | **C** | physical-memory manager (frames, DART page tables) |
| `APP/sharedcache` | 22 MB | Swift + C++ | all the conclave **services** |
| `APP/roottask.brkr_artifact` | 1.7 MB | — | broker artifact |

Conclaves present (strings): audiomxd, darwinaudiod, securepairingd, corespeechd, cameracaptured,
micactivityd, relevanced, perceptiond, soundanalysisd, mediaserverd, backboardd, **ANEExclave**,
**StorageExclave**, **EXSurface**, SISP (ISP / SecureM3), SharedDARTMapper.

> **Tooling note:** `ipsw fw exclave` rebuilds the *cL4 kernel* Mach-O from the boot **manifest**,
> not the code (0 `pacibsp`, 0 `ret` in the extracted file). The real kernel code (165 functions)
> lives inside the decompressed bundle and must be **carved and raw-loaded** into Ghidra at base
> `0xfffffc0000000000`. See [`methodology/`](../../methodology/).

## Audit results — all four surfaces hardened

### pmm_exclave (C — the direct XNU boundary, highest priority)
XNU reaches pmm through two Tightbeam channels (a stats-delegate interface `FUN_080057e0` → 4
handlers, and an L4 opcode handler `FUN_08002e3c`). Every XNU-controlled value — frame index,
conclave id, shmem group, count, shift, `CallSupervisor` frame-offset — is dominated by a
bound/range/overflow check that traps (`SoftwareBreakpoint 0x5519`) on violation. The low-level IPC
message/cap registers are bounded (`< 0x37` MRs, `< 4` caps). **No XNU-reachable memory-safety bug.**

### cL4 micro-kernel — the keystone finding (architectural, not a bug)
No `SVC`; syscalls enter via Apple **GXF/`genter`**. Dispatcher
`FUN_fffffc000000842c(cap1, cap2, selector)`: `0`=Invoke, `1`=insert, `2`=Delete, `3`=Move,
`4`=Revoke, `5`=Revoke-children. Untyped retype, IPC transfer (popcount ≤ 0x36), CNode sub-indexing
(`idx < 4`), page-table indices (masked `& 0x7ff`), and **all 28 variable-shift sites** (masked
`& 0x3f`) are textbook-guarded.

**The interesting part:** capabilities are addressed by a *raw caller pointer*
`param_1 & 0xfffffffc0` (a 36-bit, 64-byte-aligned slot address) dereferenced **directly** as the
CTE — **no CNode radix walk, no software bound**. Safety rests entirely on **PAN (Privileged Access
Never)**:

- `SCTLR_EL1 = 0x3454DD9D`, bit 23 (SPAN) = 0 ⇒ PAN is armed on every exception entry.
- The cap read is a plain `LDR` under the task's own TTBR0.
- A page is EL0-writable **iff** its PTE `AP[1] = 1` — and with PAN=1 an EL1 `LDR` of such a page
  **faults**. The CNode pages the kernel *can* read have `AP[1] = 0` (EL0 no-access), which the task
  can neither read nor write. **The two conditions for cap-forgery are mutually exclusive.**
- Verified: the whole kernel contains **0** `msr pan`, `ldtr`, `sttr`, `at s1e0` ⇒ PAN is never
  cleared or bypassed. Objects live in TTBR1 (EL0 has none).

So "caps are named by address, not bounded index" is **by design and safe** — a nice example of a
hardware mitigation (PAN) standing in for a software check. Watch-list for future revisions: any
EL0-reachable handler that clears PAN / uses `LDTR` for a cap read, or an object-type template that
makes a cap-slot type EL0-accessible — neither exists in 27.0.1. Full write-up:
[`reports/cl4-kernel-pan.md`](reports/cl4-kernel-pan.md).

### EXSurface service (Swift)
The surface-create / ImageLayout path (`sub_8868fd4` in the service cache) is pervasive Swift
**checked** arithmetic: every `adds`/`subs` traps on overflow (`b.vs → brk`), every array subscript
is bounds-checked (`cmp idx,count; b.hs → brk`), and there is **no raw unchecked multiply** of
`w×h×stride`. Overflow = a trap (DoS, by-design), not corruption. Hardened.

### ANE ZinRt deserializer (C++ — the one memory-unsafe service)
`ZinComputeProgram`/`ZinRt` parses a **Mach-O-like** compute-program (mach_header / load commands /
segments / symbols / relocations / bindings) from XNU-supplied model bytes — exactly the
dyld/ImageIO-style bug-prone shape, in C++. Yet it uses the correct discipline: a `ValidHeader`
gate (magic `0x19`, 8-byte align, size ≥ 0x48, count ≤ 0x100), a `CheckRuntimeDataAccess(ptr,len,
span)` bounds helper before field reads, and **widening `umull`** for count×size (191 widening vs
~10 non-widening multiplies, and every non-widening one is a divide-by-constant idiom or a
bounds-checked `index×stride`). Hardened. (One low-confidence site, `0x83df14c`, noted in
[`../../STATUS.md`](../../STATUS.md).)

## Overall verdict

Four surfaces deep-audited — pmm (C), cL4 kernel (TCB), EXSurface (Swift), ANE ZinRt (C++) — **all
comprehensively hardened, no exploitable bug.** The exclave world matches the project-wide pattern,
now extended to a previously-untouched surface, with one genuinely instructive architectural result
(VA-addressed capabilities + PAN).

## Detailed reports

- [`reports/pmm.md`](reports/pmm.md) — physical-memory manager (C), the direct XNU boundary + the 91%-unchanged diff.
- [`reports/cl4-kernel-pan.md`](reports/cl4-kernel-pan.md) — the VA-capability + PAN proof (flagship "road-blocked").
- [`reports/exsurface.md`](reports/exsurface.md) — EXSurface layout math (Swift checked-arithmetic).
- [`reports/ane-zinrt.md`](reports/ane-zinrt.md) — the C++ Mach-O-like ANE deserializer.
