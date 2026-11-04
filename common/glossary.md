# Glossary

Terms used across the reports. Apple-specific mechanisms are described as observed in the shipping
firmware (27.0.1 / iPhone17,2), not from any internal documentation.

## Privilege / execution model
- **EL0 / EL1 / EL2** — ARM exception levels: userspace / kernel / hypervisor.
- **GL0 / GL1 / GL2** — Apple **Guarded Exception Levels** (GXF). A second privilege axis beside
  EL. XNU runs at GL1; the monitors (SPTM/TXM) run at **GL2**; entering guarded state is done with
  the `genter` instruction, not `SVC`.
- **GXF** — Guarded Execution Feature: Apple's mechanism for the GL axis and guarded transitions.

## Monitors & secure world
- **SPTM** — Secure Page Table Monitor. GL2 monitor that owns page-table integrity and the physical
  page **type** lattice. Even a compromised kernel must ask SPTM to change a mapping or retype a
  page. `SPTM-820.x`.
- **TXM** — Trusted Execution / Code-Signing Monitor. GL monitor owning code-signing and W^X
  (executable-mapping) decisions. Built with `-fbounds-safety`. `v7.0.0`.
- **PPL** — Page Protection Layer, the pre-SPTM mechanism SPTM replaced on newer silicon; some
  idioms (SPRR flips) are inherited.
- **Exclaves / SK** — the Secure-Kernel world: an L4/cL4/seL4-derived micro-kernel plus services
  ("conclaves") that protect secrets even if XNU is fully compromised. Shipped as
  `exclavecore_bundle`.
- **Tightbeam** — Apple's exclave IPC + serialization framework. **XnuProxy** is the XNU↔exclave
  bridge.

## Hardware memory protections
- **CTRR** — Configurable Text Read-only Region (a.k.a. KTRR successor). Hardware-locked read-only
  physical ranges. CTRR-A/B lock kernel **text** (by iBoot); CTRR-C/D lock kernel **data**
  (`__DATA_CONST` / `xnu_ro_data`) — on SPTM devices, **programmed and locked by SPTM at boot**.
- **SPRR** — Shadow Permission Remapping Register. A per-domain permission-*remap*: a PTE carries a
  small "protection index" and `sprr_pperm_el1` maps index→actual R/W/X per domain. Apple's RO-zone
  enforcement flips the index's entry `0xa`(RO)↔`0xb`(RW) around a legitimate write. **EL1-writable**
  (see kernel-zone report).
- **PAN** — Privileged Access Never. When `PSTATE.PAN=1`, EL1 loads/stores to EL0-accessible pages
  fault. Armed on every exception entry when `SCTLR_EL1.SPAN=0`. Bypassed only by `LDTR`/`STTR`
  (unprivileged load/store) or `msr PAN,#0`.
- **PAC** — Pointer Authentication. Signs pointers (return addresses, function pointers, some data
  pointers) to resist control-flow hijack; central to why EL1 *code execution* is hard to obtain.
- **PAPT** — the SPTM-managed physical-aperture page tables; XNU cannot write PTEs directly.

## XNU kernel objects
- **zone / zalloc** — the kernel heap allocator, partitioned into typed "zones".
- **`zone_require` / `zone_id_require`** — anti-type-confusion checks: validate that a pointer
  belongs to the expected zone (by range + per-page metadata zone-id) before use.
- **`ZC_READONLY` zone / `zalloc_ro_mut`** — read-only zones for security-critical objects
  (`proc_ro`, `ucred`, `cs_blob`); mutation only through a controlled SPRR-flipping writer.
- **proc / task / proc_ro** — process objects. `proc` and `task` are co-allocated (`proc_task`
  zone); `proc_ro` is the read-only companion holding credentials/csflags with panic-enforced
  backrefs.
- **ucred / kauth_cred** — process credentials (uid/gid/groups + MAC label + audit).

## Bug classes
- **int-overflow→alloc** — a `count*size` (or multi-factor) multiply overflows a 32/64-bit integer
  → undersized allocation → heap OOB. The canonical media-parser bug.
- **OOB r/w** — out-of-bounds read/write.
- **UAF** — use-after-free.
- **type confusion** — treating an object of one type as another (what `zone_id_require` resists).
- **TOCTOU / race** — time-of-check vs time-of-use; the SPTM concurrency findings.
- **zero-click** — triggered by data the victim merely receives (auto-decoded image/video/3D model).

## Diff/RE terms
- **patch-diff** — comparing two builds to find silently-fixed bugs (see
  [`../methodology/`](../methodology/)).
- **variant hunt** — after finding a fixed bug, scanning its siblings for the same unpatched pattern.
- **string-xref anchoring** — recovering stripped function identity from assertion/`__func__`/RTTI
  strings they reference.
