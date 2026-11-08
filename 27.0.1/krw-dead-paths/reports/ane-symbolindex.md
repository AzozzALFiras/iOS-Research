# ANE symbolIndex OOB — CVE-2026-84494

**Verdict:** ☠️ DEAD — kernel bug is real but architecturally unreachable from app sandbox.
**Build:** 24A446 (iPhone 17,2, A18 Pro)
**Evidence:** [`ane-sandbox-barrier.md`](../evidence/ane-sandbox-barrier.md)

---

## The bug (real)

In the `processInputBufferMappingInfo` function of the **AppleH16ANEInterface** kext,
`symbolIndex` is read from a shared memory buffer and used as an array index **without any
bounds check**:

```arm64
; processInputBufferMappingInfo — AppleH16ANEInterface kext, 24A446
ldr    w22, [x10]              ; w22 = symbolIndex   ← NO BOUNDS CHECK
lsl    x10, x22, #9            ; symbolIndex × 0x200 (stride)
ldr    w9, [x12]               ; OOB READ at kernel_table + symbolIndex×0x200
str    w22, [x12]              ; OOB WRITE (stores symbolIndex value back)
```

**Fix in 27.2:** `cmp w19, w8` (symbolIndex vs `totInputBuffers`) followed by `b.hs` to error
path. This confirms the bug was considered exploitable by Apple.

### OOB primitive characteristics

| Property | Value |
|----------|-------|
| Read stride | `symbolIndex × 16` (Array 1) |
| Write stride | `symbolIndex × 0x200` (Array 2, 512 bytes per step) |
| Write offset | `+0xA4C` into each slot |
| Additional copy | `memcpy(dst, src + symbolIndex × 0xB40, 0x200)` — 512 bytes |
| Control | Full — `symbolIndex` comes from the model file |

This is a powerful OOB primitive: large stride (0xB40 = 2880 bytes per step), write + copy
capabilities, fully controlled index. The 5 missing bounds checks (procedure_id, input/output
symbol indices, IO counts, endpoint offset+size) compound the reach.

---

## Why it's dead — the sandbox barrier

### The architecture

```
App process                 aned daemon              Kernel (kext)
───────────                 ───────────              ─────────────
CoreML API                                           AppleH16ANEInterface
  ↓                                                       ↑
MLModel.load()                                            │
  ↓                                                       │
espresso/CoreML              aned                         │
  ↓  (XPC)                  ↓                             │
  ───────────────────→  receives model                    │
                        compiles for ANE                  │
                        creates program  ─── IOKit ───→  ProgramCreate (sel 2)
                        maps mutable buf ─── IOKit ───→  MapMutableWeights (sel 8)
                        prepares program ─── IOKit ───→  ProgramPrepare (sel 4)
                        sends inference  ─── IOKit ───→  SendRequest (sel 5)
                             ↑
                     The mutable weights
                     buffer lives HERE —
                     in aned's address
                     space, mapped to the
                     kext via IOKit sel 8
```

The **mutable weights buffer** — the buffer that `processInputBufferMappingInfo` reads
`symbolIndex` from — is created by the `aned` daemon and mapped directly to the kext. The app
process never sees this buffer.

### Five delivery paths tested and eliminated

#### Path 1: Direct IOKit

Open `H11ANEIn` service and call selectors directly.

**Result:** `kIOReturnNotPermitted`. The ANE user client requires connection through the `aned`
daemon's XPC service. Apps cannot open the IOKit connection directly, even with
`com.apple.ane.iokit-user-access` (which CoreML has, but which routes through `aned`).

#### Path 2: CoreML inference (ANEDeepDiag v1, 11 phases)

Load a compiled CoreML model with `.cpuAndNeuralEngine`, run inference, install IOKit hooks
(fishhook) to intercept `IOConnectCallStructMethod` / `IOConnectMapMemory64`, scan all RW
memory regions for the mutable weights header format (`ane_mutable_weights_header_t`).

**Result:**
- 0 IOKit calls captured by hooks (the calls happen in `aned`'s process, not ours)
- ANE Mach-O loaded at `0x1179b0000` — visible but read-only
- 32 MB buffer found — all zeros, no procedure info
- `MapMutableWeights` (sel 8): never seen
- `GetMutableWeights` (sel 10): never seen

#### Path 3: MLUpdateTask (ANEUpdateDiag v2)

Use CoreML's training API (`MLUpdateTask`) to force weight updates, hoping the mutable weights
buffer would be created in the app's address space.

**Result:**
- Training succeeds: `loss=4.1553`, completes in ~14ms
- **Runs entirely on CPU** — zero IOKit calls, zero ANE kext involvement
- 0 mutable weight headers found after training
- 48 new small regions appeared — all tensor descriptors (`02 00 00 00 02 00 00 00 40 00 00 00 09 00 00 00`), not the mutable weights format
- The `0x274xxx000` region changes between training rounds (fill 0%→21%→32%→12%) — but contains CPU-side weight matrices, not ANE procedure info

#### Path 4: ANE cache patching

Locate compiled ANE model cache files in the app sandbox, binary-patch the `symbolIndex` field
at offset `+0x204` of the `0xB40`-stride mapping record, reload from cache.

**Result:** "No ANE-related cache files found in sandbox." The compiled ANE programs are stored
in `aned`'s cache directory, not the app's sandbox.

#### Path 5: vm_region exhaustive scan

Scan all RW regions in the process for any buffer matching the mutable weights header format
(standard layout, relaxed layout, alternate offsets).

**Result:** 0 matches across all regions. The header format (`magic_version` + `flags` +
`total_data_size` + `num_procedures` + procedure offsets) does not exist anywhere in the app's
address space.

### Write-access confirmation

A canary test confirmed that the regions we can find **are writable**:

```
Write region 0x104828000: wrote 0xcafe0002 read 0xcafe0002 — WRITABLE ★
```

The problem is not write permission — it is that the **target buffer does not exist in our
address space**.

---

## The deeper lesson

This is a case where a **kernel bug is real and powerful** (unchecked index, large stride OOB
with read+write+copy capabilities, 5 missing checks) but **architecturally unreachable** from
the intended attack position (app sandbox).

The defense is not a bounds check or a mitigation — it is the **process boundary** between the
app and `aned`. The XPC daemon architecture means the app never directly handles the data
structures that the kext parses. Even with full control over the CoreML model file, the app
cannot influence the mutable weights buffer because:

1. `aned` compiles the model independently
2. `aned` creates the buffer in its own address space
3. `aned` maps the buffer to the kext via IOKit
4. The app is not part of this transaction

To exploit this bug, an attacker would need either:
- Code execution in `aned` (a separate vulnerability)
- A way to inject data into `aned`'s IOKit mappings from outside (no known mechanism)
- A different kernel entry point that reads `symbolIndex` from app-controlled memory (none found)

---

## Related

- Evidence: [`ane-sandbox-barrier.md`](../evidence/ane-sandbox-barrier.md)
- Lesson: XPC daemon mediation is an effective (if implicit) mitigation against kext-level bugs
