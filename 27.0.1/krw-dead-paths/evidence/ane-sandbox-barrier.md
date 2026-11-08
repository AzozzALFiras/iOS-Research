# Evidence: ANE mutable weights buffer is in `aned`, not the app

**Build:** 24A446 (iPhone 17,2, A18 Pro, `d94ap`)
**Claim:** The mutable weights buffer read by `processInputBufferMappingInfo` (the function
with the CVE-2026-84494 symbolIndex OOB) exists in the `aned` daemon's address space, not in
the calling app's address space. The app cannot deliver a crafted `symbolIndex` to the kext.

---

## Reproduction

### Test 1 — ANEDeepDiag v1 (11 phases)

**Method:** Installed IOKit hooks via fishhook to intercept `IOConnectCallStructMethod`,
`IOConnectCallMethod`, and `IOConnectMapMemory64`. Loaded a compiled CoreML model
(`ANETarget.mlmodelc`) with `.cpuAndNeuralEngine` compute preference. Ran inference. Scanned
all RW memory regions before and after.

**Key results:**
```
Phase 1: Hooks installed — monitoring IOConnectCall* and MapMemory64
Phase 3: Model loaded (ANETarget.mlmodelc, isUpdatable=YES)
Phase 4: Inference result: OK
  ── IOKit hooks (after inference) ──
  Calls captured: 0           ← ZERO IOKit calls in our process
  Memory maps:    0
  ANE connection: 0x0
  MapMutableWt:   false
  GetMutableWt:   false
Phase 6: ✗ No mutable buffer found (standard scan)
         ✗ No mutable buffer found (relaxed scan)
Phase 8: No ANE-related cache files found in sandbox
Phase 9: ✗ IOKit BLOCKED: kIOReturnNotPermitted (XPC gate)
```

**Interpretation:** Zero IOKit calls were intercepted because the IOKit calls happen in
`aned`'s process (the XPC daemon), not in our app. The hooks only see calls made from **our**
address space. `aned` makes the IOKit calls on our behalf after receiving the model via XPC.

### Test 2 — ANEUpdateDiag v2 (MLUpdateTask)

**Method:** Used CoreML's `MLUpdateTask` API to force model weight updates, hoping the mutable
weights buffer would be created in the app's address space (since training modifies weights).

**Key results:**
```
Phase 3: Update result: OK (loss=4.1553 epochs=0)  ← training succeeds
         Update time: ~14ms                         ← very fast = CPU, not ANE
Phase 5: Changed/new RW regions after update: 0     ← no new LARGE RW regions
         New small regions: 48                       ← tensor descriptors only
Phase 6: ✗ No mutable header with procedures found anywhere
         Alternate layout scan: 0 alternate layout matches
Phase 7: Large RW after Round 1:
           0x274030000 31MB fill=21%                ← data appears
         Large RW after Round 2:
           0x274050000 31MB fill=32%                ← more data, address shifted
         Large RW after Round 3:
           0x274070000 31MB fill=12%
         ★ BUT: 0 mutable weight headers found in any round
Phase 8: Write test: 0x104828000 wrote 0xcafe0002 read 0xcafe0002 — WRITABLE
```

**Interpretation:**
- MLUpdateTask runs on **CPU** (14ms completion time, zero IOKit calls) — it does not use the
  ANE kext for backpropagation
- The `0x274xxx` region does fill with data between training rounds, but this is **CPU-side
  weight matrix data**, not the `ane_mutable_weights_header_t` format that the kext reads
- The base address shifts by `0x20000` each round (0x274010000 → 0x274030000 → 0x274050000),
  indicating CoreML remaps the buffer each iteration
- The 48 new small regions all contain the ANE tensor descriptor header
  (`02 00 00 00 02 00 00 00 40 00 00 00 09 00 00 00`) — these are model metadata, not the
  mutable weights buffer
- Write access is confirmed (canary test passed) — the problem is not permissions, it is that
  the target buffer **does not exist** in our address space

### Additional checks

| Check | Result |
|-------|--------|
| Direct `IOServiceOpen("H11ANEIn")` | `kIOReturnNotPermitted` |
| ANE cache file scan (`~/Library/Caches`, `~/tmp`, etc.) | 0 ANE-related files found |
| Full vm_region scan for `ane_mutable_weights_header_t` | 0 matches (standard + relaxed + alternate layouts) |
| XPC daemon paths | `/usr/libexec/aned` EXISTS, `/System/Library/PrivateFrameworks/ANECompiler.framework` EXISTS |

---

## Binary basis

The vulnerable function `processInputBufferMappingInfo` reads the mutable weights buffer that
was mapped via IOKit selector 8 (`MapMutableWeights`). The mapping call is made by `aned`:

```
aned process:
  IOConnectCallStructMethod(connection, 8 /*MapMutableWeights*/, input, 0x20, NULL, NULL)
  → kext creates mapping from aned's address space buffer to kernel-internal array
  → symbolIndex at buffer+offset is read by processInputBufferMappingInfo
  → OOB occurs relative to kernel-internal arrays (stride 0xB40, write at +0xA4C)
```

The app never calls selector 8. The app never has a valid ANE `io_connect_t`. The buffer that
the kext reads is in `aned`'s memory.

---

## Annotation

This is an **architectural isolation** — the process boundary between the app and `aned`
prevents the app from controlling the data structures that the kext parses. This is not a
mitigation that was added in response to a bug; it is the intended design of the CoreML/ANE
pipeline. The XPC daemon architecture exists for resource management and scheduling, but it
also provides an implicit security boundary that blocks app-level exploitation of kext-level
bugs.

Five distinct delivery approaches were tested (direct IOKit, inference, MLUpdateTask, cache
patching, vm_region scan). All failed for the same fundamental reason: the mutable weights
buffer is in `aned`'s address space, and the app has no mechanism to inject data into it.
