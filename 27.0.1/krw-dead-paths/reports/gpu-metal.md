# GPU / Metal Paths — 4 Dead

**Build:** 24A446 (iPhone 17,2, A18 Pro)
**Evidence:** [`gpu-uat-isolation.md`](../evidence/gpu-uat-isolation.md)

---

## Overview

Four attempts to use GPU capabilities (specifically the F1OOB cross-object OOB write, which is
100% reliable) to achieve kernel memory access. All dead due to hardware-level address
translation isolation.

### Background: what we have

The **F1OOB** primitive gives us reliable GPU-side OOB writes between Metal buffer objects. We
can write from one GPU buffer into an adjacent one with 100% reliability
(`delta=0x18000`, AGX VA mismatch). A bridge spray confirms GPU→CPU→IOSurface data transfer
works (16/16 successful). **The GPU-side primitive is solid.**

The question was: can we point this GPU write at **kernel memory**?

---

## B1 — F1OOB GPU → kernel direct

**Idea:** Use the GPU OOB write to reach beyond the GPU's allocated buffers and write into
kernel memory regions.

**Why dead:** Metal's hardware buffer bindings include bounds checking. OOB reads return 0, OOB
writes silently discard. While the F1OOB technique bypasses this for cross-buffer writes (by
exploiting AGX VA translation gaps), the **DART (Device Address Resolution Table)** prevents any
GPU virtual address from mapping to kernel physical address space.

GPU buffers are mapped into the GPU's address space through DART, which maintains a strict
mapping that includes only the buffers the GPU is supposed to access. Kernel memory is simply
not in the GPU's DART mapping.

---

## B2 — GPU→Kernel R/W via UAT (DEFINITIVE)

**Idea:** Use the Unified Address Translator (UAT) — the GPU's page table mechanism on Apple
Silicon — to translate GPU virtual addresses into kernel physical addresses, bypassing DART.

**Tested with:** SKVLENT F1OOB application, which confirmed that cross-buffer GPU writes work
in userland (the GPU can write between its own buffers).

**Result:** **UAT completely blocks access to kernel memory from the GPU.** The GPU's virtual
address space is fully isolated from the kernel's physical address space. UAT translations are
set up by the kernel and include only user-allocated GPU buffers. There is no GPU VA that
resolves to a kernel PA.

This is a **definitive** result. It is not a software mitigation that might be bypassed — it is
a hardware-enforced address space boundary. The GPU physically cannot address kernel memory
through its normal translation path.

**This kills ALL GPU→kernel R/W paths**, regardless of the GPU-side primitive used.

---

## B3 — GPU PTE corruption

**Idea:** Use the GPU OOB write to corrupt DART page table entries (PTEs), remapping a GPU
buffer to point at kernel physical memory.

**Why dead:** DART page tables reside in **kernel memory**, not in GPU-accessible memory.
Writing to a pixel buffer (which is what the GPU can access) does not modify DART entries.
The GPU can only modify data within its own DART-mapped regions, and those regions do not
include the DART page tables themselves.

This is dead by transitivity from B2 — if the GPU cannot access kernel memory, it cannot access
the DART page tables that live in kernel memory.

---

## B4 — Metal buffer-extension OOB (A18 Pro specific)

**Idea:** Exploit A18 Pro-specific Metal buffer allocation behavior where buffer extensions
might create an OOB write opportunity past DART boundaries.

**Test:** 5 retry attempts with various buffer sizes and extension patterns.

**Result:** DART silently discards OOB writes. An initial "hit" was an unreproducible fluke
attributed to physical layout coincidence. All subsequent attempts: MISS.

---

## The lesson

**UAT provides complete, hardware-enforced isolation between GPU and kernel address spaces.**

The GPU cannot access kernel memory regardless of the GPU-side primitive's power. F1OOB gives us
a reliable GPU write — but it is confined to the GPU's own buffer space. The GPU→CPU→IOSurface
bridge works for **data transfer** between GPU buffers and CPU-accessible IOSurface pixel
buffers, but neither of these is kernel memory.

The only way to use GPU capabilities for kernel exploitation would be to first gain a separate
kernel vulnerability that maps kernel memory into the GPU's DART tables — at which point the GPU
primitive is redundant (you already have kernel access).

---

## Related

- Evidence: [`gpu-uat-isolation.md`](../evidence/gpu-uat-isolation.md)
- The F1OOB primitive and bridge spray remain useful **post-kR/W** for data movement, but cannot
  provide the kR/W itself.
