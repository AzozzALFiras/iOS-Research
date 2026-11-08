# Evidence: UAT prevents GPU access to kernel memory

**Build:** 24A446 (iPhone 17,2, A18 Pro, `d94ap`)
**Claim:** The Unified Address Translator (UAT) on Apple Silicon completely isolates the GPU's
virtual address space from the kernel's physical address space. No GPU-side primitive can
directly read or write kernel memory.

---

## Reproduction

### SKVLENT F1OOB application test

**Method:** The SKVLENT F1OOB app exploits an AGX VA (virtual address) mismatch between Metal
buffer bindings to achieve **cross-buffer GPU writes** — writing from one GPU buffer into an
adjacent one. The app was used to test whether GPU writes could reach beyond GPU-allocated
buffers into kernel memory regions.

**Result:**
- Cross-buffer GPU writes within userland: **WORK** (delta=0x18000, 100% reliable)
- GPU writes to kernel address space: **BLOCKED by UAT**
- GPU VA space cannot resolve to kernel PA (physical address)

### Bridge spray verification

A separate test confirmed that GPU→CPU→IOSurface data transfer works:

```
Bridge spray: 16/16 GPU→CPU→IOSurface transfers successful
```

The GPU can write data to CPU-visible buffers (IOSurface pixel buffers). But these are
**userspace-mapped** hardware buffers — not kernel memory.

### Why UAT blocks kernel access

The GPU's page tables are managed by DART (Device Address Resolution Table), which maintains
GPU VA → PA mappings. These mappings are created by the kernel when GPU buffers are allocated.
The kernel **only maps user-allocated GPU buffers** into the GPU's address space — kernel
memory is never included in these mappings.

```
GPU VA space (managed by UAT/DART):
  0x000000000 – 0x...  : user GPU buffer A  → PA 0x10afec000
  0x...       – 0x...  : user GPU buffer B  → PA 0x10b000000
  (no mapping)                               → kernel PA range
```

There is no GPU VA that translates to a kernel physical address, because the kernel never
creates such a mapping. The GPU physically cannot issue a memory transaction to kernel memory.

### Why GPU PTE corruption fails

DART page table entries themselves reside in **kernel memory**. Since GPU writes cannot reach
kernel memory (proven above), GPU writes cannot modify DART PTEs. The GPU cannot change its own
page tables.

This makes the isolation self-reinforcing: the GPU can only access addresses in its DART
mappings, and it cannot modify those mappings.

---

## Physical address observation

AGX selector 8 (at `+0x10` in the output structure) returns a physical address
(`PA=0x10afec180`) for GPU buffer allocations. This confirms that the GPU operates on physical
addresses translated through DART, and that the returned PAs are in the device memory range,
not in the kernel's virtual address range.

---

## Annotation

UAT/DART isolation is a **hardware-enforced** boundary. It is not a software mitigation that
might be bypassed by clever programming — it is a property of the memory management unit. The
GPU's load/store units issue addresses that are translated by DART hardware before reaching the
memory bus. If DART does not contain a mapping for the target address, the transaction is
silently dropped (OOB writes) or returns zero (OOB reads).

The only way to break this isolation would be to:
1. Modify DART page table entries to include kernel memory mappings — but DART PTEs are in
   kernel memory, which is inaccessible (circular)
2. Use a DMA engine that bypasses DART — no known mechanism on A18 Pro
3. Exploit a bug in the DART hardware itself — outside the scope of software research

For practical purposes, GPU-side capabilities (F1OOB, shader exploits, buffer overflows) are
**confined to the GPU's own buffer space** and can be used for data movement between GPU and
CPU buffers, but never for direct kernel memory access.
