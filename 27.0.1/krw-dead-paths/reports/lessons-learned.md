# Lessons learned — 7 rules from 27 dead paths

**Build:** 24A446 (iPhone 17,2, A18 Pro)

These lessons were extracted from testing 27 separate approaches to kR/W on iOS 27.0.1. Each
one cost days of reverse engineering and on-device testing. They are documented here so other
researchers can skip directly to approaches that have a chance of working.

---

## ① `IOSurfaceGetBaseAddress()` ≠ kernel memory

`IOSurfaceGetBaseAddress()` returns a pointer to the **userspace-mapped pixel buffer**. This is
CPU-accessible memory containing image sample data (BGRA pixels, NV12 planes, etc.). It is not
kernel heap memory. Kernel pointers will never appear there.

The misconception is easy to arrive at: "an IOSurface is a kernel object, so its base address
might be a kernel address." In reality, `IOSurfaceGetBaseAddress()` returns the result of an
`IOConnectMapMemory64` mapping — the kernel maps the hardware buffer into the calling process's
address space. What you get is a userspace VA pointing at pixel data.

**Rule:** Any approach based on scanning pixel buffers for kernel pointers is a conceptual error,
not a missing leak.

---

## ② Type isolation cannot be broken from inside the allocator

iOS 27.0.1 uses `kalloc_type` zones, which allocate each C/C++ struct type in a **dedicated,
per-type zone**. The relevant zones for our research:

```
kalloc_type<IOSurface>.1024     ← IOSurface objects
kalloc_data.1024                ← OSData, pipe buffers, mach_msg_ool_descriptor
kalloc_type<ipc_port>.256       ← Mach port structures
```

These zones occupy different physical pages. A freed slot in `kalloc_type<IOSurface>.1024` can
**only** be reclaimed by another `IOSurface` allocation — never by an OSData, pipe buffer, or
mach_msg. Zone GC does not help because Apple added **zone sequestering** (freed type-zone
pages are not returned to the general page pool).

This kills every exploitation technique that depends on cross-type heap object substitution:
fake-object spray, pipe-buffer overwrite, mach_msg replacement, OSData layout control, etc.

**Rule:** If your kR/W approach requires "spray X to reclaim freed Y where X and Y are different
types," it will not work on iOS 27.0.1.

---

## ③ GPU virtual addresses ≠ kernel virtual addresses

The GPU's address space is **completely isolated** from the kernel's address space by the UAT
(Unified Address Translator) and DART (Device Address Resolution Table). Confirmed on-device
with the SKVLENT F1OOB application: cross-buffer GPU writes work within userland, but GPU
virtual addresses cannot reach kernel physical addresses.

This is **hardware-enforced**, not a software mitigation. The GPU physically cannot issue a
memory transaction to a kernel address — the translation hardware does not contain mappings for
kernel memory. GPU page tables (DART entries) reside in kernel memory, so they cannot be
modified from the GPU either (circular: you need kernel access to modify the tables that would
give you kernel access).

**Rule:** No GPU-side primitive (OOB write, buffer overflow, shader exploit) can directly access
kernel memory. GPU capabilities are useful only for data movement between GPU buffers and
CPU-mapped regions (IOSurface pixel buffers), not for kernel exploitation.

---

## ④ VideoToolbox userspace is the gatekeeper for all video encode/decode kernel paths

Every parameter that reaches the AppleAVE2 kernel driver first passes through VideoToolbox's
**userspace validation layer**. VT checks value ranges, clamps parameters (e.g.
`NumberOfTemporalLayers` is always clamped to 1), and rejects malformed inputs (e.g.
`log2_max_frame_num > 16` returns `-12911`).

The 27.2 kernel bounds checks visible in patch-diffs (the ones described in CVE advisories) are
**defense-in-depth**. On 27.0.1, VT already prevents the malicious values from reaching the
kernel. The kernel checks are real hardening, but they are the second line of defense, not the
first.

**Rule:** To exploit an AVE/AVC kernel bug from userspace, you first need a **VT bypass** — a
separate vulnerability in VideoToolbox's parsing that lets a malformed value pass through to the
kernel. Without that, kernel-side bugs in video processing are unreachable.

---

## ⑤ `aned` is the only gateway to the ANE kext

The Apple Neural Engine kext (`AppleH16ANEInterface`) is mediated by the `aned` XPC daemon. Apps
cannot open a direct IOKit connection to the ANE — `IOServiceOpen` returns
`kIOReturnNotPermitted`.

The critical implication: **mutable weights buffers are created in `aned`'s address space**, not
the app's. When `aned` calls IOKit selector 8 (`MapMutableWeights`), it maps a buffer from its
own memory to the kext. The app never sees this buffer.

This was verified exhaustively:
1. IOKit hooks (fishhook) captured 0 ANE-related IOKit calls in the app process
2. `MLUpdateTask` trains on CPU (~14ms), zero IOKit calls
3. vm_region scan found 0 buffers matching the expected `ane_mutable_weights_header_t` format
4. No ANE cache files exist in the app sandbox
5. Direct IOKit: `kIOReturnNotPermitted`

**Rule:** ANE kext bugs (even powerful ones like CVE-2026-84494's unchecked symbolIndex OOB) are
architecturally unreachable from app sandbox. Exploiting them requires either code execution in
`aned` or a way to inject data into `aned`'s IOKit mappings — both of which require separate
vulnerabilities.

---

## ⑥ IPC request table: the grow-once design

The per-space port request table in Mach IPC (`ipc_space_t + 0x68`) has a grow-once property:
after the table expands past 64 entries (to 128 entries in `kalloc_data.2048`), the freelist
contains 48+ unused entries. Since `ipc_port_request_alloc()` always returns a freelist entry
when one is available, `ipc_port_request_grow()` is **never called again**.

The race trigger for CVE-2026-112507 requires `ipc_port_request_grow()` to execute (it drops the
port lock during allocation, creating a TOCTOU window). Since grow is never called after the
initial expansion, there is **no race window** — the OOB condition cannot be reached at runtime.

Confirmed by: 12,288 rounds (all `f=0`), 7-round retest (all `f=0`), external SPBY ipcfuzz
(10,000 ops × 4 threads, 0 panics).

**Rule:** A resize-race bug is only exploitable if the resize can be triggered repeatedly.
Grow-once allocation strategies (tables with persistent freelists) are an implicit mitigation
against TOCTOU in resize paths. Always check whether the trigger (grow/resize/realloc) can
actually recur.

---

## ⑦ Successful jailbreaks work at the physical / VM level

Every recent iOS jailbreak (16+) that achieves kR/W does so by operating **above** the zone
allocator, at the virtual-memory or physical-page level:

| Jailbreak | Technique | Level |
|-----------|-----------|-------|
| **kfd** (PUAF) | Physical page use-after-free via `vm_map` manipulation | Physical pages |
| **ClearSword** | VFS/UPL OOB → socket spray → `icmp6_filter` → kR/W | VFS / UPL |
| **DarkSword** | Copy-on-Write bypass → physical page manipulation | VM / CoW |
| **WeightBufs** | DMA buffer confusion → physical memory access | DMA / physical |

None of these operate at the `kalloc` zone level. They bypass type isolation entirely by
working at a layer where "what type was this allocation?" is not a relevant question — pages
and physical memory have no type.

**Rule:** If you are stuck on kR/W and type isolation is the wall, you are operating at the
wrong abstraction level. Look at VM subsystem bugs (CoW violations, UPL/VFS OOB, `vm_map`
manipulation, physical page lifecycle) instead of heap-level corruption.

---

## Summary

The consistent theme across all 27 dead paths: **iOS 27.0.1's defense-in-depth works.** Each
layer (VT userspace validation, type isolation, UAT/DART hardware isolation, XPC daemon
mediation, SPTM privilege separation) independently blocks a class of attacks. Even when a
kernel bug is real and powerful, reaching it from an unprivileged app requires crossing multiple
boundaries — and each boundary eliminates a category of approaches.

The path forward is not to find a bug that bypasses all layers simultaneously. It is to find a
bug that operates at a level **where the layers don't apply** — physical memory, VM subsystem,
or a daemon with direct kernel access.
