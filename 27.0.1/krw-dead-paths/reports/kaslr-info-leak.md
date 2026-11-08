# KASLR Info Leak Paths — 7 Dead (but KASLR is solved)

**Build:** 24A446 (iPhone 17,2, A18 Pro)

---

## Important context

**KASLR is not the blocker.** KASLR was defeated via a timing oracle (z-score 7.67, reliable
on first attempt). These 7 paths are documented for completeness, but the current chain
architecture does not depend on any of them.

The timing oracle works by measuring variance in Mach IPC round-trip times across 64 probes
targeting different candidate kernel slide values. The correct slide produces a statistically
significant timing signature (z > 4.0 threshold, observed z = 7.67).

---

## A1 — `mach_port_kobject`

**Idea:** Use `mach_port_kobject()` to extract kernel object addresses from Mach port
descriptors.

**Result:** Apple zeroes the `kaddr` return value on 27.0.1 for **all** port types:
- Host port (type 3): `kr=0x0`, `addr=0x0`
- Task port (type 2): `kr=0x0`, `addr=0x0`
- Clock port (type 25): `kr=0x0`, `addr=0x0`
- 241 ports enumerated via port-space walk — all `addr=0x0`

**Why dead:** Kernel-side change zeroes the returned address field. This was a well-known KASLR
leak vector patched in earlier iOS versions; 27.0.1 includes the fix.

---

## A2 — `task_info(TASK_DYLD_INFO)`

**Idea:** Query `task_info` with `TASK_DYLD_INFO` flavor to extract the `dyld_all_image_infos`
structure, which historically contained kernel pointers.

**Result:** Returns userspace address `0x1f8e26670` with `size=0x170`. This is the dyld info
structure in the **task's own address space**, not a kernel pointer.

**Why dead:** The returned address is a userspace VA, not a kernel VA. No kernel pointer is
exposed through this interface on 27.0.1.

---

## A3 — IORegistry property scan

**Idea:** Enumerate IORegistry services (`IOPlatformExpertDevice`, `AppleARMPE`,
`IOSurfaceRoot`, `AGXAccelerator`, etc.) and scan their property dictionaries for leaked kernel
pointers (addresses in the `0xfffffff0xxxxxxxx` range).

**Result:** 0 kernel pointers found in any property dictionary across all enumerated services.

**Why dead:** IORegistry property serialization strips kernel-internal values before exposing
properties to userspace. All returned values are user-level configuration data.

---

## A4 — Mach port space scan

**Idea:** Walk the entire Mach port space using `mach_port_space_info` and related APIs,
examining port names, types, and associated metadata for leaked kernel addresses.

**Result:** 241 Mach ports enumerated. None contained kernel addresses in any accessible field.

**Why dead:** Port metadata exposed to userspace has been sanitized. Port names are indices into
a port namespace, not kernel pointers.

---

## A5 — IOSurface `CopyAllValues`

**Idea:** Create IOSurface objects and use `IOSurfaceCopyAllValues()` to dump all associated
properties, hoping internal kernel pointers (buffer addresses, allocation metadata) would be
included.

**Result:** Returns user-facing properties only: dimensions, pixel format, plane info, cache
mode, etc. No internal kernel fields.

**Why dead:** The serialization boundary between kernel IOSurface state and user-visible
properties is well-enforced. Internal addresses are stripped during property export.

---

## A6 — decmpfs compressed-file scanning

**Idea:** Access compressed files via the `decmpfs` (decmpfs compression) subsystem and examine
the decompression metadata for kernel pointer leaks. Some iOS versions leaked kernel addresses
through the compression metadata structures.

**Test:** 23 compressed files examined.

**Result:** 0 kernel pointer leaks. Decompression metadata contains only file-content-related
information (compressed size, algorithm, offsets).

**Why dead:** The `decmpfs` metadata exposure was patched in earlier iOS versions. 27.0.1 does
not leak kernel addresses through this path.

---

## A7 — IOSurface pixel buffer scanning (CONCEPTUAL ERROR)

**Idea:** Call `IOSurfaceGetBaseAddress()` on an IOSurface and scan the returned buffer for
kernel pointers that might have been copied into the pixel data during encode or DMA
operations.

**Result:** The returned buffer contains pixel data (BGRA/NV12 sample values) — no kernel
pointers.

**Why dead:** This was a **conceptual error**, not a patched leak. `IOSurfaceGetBaseAddress()`
returns a pointer to the **userspace-mapped pixel buffer** — CPU-accessible memory containing
image data. Kernel pointers will **never** appear there because:

1. The buffer is mapped into userspace via `IOConnectMapMemory64` — it is a shared mapping of a
   hardware buffer, not kernel heap memory.
2. DMA operations write pixel data into this buffer, not kernel metadata.
3. Even if the kernel internally uses pointers near this buffer, those pointers are in kernel
   address space and are not DMA'd into the pixel data region.

This is worth documenting because the misconception — "GPU/encode hardware might DMA kernel
pointers into a pixel buffer" — is easy to arrive at and completely wrong.

---

## Related

- KASLR is solved via timing oracle — see the chain architecture in the main
  [`README.md`](../README.md)
- The kernel slide for 24A446 was determined on first attempt with z=7.67 (well above the 4.0
  threshold)
