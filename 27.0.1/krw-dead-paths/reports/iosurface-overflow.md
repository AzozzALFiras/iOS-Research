# IOSurface Overflow Paths — 2 Dead

**Build:** 24A446 (iPhone 17,2, A18 Pro)

---

## C1 — compressionType=3 (F4 overflow)

**Idea:** Setting `IOSurfaceCompressionType=3` triggers a different code path in the kernel's
IOSurface allocation that uses a 32-bit multiplication susceptible to integer overflow. If the
overflow produces a smaller allocation than expected, subsequent writes to the surface would
corrupt adjacent heap objects.

**Test:** 10 configurations (T1–T10) with varying BPS (bytes per sample), slice offsets, and
tile dimensions.

**Result:** Every configuration returned `e00002c2` (`kIOReturnBadArgument`). The kernel
rejects all `compressionType=3` variants on this hardware.

**Why dead:** Additional validation exists beyond what is visible in the decompiled code. The
kernel checks the compression type against the hardware's supported types, and type 3 is not
supported on A18 Pro. This is a hardcoded rejection, not a runtime check that might be
bypassable with different parameters.

---

## C2 — sliceCount tile OOB

**Idea:** Setting a high `sliceCount` value in IOSurface creation could cause tile-based
overflow in the internal buffer size calculation, leading to undersized allocation and OOB
writes when tiles are written.

**Result:** The kernel internally clamps `sliceCount` to 1 regardless of the userspace-requested
value. The multi-slice allocation arithmetic never executes.

**Why dead:** The kernel normalizes the `sliceCount` parameter before using it in any size
calculation. The parameter is accepted without error (no `kIOReturnBadArgument`), but the
internal value is always 1. Requesting `sliceCount=256` is identical to `sliceCount=1` from
the kernel's perspective.

---

## The lesson

IOSurface's kernel implementation validates and normalizes creation parameters aggressively.
Compression-type and slice-count attacks are blocked at the parameter-validation stage, before
any allocation or size calculation occurs. The attack surface for IOSurface overflow is narrower
than the decompiled code suggests — many code paths are unreachable due to parameter checks
that are not visible in the main allocation function.
