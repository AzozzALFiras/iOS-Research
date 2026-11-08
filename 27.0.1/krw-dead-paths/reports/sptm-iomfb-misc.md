# SPTM / IOMFB / External — 5 Dead

**Build:** 24A446 (iPhone 17,2, A18 Pro)

---

## H1–H3 — SPTM attack paths (3 dead)

### H1 — SPTM CAS (Compare-And-Swap) race

**Idea:** Race the SPTM's CAS-based state transitions in the Frame Table to create an
inconsistent page-type state, potentially allowing a page retype that SPTM would normally
reject.

**Why dead:** SPTM operates at EL2 (the Secure Page Table Monitor runs in a higher privilege
level than the kernel at EL1). The CAS operations and their surrounding DSB/ISB barriers are
**only reachable from EL2 code**. An attacker at EL1 (kernel level) or below cannot race SPTM's
internal state transitions — they can only invoke SPTM through its defined hypercall interface,
which serializes all access.

Exploiting this would require existing code execution at EL2 or EL3, which is **harder** than
the kernel compromise we are trying to achieve.

### H2 — SAPT (Secure Address Page Table) bypass

**Idea:** Bypass SPTM's SAPT validation to create page table entries that map kernel-writable
pages as executable, bypassing W^X enforcement.

**Why dead:** Same as H1 — SAPT manipulation requires EL2 access. The SAPT is managed entirely
within SPTM's address space and is not accessible from EL1.

### H3 — GMMU TLBI (GPU MMU TLB Invalidation) skip

**Idea:** Exploit a gap in GPU TLB invalidation during page retype operations. If the GPU's TLB
retains a stale translation to a page that SPTM has retyped, DMA through the stale translation
could read/write memory that should no longer be accessible to the GPU.

**Why dead:** While this is a real defense-in-depth gap (the `verify-gmmu-tlbis-at-sync`
DeviceTree key is **absent** on d94ap across all three tested builds — 27.0.1, 27.2, 27.3β),
**triggering it requires kernel-level code execution** to initiate page retype operations and
manipulate the GPU MMU state. This is circular: we need kernel access to exploit it, but we're
trying to gain kernel access.

Additionally, this has **public prior art** — it is not a novel finding.

---

## I1 — IOMobileFrameBuffer race (CVE-2026-112459)

**Idea:** Exploit a race condition in `IOMobileFrameBuffer` to achieve a use-after-free or
type confusion in the kernel's framebuffer management code.

**Why dead:** **IOMobileFrameBuffer does not exist as a kernel extension on A18 Pro devices.**

On A18 Pro (iPhone 17,2), the framebuffer is managed by the **DCP (Display Co-Processor)** — a
separate processor with its own firmware. The display stack on modern Apple Silicon iPhones
uses `IOMobileGraphicsFamily-DCP` and `AppleDCP` kexts, which are thin shims that communicate
with the DCP processor over a mailbox interface.

Shape-diff analysis of the 4 adjacent kexts between 27.0.1 and 27.2:
- **IOMobileGraphicsFamily:** 1154/1156 functions identical. NO locking changes.
- **IOMobileGraphicsFamily-DCP:** version-pinned, byte drift only.
- **AppleMobileDispH17P-DCP:** version-pinned.
- **AppleDCP:** version-pinned.

The CVE-2026-112459 fix is in **DCP firmware**, which is not part of the kernelcache and cannot
be analyzed through kernel binary diffing. This was confirmed by the duper-cves analysis with a
receipt: **"scope-NULL, receipt-backed"** — the fix cannot be located in any kernel artifact.

---

## K1 — AGX-RW-iOS-PoC (external reference)

**Idea:** Adapt the `AGX-RW-iOS-PoC` by `0xjohnnydev` for iOS 27.0.1 to achieve kernel R/W
through GPU firmware manipulation.

**Why dead (not applicable to our situation):**

1. **Targets iOS 18.6.2** (build 22G100), not iOS 27.0.1. All offsets are hardcoded per-build.
2. **Depends on ClearSword KRW** (CVE-2025-43520, also called DarkSword) — an existing kernel
   read/write primitive that we do not have. The AGX technique is a **post-exploitation**
   capability, not an initial kR/W vector.
3. **Contains no KASLR bypass** — assumes the kernel base is already known.
4. **GFX firmware R/W** is useful for post-exploitation (DropMDSID, PAC reuse) but cannot
   provide the initial kernel access we need.

---

## The lesson

- SPTM paths (H1–H3) are **circular dependencies** — they require the kernel access we are
  trying to achieve.
- IOMFB (I1) is a **scope error** — the target code does not exist in the kernel on this
  hardware.
- External PoCs (K1) are **post-exploitation tools** that assume existing kR/W.

None of these categories can provide a first-stage kR/W primitive from an unprivileged app
sandbox.
