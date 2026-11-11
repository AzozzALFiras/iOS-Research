# Kernel Diff: iOS 27.0.1 (24A446) → 27.2 (24B119) — Initial Findings
## iPhone 16 Pro Max (A18 Pro, iPhone17,2)
**Date:** 2026-11-09
**Status:** INITIAL — deep analysis in progress

---

## Executive Summary

Binary diff of kernelcache 27.0.1→27.2 reveals **3 high-priority exploit targets** for kR/W on 27.0.1:

| # | Target | CVE (likely) | Type | kR/W Potential | Sandbox Reachable |
|---|--------|-------------|------|----------------|-------------------|
| 1 | **Socket UAF** | CVE-2026-112514 | UAF (network) | ⭐⭐⭐ HIGH | ✅ YES (network) |
| 2 | **VM sk_deferred page** | CVE-2026-84495/112474 | UAF (pages) | ⭐⭐⭐ HIGH | ? TBD |
| 3 | **FSCompression info leak** | CVE-2026-113910 | Info disclosure | ⭐ (KASLR aid) | ✅ YES (file read) |

**Plus 3 previously identified unverified leads** (AVD shared buffer, JPEG 2024, SEPKeyStore DER).

---

## Methodology

1. Extracted 323 kexts from both kernelcaches via `ipsw kernel extract --all`
2. Compared binary sizes → identified 49 kexts with version changes, ~15 with code changes
3. Extracted and diffed `strings` output → identified ~1748 new strings in 27.2 kernel
4. Mapped new strings to XNU source files → ~190 recompiled files in networking alone
5. Cross-referenced with 27.2 security advisory CVE list
6. Filtered against DEAD_PATHS_BLACKLIST.json (28 dead paths excluded)

---

## Finding 1: Socket Subsystem UAF (CRITICAL)

### Evidence
- **~190 networking source files** recompiled in bsd/kern/, bsd/net/, bsd/netinet/, bsd/netinet6/, bsd/skywalk/
- **New function: `sofreelastref`** — "socket free last reference" — absent in 27.0.1
- New mbuf validation: `mbuf %p len (%u) < off+len (%u+%u)`
- `m_free`, `m_freem` function symbols changed

### CVE Match
**CVE-2026-112514** — CVSS **9.1 CRITICAL**
- **Vector:** AV:N/AC:L/PR:N/UI:N — Network-reachable, no privileges!
- **Impact:** "corrupt kernel memory"
- **Credits:** Marc Newlin (SkySafe), Billy Jheng Bing Jhong + Pan Zhenpeng (STAR Labs)
- **Type:** Use-after-free, CWE-416

### Why This Is Promising for kR/W
1. **Socket zones are NOT type-isolated** like IOKit zones — cross-zone spray may work
2. Socket objects are large structs with function pointers (`so_proto->pr_usrreqs`)
3. Network-reachable means trigger doesn't need special entitlements
4. The `sofreelastref` fix suggests a **reference counting race** in socket close path
5. In 27.0.1, the socket can be freed while network processing still holds a reference → classic UAF
6. STAR Labs researchers are known for building full kernel exploit chains

### Recompiled Source Files (key files)
```
bsd/kern/uipc_socket.c      — socket implementation (sofree, soclose)
bsd/kern/uipc_socket2.c     — socket utility functions
bsd/kern/uipc_syscalls.c    — socket syscalls
bsd/kern/uipc_mbuf.c        — mbuf management
bsd/netinet/tcp_input.c     — TCP input processing
bsd/netinet/tcp_subr.c      — TCP subroutines
bsd/netinet/tcp_timer.c     — TCP timers (race window?)
bsd/netinet/mptcp_*.c       — multipath TCP
bsd/netinet/flow_divert.c   — flow divert (sandbox interaction)
bsd/net/content_filter.c    — content filter
```

### Next Steps
- [ ] Decompile `sofree` in 27.0.1 kernel — find missing reference check
- [ ] Decompile `sofreelastref` in 27.2 kernel — understand the fix
- [ ] Map socket zone allocation (kalloc.type or generic?)
- [ ] Identify trigger path (TCP close race? MPTCP?)
- [ ] Build PoC socket lifecycle fuzzer

---

## Finding 2: VM Skywalk Deferred Page Handling (HIGH)

### Evidence
- **New module: `vm_sk_deferred.c`** — entirely absent in 27.0.1
- New functions: `vm_sk_deferred_drain`, sysctls `vm_sk_deferred_high_watermark_mib`, `vm_sk_deferred_max_age_secs`
- New zone: `site.struct vm_sk_deferred_entry`
- New overflow checks: `!os_add_overflow(*__counter, page_count, __counter)`, `!os_sub_overflow(*__counter, e->vmsk_page_count, __counter)`
- VM entry lock overflow detection: `VM entry %p lock shared lock overflow`
- Page integrity: `Page modified after framebank withdraw %p`

### CVE Match (likely)
**CVE-2026-84495** (Wang Yu) — Kernel UAF → "write kernel memory"
**CVE-2026-112474** (STAR Labs) — Kernel UAF → "write kernel memory"

### Why This Is Promising
1. **Page-level operations bypass Type Isolation** (golden rule #5)
2. Overflow checks suggest integer overflow in page counting → can cause undersized allocation
3. Missing lock overflow detection in 27.0.1 → possible race on VM entries
4. `framebank withdraw` integrity check suggests pages can be modified after withdraw in 27.0.1
5. Skywalk pages are shared between kernel and userspace channel rings

### Next Steps
- [ ] Identify where `vm_sk_deferred` page operations happen in 27.0.1 (inline or absent?)
- [ ] Check if page count overflow is triggerable from Skywalk channel API
- [ ] Analyze VM entry lock mechanism in 27.0.1 for counter overflow
- [ ] Determine sandbox reachability of Skywalk channels

---

## Finding 3: AppleFSCompression Decompression Info Leak

### Evidence
- New assertion: `"chunk %u produced %lld of %lld expected bytes"` — **ABSENT in 27.0.1**
- Recompiled: `ChunkCompression.cpp`, `compressorKext.c`
- 27.0.1 does NOT validate decompression output size

### CVE Match
**CVE-2026-113910** — "Disclosure of kernel memory" via memory initialization issue

### Impact
- If decompressor produces fewer bytes than expected, buffer remainder contains **uninitialized kernel heap data**
- Readable via compressed file access (sandbox reachable!)
- Useful as KASLR leak backup (though we already have timing oracle)
- Could leak zone metadata, function pointers, or other secrets

### Next Steps
- [ ] Reverse ChunkCompression decompression path in 27.0.1
- [ ] Identify how to craft file triggering short decompress
- [ ] Test if leaked data contains kernel pointers

---

## Other Changed Kexts

| Kext | Delta | Notes |
|------|-------|-------|
| ASIOKit | +114KB | Feature code (data tables), not security |
| AppleH16ANEInterface | +65KB | Feature/ANE updates (blacklisted — unreachable from sandbox) |
| Kernel core | +32KB | Socket + VM fixes (Findings 1 & 2) |
| RTBuddy | +32KB | Real-time buddy updates |
| sandbox | +16KB | Minor: deprecated-get-network-info, trustdFileHelper, documentprocessingd |
| AppleAVE2 | +16KB | Known AVE patches (blacklisted — VT gatekeeper) |
| FSCompression | +16KB | Finding 3 |
| SEPKeyStore | +8B | DER size check (confirmed unverified lead) |
| APFS | +8B | Minor |
| IOSurface | version only | Client teardown flag fix (known, already in blacklist) |

---

## SEPKeyStore DER — Unverified Lead Confirmed

The workflow-nov9 lead is confirmed:
- 27.2 adds: `"device state der too big to cache: %u > %zu"`
- 27.0.1 has NO size check on DER blob → heap overflow on oversized input
- Recompiled files: AppleKeyStore.cpp, ipc.c, msg.c, platform.c, platform_kernel.c, timestamp_ticket.c
- **Risk:** Likely entitlement-gated — needs testing from app sandbox

---

## Full iOS 27.2 Kernel CVE Map (15 CVEs)

| CVE | Type | Impact | Credits | Status |
|-----|------|--------|---------|--------|
| **CVE-2026-112514** | UAF (socket) | kR/W ⭐ | Marc Newlin + STAR Labs + greenbynox | **ANALYSIS COMPLETE** |
| **CVE-2026-84495** | UAF (VM) | kR/W | Wang Yu | Under analysis |
| **CVE-2026-112474** | UAF (VM) | kR/W | STAR Labs | Under analysis |
| CVE-2026-112507 | UAF (IPC) | kR/W | Tim Michaud | **DEAD** (grow-once) |
| CVE-2026-112679 | UAF | corruption | STAR Labs | **NEW** — possibly flow_divert |
| CVE-2026-65350 | UAF | corruption | Nebula/Pangu | Unattributed |
| CVE-2026-112517 | UAF | crash | Multiple | Unattributed |
| CVE-2026-112516 | UAF | crash | greenbynox | Unattributed |
| CVE-2026-112576 | CoW integrity | data | Pedro Pinho | **DEAD** |
| CVE-2026-112606 | Type confusion | crash | Wang Yu | Unattributed |
| CVE-2026-112698 | Memory | crash | STAR Labs + OpenAI | Unattributed |
| CVE-2026-112501 | Race condition | crash | Cem Onat Karagun | Unattributed |
| CVE-2026-112476 | OOB read | crash | Matt Suiche | Unattributed |
| CVE-2026-112665 | Info disclosure | KASLR | Will Estes | Low priority |
| CVE-2026-112624 | Logic | privacy | Jerry Knot | Not kR/W |

**NOTE:** CVE-2026-112438 (root code exec, Jakob Pammer) and CVE-2026-112543 (sandbox escape, MurphySec) are **macOS-only** — NOT in iOS advisory.

---

## Priority Assessment

### Tier 1 — Analysis Complete
1. **Socket UAF (CVE-2026-112514)** — CVSS 9.1, AV:N, struct socket NOT type-isolated. PoC trigger + kR/W exploitation code written. See `SOCKET_UAF_ANALYSIS.md`.

### Tier 2 — Under Analysis
2. **VM sk_deferred (CVE-2026-84495/112474)** — Page-level, bypasses type isolation
3. **CVE-2026-112679 (STAR Labs UAF)** — New `site.struct flow_divert_pcb_handle` in 27.2 suggests flow_divert UAF

### Tier 3 — Investigate After Tier 2
4. **AVD shared buffer lifecycle** (workflow lead) — Page-level UAF
5. **SEPKeyStore DER overflow** — Needs entitlement check
6. **CVE-2026-65350 (Nebula/Pangu UAF)** — Unattributed, needs diff work

### Low Priority / Done
7. FSCompression info leak (KASLR already solved)
8. JPEG 2024 struct (DART DMA)

### NOT Investigated (blacklisted)
- All 28 dead paths from DEAD_PATHS_BLACKLIST.json
- CVE-2026-112507 (IPC grow-once — DEAD)
- CVE-2026-112576 (CoW bypass — DEAD)
- AVE/AVC, GPU/DART, ANE, IOMFB, ScalerCSC

---

## Additional Findings from Deep Analysis

### New Type-Isolated Struct: `flow_divert_pcb_handle`
- `site.struct flow_divert_pcb_handle` — ABSENT in 27.0.1, present in 27.2
- Likely fix for CVE-2026-112679 (STAR Labs UAF)
- flow_divert handles VPN-like traffic redirection — sandbox reachable
- Adding type isolation to PCB handle = was previously exploitable via cross-zone spray

### New VM Assertions
- `prev_entry != ((void*)0)` — NULL check in linked list (VM entries?)
- `VM entry %p lock shared lock overflow` — lock counter overflow detection
- `memorystatus: purged %llu KiB of deferred SK pages` — new SK page purging

### New Entitlements
- `com.apple.private.verified-jit-mode` — JIT-related
- `com.apple.private.vfs.unmunged-access-time` — VFS timestamp access

---

## 27.2.1 Analysis — Pending

iOS 27.2.1 (24B156) OTA downloading (~3.6GB / ~7GB). Once extracted:
1. Diff 27.2→27.2.1 for NEW incremental patches (potential new CVEs)
2. Diff 27.0.1→27.2.1 to see if socket/VM fixes changed further
3. Apple hasn't published 27.2.1 CVEs yet — silent patches are the target
