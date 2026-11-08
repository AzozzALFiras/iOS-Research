# Handle Race kR/W Conversion Strategies — 4 Dead

**Build:** 24A446 (iPhone 17,2, A18 Pro)
**Evidence:** [`type-isolation-zones.md`](../evidence/type-isolation-zones.md)

---

## Background

The IOSurface Handle Race (CVE-2026-112477) is **working**:
- `set_surface_handle` at VA `0xfffffff00a352500` uses non-atomic `ldr`/`str` (PAC discriminator `0xf69b`)
- ~21% race rate confirmed from binary analysis
- ~217,000+ race wins achieved
- Spray-reclaim of the freed `kalloc_type<IOSurface>.1024` slot confirmed

**The race gives us a dangling IOSurface reference.** The question is: how to convert that
dangling reference into a kernel Read/Write primitive.

Four strategies were attempted. All dead.

---

## J1 — Strategy A: OSData fake-layout spray

**Idea:** After the Handle Race frees an IOSurface object (in `kalloc_type<IOSurface>.1024`),
spray OSData objects to reclaim the freed slot. The OSData would contain a fake IOSurface layout
with controlled field values, allowing kernel memory reads via IOSurface property queries.

**Why dead:** **Type isolation.** iOS 27.0.1 uses `kalloc_type` zones, which allocate each
C/C++ type in a dedicated zone. IOSurface objects live in `kalloc_type<IOSurface>.1024`, while
OSData objects live in `kalloc_data`. These are **completely separate zones** — an OSData
allocation will never reclaim an IOSurface slot.

```
kalloc_type<IOSurface>.1024    ← IOSurface objects go here
kalloc_data.1024               ← OSData, pipe buffers, mach_msg go here
                               ↑ different zone, different pages, no overlap
```

This also kills pipe-buffer spray, mach_msg spray, and any other `kalloc_data`-based reclaim
strategy. The only way to reclaim an IOSurface slot is with **another IOSurface object** (which
we do — but that doesn't give us a fake layout).

---

## J2 — Strategy B: Property kernel-pointer scan

**Idea:** Use IOSurface's property dictionary (`IOSurfaceCopyAllValues`,
`IOSurfaceGetPropertyValueForKey`, etc.) to extract kernel pointers leaked through property
serialization.

**Test:** Queried all accessible IOSurface properties after the Handle Race.

**Result:** IOSurface properties are serialized for userspace consumption. The kernel strips
internal fields (kernel pointers, internal flags) during serialization. The user-facing
properties contain surface dimensions, pixel format, plane info, and similar **user-provided
data** — never kernel addresses.

**Why dead:** The property serialization boundary is well-designed. Internal kernel state is
not exposed through the property interface.

---

## J3 — Strategy C: IOKit selector scan

**Idea:** Call IOSurface external methods (selectors 0–35) and `IOConnectMapMemory64` (types
0–4) on the dangling/reclaimed IOSurface connection to extract kernel pointers from return
values, output structures, or mapped memory.

**Test:** Systematically called all reachable selectors with various input parameters and
examined output buffers and mapped regions.

**Result:** Zero kernel pointers in any output. All outputs contain user-level data (surface
metadata, pixel buffer addresses, allocation sizes). Mapped memory regions (via
`IOConnectMapMemory64`) return userspace-mapped GPU/CPU buffer addresses, not kernel VAs.

**Why dead:** IOSurface's external method handlers are consistent about not exposing kernel
internal addresses to userspace. This is not a case of "most selectors are safe but one leaks"
— the entire interface is designed to return only userspace-relevant data.

---

## J4 — Strategy D: Notification UAF (selector 17)

**Idea:** Use `registerEventNotifier` (selector 17) on a **torn-down** IOSurface client. On
27.0.1, there is no check for the `torn-down` flag at `client+0xf1`. The event notification
delivery handler (`sub_fffffff00a352908`) dereferences `client+0xd8` — a UAF if the client
has been freed and its memory reclaimed with controlled data.

**27.2 fix:** `ldrb w8, [client, #0xf1]; tbz` rejects torn-down clients.

**Test:** 200 race attempts (close IOSurface connection + register event notifier
simultaneously).

**Result:** Zero successful hits. The timing window for the close-then-register race is
extremely narrow. The notification registration function acquires a lock that the close path
also holds, making the race window dependent on the exact interleaving of lock
acquire/release operations.

**Current status:** Not exhaustively eliminated. The bug is real (27.2 added a fix), and the
delivery path exists (handler at `sub_fffffff00a352908` dereferences `client+0xd8`, and the
async result is sent to our Mach port). 200 attempts may not be enough — more aggressive
racing (thread pinning, burst racing) might succeed. This is the **least dead** of the four
strategies.

---

## The deeper lesson

**Type isolation is the wall.**

Three of four strategies (A, B, C) fail because iOS 27.0.1's `kalloc_type` zone system prevents
cross-type heap object substitution. Even with a perfect dangling reference to a freed
IOSurface, the only thing that can reclaim the slot is another IOSurface — not a fake object
with controlled fields.

The successful jailbreaks on iOS 16+ (kfd, ClearSword, DarkSword) all achieve kR/W by working
**above** the zone allocator:
- **Physical page reuse** (PUAF — kfd)
- **VFS/UPL page manipulation** (DarkSword)
- **vm_map Copy-on-Write violations** (various)

These approaches operate at the virtual-memory or physical-page level, where type isolation does
not apply. Any future kR/W approach on 27.0.1 will likely need to follow this pattern.

---

## Related

- Evidence: [`type-isolation-zones.md`](../evidence/type-isolation-zones.md)
- Strategy D (Notification UAF) is the only approach not definitively eliminated — see
  the main [`README.md`](../README.md) for current status.
