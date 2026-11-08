# Evidence: `kalloc_type<IOSurface>` is isolated from `kalloc_data`

**Build:** 24A446 (iPhone 17,2, A18 Pro, `d94ap`)
**Claim:** `kalloc_type<IOSurface>.1024` and `kalloc_data.1024` are completely separate zones.
A freed IOSurface slot cannot be reclaimed by an OSData, pipe buffer, or mach_msg allocation.

---

## Reproduction

### Handle Race spray-reclaim test

**Method:** The Handle Race (CVE-2026-112477) frees an IOSurface object in
`kalloc_type<IOSurface>.1024`. After the free, spray objects from `kalloc_data` to attempt
reclamation of the freed slot:

1. **OSData spray:** 512 OSData objects of size 1024 bytes
2. **Pipe buffer spray:** 256 pipe pairs with 1024-byte buffers
3. **mach_msg OOL spray:** 128 mach_msg out-of-line descriptors of 1024 bytes

After each spray, examine the reclaimed IOSurface slot for signs of controlled data.

**Result:** The freed IOSurface slot was **never reclaimed** by any `kalloc_data` spray. The
slot was only reclaimable by creating another IOSurface object (same `kalloc_type`).

### Zone identity verification

**Method:** Confirmed zone identities via `zone_id_require` reverse engineering:

```
IOSurface:    zone_id = 0x1a, zone = kalloc_type<IOSurface>.1024
              element_size = 0xe38 (struct padded to 1024-byte zone bucket)
              zone_require check at proc+0x768 (task accessor)

OSData:       zone = kalloc_data (generic data zone)
pipe buffer:  zone = kalloc_data
mach_msg OOL: zone = kalloc_data
ipc_port:     zone = kalloc_type<ipc_port>.256 (separate type zone)
```

### Zone sequestering

iOS 27.0.1 includes **zone sequestering**: when a `kalloc_type` zone's pages are freed (via
zone GC), they are **not returned to the general page pool**. Instead, they are held in a
per-zone sequester list. This prevents the "zone GC → page reuse" technique that earlier iOS
versions were vulnerable to.

```
Without sequestering (pre-iOS 16):
  Free type-zone page → general page pool → realloc as data-zone page → cross-zone overlap

With sequestering (iOS 27.0.1):
  Free type-zone page → sequester list (same zone) → realloc ONLY in same zone → no cross-zone
```

---

## Annotation

Type isolation is the fundamental reason why most heap-level kR/W techniques fail on iOS
27.0.1. The zone system enforces a strict invariant: **the type of the allocation that created
a slot is the only type that can reclaim that slot.** This is enforced at two levels:

1. **Allocation-time:** `kalloc_type<T>` routes to a dedicated per-type zone.
2. **Page-level:** Zone sequestering prevents freed pages from being reused by different zones.

Any exploitation technique that relies on "free object A (type X), spray object B (type Y) into
the same slot" will fail. This includes:

- Fake-object spray (OSData with controlled layout replacing a freed kernel object)
- Pipe-buffer overwrite (pipe data replacing a freed IOSurface)
- mach_msg replacement (OOL data replacing a freed ipc_port)
- Cross-zone heap feng shui (arranging objects of different types adjacently)

The workaround used by successful jailbreaks (kfd, ClearSword, DarkSword) is to operate at the
**physical page** or **VM subsystem** level, where type isolation does not apply — pages and
physical memory do not have a "type" in the `kalloc_type` sense.
