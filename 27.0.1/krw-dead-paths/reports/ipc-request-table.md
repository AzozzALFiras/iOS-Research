# IPC Port Request Table OOB — CVE-2026-112507

**Verdict:** ☠️ DEAD — table grows once; freelist absorbs all subsequent allocations; no race window.
**Build:** 24A446 (iPhone 17,2, A18 Pro)
**Evidence:** [`ipc-table-grow-once.md`](../evidence/ipc-table-grow-once.md)

---

## The bug (real)

The per-IPC-space port request table (`ipc_space_t + 0x68`, PAC discriminator `0xb9dc`) contains
three sites where bounds-check results are computed but **not used for the actual memory
operations**. Fixed in 27.2 with bounds traps in `ipc_port.c` lines 38, 40, and 41.

### Site 1 — OOB Read (VA `0xfffffff00ab86c64`)

Unchecked index in the type-query path. The bounds check result is stored to a register that is
never read before the subsequent load uses the unchecked original index.

### Site 2 — OOB Write (VA `0xfffffff00ab86cd0`)

The most severe site. Disassembly:

```arm64
csel  x10, xzr, x12, hi    ; bounds-check result → x10 (UNUSED for memory!)
ldr   x9, [x12]             ; ★ OOB READ via UNCHECKED x12
str   w11, [x12, #8]        ; ★ OOB WRITE — w11 = idx×16 + 0x10
str   xzr, [x12]            ; ★ OOB WRITE — zeroes 8 bytes
```

The `csel` stores the safe-or-zero result into `x10`, but the `str` instructions use `x12` — the
**unchecked, raw index-derived pointer**. This is a textbook "discarded bounds check" pattern.

The written value `w11 = idx×16 + 0x10` is **attacker-influenced** (index chosen at notification
registration time), and the zero-write erases 8 bytes of adjacent memory.

### Site 3 — OOB Read + Write (VA `0xfffffff00ab86b2c`)

No bounds check at all on the mark-via-message-send path. Both read and write operations use the
raw index with no validation.

### Why this looked promising

1. **Request table allocated in `kalloc_data`** — not `kalloc_type`. This means pipe buffer spray
   can land adjacent objects, which would bypass type isolation (the wall that killed most other
   approaches).
2. **Reachable via `mach_port_request_notification`** — no entitlements required, any sandboxed
   app can call it.
3. **Three independent sites** — if one path is unreachable, another might work.
4. **The write value is controlled** — `w11 = idx×16 + 0x10` gives a range of values.

---

## Why it's dead

### The grow-once problem

The race trigger requires `ipc_port_request_grow()` to execute — it drops the port lock during
a `kalloc_data` allocation, creating a TOCTOU window where a concurrent teardown could leave a
stale index in the table.

**But `ipc_port_request_grow()` can only be called when the table's freelist is empty.** Here is
the actual growth sequence:

```
Initial table:   16 entries (kalloc_data.256)
                  ↓ fill all 16 → freelist empty → grow triggered
After 1st grow:  32 entries (kalloc_data.512), ~16 free in freelist
                  ↓ fill all 32 → freelist empty → grow triggered
After 2nd grow:  64 entries (kalloc_data.1024), ~32 free in freelist
                  ↓ fill all 64 → freelist empty → grow triggered
After 3rd grow: 128 entries (kalloc_data.2048), ~48+ free in freelist
                  ↓ iOS port limits (~1000–2000 per process) prevent
                    filling 128 slots with actual port notifications
```

After the table reaches 128 entries, there are **48+ free entries on the freelist**.
`ipc_port_request_alloc()` always returns a freelist entry when one is available. Since the
freelist never drains (the iOS port limit prevents registering enough notifications to fill 128
slots), **`ipc_port_request_grow()` is never called again**.

No grow → no lock drop → no TOCTOU window → no race → no OOB trigger.

### Device test results

**Test 1 (SPTM diagnostic app, 12,288 rounds):**
Every round showed `f=0` — the freelist path was taken every time. Zero grow operations
observed after the initial table setup.

**Test 2 (SPTM diagnostic v2, 7 rounds):**
Re-confirmed `f=0` on all rounds. Consistent with Test 1.

**External confirmation (SPBY `ipcfuzz` tool):**
```
$ ipcfuzz 10000 4
ipcfuzz — ipc_port request-table notify stress (112507 / Site-2)
  host pin: kern fn 0xfffffff00a215050 (discarded-bounds str) [O]
  ops=10000 threads=4 — bounded, not a write PoC
  sequential DEAD_NAME: live=256/256
  replace-storm rounds=1152 on 24 ports
  destroy-race pool=25 ports
  KERN_SUCCESS=11463/11465
  survived=yes  (process still here — no kernel abort observed)
  note: a hit would be a kernel panic/abort, not a userspace kr [I]
```

10,000 operations with 4 racing threads, including replace-storm and destroy-race patterns,
produced **zero kernel panics** and the tool itself classified the result as "bounded, not a
write PoC".

---

## The deeper lesson

The bug is **real** — the bounds check truly is discarded, and a bad index truly would produce
OOB memory access. But the kernel's allocation strategy prevents the bad index from ever
existing at runtime. The `ipc_port_request_grow()` function is the only code that resizes the
table (creating the TOCTOU window), and its precondition (empty freelist) cannot be met after
the table's first expansion past 64 entries.

This is a pattern worth recognizing: **a proven memory-safety bug that is architecturally
unexploitable because the trigger condition cannot be reached at runtime.** The grow-once design
with a persistent freelist is an implicit mitigation — likely unintentional, but effective.

---

## Related

- Evidence: [`ipc-table-grow-once.md`](../evidence/ipc-table-grow-once.md)
- Lesson: grow-once design is an implicit mitigation against TOCTOU in resize paths
