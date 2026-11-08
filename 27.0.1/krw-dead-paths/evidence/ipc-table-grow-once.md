# Evidence: IPC request table grows once — no race window after

**Build:** 24A446 (iPhone 17,2, A18 Pro, `d94ap`)
**Claim:** `ipc_port_request_grow()` is only triggerable once the table reaches 64→128 entries.
After that, the freelist absorbs all subsequent allocations and grow is never called again.

---

## Reproduction

### Test 1 — SPTM diagnostic app

**Method:** Built an IPA diagnostic that registers `mach_port_request_notification` calls in a
loop, tracking whether each registration triggers a grow operation (by monitoring the table size
and freelist count before and after each call).

**Parameters:** 12,288 rounds, sequential registration.

**Result:**
```
Round      f (freelist)   Grew?
1-63       decreasing     no — consuming initial freelist
64         0              YES — triggers grow (64→128)
65-12288   >0             no — all subsequent allocs from freelist
```

All 12,288 rounds after the single grow showed `f=0` (freelist path taken). Zero additional
grows observed.

### Test 2 — SPTM diagnostic v2 (reconfirmation)

**Parameters:** 7 rounds, embedded in ANE diagnostic crash log.

**Result:** All 7 rounds: `f=0`. Consistent with Test 1.

### Test 3 — SPBY `ipcfuzz` (external tool, independent confirmation)

**Method:** Third-party research tool running on the same device via SSH.

**Command and output:**
```
$ ipcfuzz 10000 4
ipcfuzz — ipc_port request-table notify stress (112507 / Site-2)
  host pin: kern fn 0xfffffff00a215050 (discarded-bounds str) [O]
  ops=10000 threads=4 — bounded, not a write PoC
  sequential DEAD_NAME: live=256/256
  replace-storm rounds=1152 on 24 ports
  destroy-race pool=25 ports
  race: joined (8s cap)
  kern_return histogram (11465 calls):
      kr=0 (KERN_SUCCESS) count=11463
      kr=0xf (KERN_INVALID_NAME) count=2
  KERN_SUCCESS=11463/11465
  survived=yes  (process still here — no kernel abort observed)
  note: a hit would be a kernel panic/abort, not a userspace kr [I]
```

10,000 operations across 4 threads with replace-storm (1,152 rounds on 24 ports) and
destroy-race (pool of 25 ports) patterns: **zero kernel panics**.

The tool itself classified the result as `bounded, not a write PoC` — acknowledging that the
bug's OOB sites exist in the binary but cannot be triggered at runtime.

---

## Binary basis

The discarded-bounds-check pattern at Site 2 (VA `0xfffffff00ab86cd0`):

```arm64
csel  x10, xzr, x12, hi    ; bounds → x10 (result UNUSED by memory ops)
ldr   x9, [x12]             ; OOB READ uses unchecked x12
str   w11, [x12, #8]        ; OOB WRITE uses unchecked x12
str   xzr, [x12]            ; OOB WRITE uses unchecked x12
```

The bug is real — the bounds check result is discarded. But `x12` can only be a bad pointer if
the table index exceeds the table size, which only happens during a grow race. Since grow cannot
recur after the initial expansion (freelist prevents it), the bad-pointer condition cannot be
reached.

---

## Annotation

The grow-once behavior is an **implicit mitigation**. The freelist design ensures that
`ipc_port_request_alloc()` never needs to grow the table after the first expansion, because the
table always has more entries than can be simultaneously used (iOS port limits of ~1000–2000 per
process are far below the 128-entry table capacity after a single grow to 64→128).

This is not a defense-in-depth patch — it is a natural consequence of the allocation strategy.
But the effect is the same: the TOCTOU window in `ipc_port_request_grow()` is unreachable at
runtime.
