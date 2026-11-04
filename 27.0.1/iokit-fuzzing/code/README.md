# IOKit fuzzer — code artifacts

Educational code from the on-device experiment. This is **analysis/research tooling**, not a
weapon: it enumerates IOKit services reachable from an app sandbox and drives seeded, reproducible
input through them, with heavy safety engineering. On hardened 27.0.1 it found **0 crashes** (see
[`../experiments/results.md`](../experiments/results.md)).

## `FuzzCore.h` — the C API contract

The whole design philosophy is in the header. Three ideas worth copying for any device fuzzer:

1. **Staged modes** (`fuzz_mode_t`). Default is `ENUMERATE` = list services only, never even open a
   user client = zero risk. You *opt up* to `OPEN` → `CALL`/`CONTENT`. You never accidentally run
   the dangerous mode.

2. **Crash recovery via a breadcrumb** (`fuzz_recover_pending`). Before each call, a `pending.json`
   recording `(class, type, selector, input)` is written and `fsync`'d; it is truncated *after* the
   call returns. If the device panics mid-call, the breadcrumb survives the reboot → on next launch
   it is promoted to `suspects.jsonl` **and** its trigger is appended to a permanent **blocklist**
   so the fuzzer never hits that exact panic again. This is what makes forward progress possible on
   a target that can hard-crash.

3. **Circuit breaker** (`fuzz_consecutive_crashes` / `fuzz_reset_health`). After N consecutive
   crash-recoveries the UI refuses to start until a human resets — so a boot-loop can't form.

Plus: a thermal guard (`fuzz_set_paused` on thermal pressure), inter-call pacing, hard caps on
struct size / scalar count, and a conservative class denylist (NVRAM/power).

## What is NOT published here

The full `FuzzCore.c` (the enumeration + `IOConnectCallMethod` driver) and the SwiftUI app are the
author's and live outside this repo. The header is sufficient to understand the method and the
safety model, which is the educational point. The *useful* output of the experiment — the recovered
static `IOExternalMethodDispatch` tables (the real parse surface's exact argument shapes) — is in
[`../experiments/results.md`](../experiments/results.md).

> **Device-safety note.** A method fuzzer can panic a device *by design*. Run it only on a
> secondary / backed-up device, never on one holding irreplaceable data. The breadcrumb + blocklist
> + breaker exist precisely because the first few runs *will* find a panic path.
