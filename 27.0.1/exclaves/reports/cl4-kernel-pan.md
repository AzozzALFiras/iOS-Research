# Exclave cL4 micro-kernel — VA-addressed capabilities, kept safe by PAN

**Verdict:** hardened / by-design. This is the most instructive "road-blocked" proof in the repo:
the Secure-Kernel addresses capabilities by a *raw caller-supplied pointer* with **no software
bound**, and that is safe **only** because of a hardware property — PAN (Privileged Access Never) —
plus the AP[1]/PAN mutual exclusion. We prove it to the bar in
[`../../../methodology/proof-methodology.md`](../../../methodology/proof-methodology.md): identify the
sink, enumerate the paths, show the dominating guard, and provide a negative control.

- Binary: `exclavecore_bundle` → `SYSTEM/kernel`, carved and raw-loaded at base
  `0xfffffc0000000000` (see [`../../../methodology/`](../../../methodology/) for the carve).
- Build: 27.0.1 (24A446), iPhone17,2. Source modules (from panic `file:line` strings):
  `obj_cnode.c`, `obj_untyped.c`, `obj_ec.c`, `obj_arm64_space.c`, `exception.c`, `pmap.c`, …
  (an seL4/cL4-family design).

## Syscall model (reconstructed)

No `SVC`. Syscalls enter guarded state via Apple **GXF/`genter`**; the ESR-analog is read from the
IMP-DEF register `S3_6_C15_C10_5`, `EC = (esr >> 0x1a) & 0x3f`, and `EC == 0x15` is handled.

Top dispatcher **`FUN_fffffc000000842c(x0=cap1, x1=cap2, w2=selector)`** = `CallSupervisor(selector)`:

| selector | op | sink |
|---|---|---|
| 0 | Invoke | `(*PTR_13610[type*0xb])(slot, method)` |
| 1 | insert/grant | `FUN_e660` |
| 2 | Delete | `FUN_e5dc` |
| 3 | Move | vtable +0x40 |
| 4 | Revoke (single) | `FUN_e7a0(obj,1)` |
| 5 | Revoke children | `FUN_e7a0` over the MDB child chain |

## The sink: capabilities are named by a raw caller pointer

Every selector derives the capability-slot pointer the same way — mask the caller's register to a
36-bit, 64-byte-aligned address and dereference it **directly** as the CTE:

```asm
0x...8470  and  x9, x20, #0xfffffffc0     ; x20 = caller's cap1 (param_1), masked to 36-bit/64B
0x...8490  ldr  x8, [x9]                   ; <-- the cap word is read from a caller-chosen address
0x...8494  lsr  x8, x8, #0x3a              ; bits[58:63] = object TYPE
           ...                             ; bits[0:40] = object id, address = id * -0x40 (TTBR1)
```

There is **no CNode radix walk, no CSpace size/window check** — only non-null and `type != 0`. So if
the attacker could make `[x9]` read a value whose *contents* they control, they would forge a
capability (arbitrary type + arbitrary object id) = full compromise. **That is the whole attack, and
it is blocked by PAN.**

## The guard: PAN + AP[1]/PAN mutual exclusion

1. **PAN is armed on every exception entry.** `SCTLR_EL1 = 0x3454DD9D`; **bit 23 (SPAN) = 0** ⇒ the
   CPU sets `PSTATE.PAN = 1` on each exception taken to EL1. (The two runtime `orr` writes to SCTLR
   touch other bits; SPAN is never set.)
2. **The cap read is a plain `LDR`** (`ldr x8,[x9]`), executed in the task's own TTBR0 regime
   (`FUN_b280` at the dispatcher entry is only an atomic preemption/epoch gate — no TTBR/GXF/SPRR
   switch).
3. **EL0-writable ⟺ AP[1] = 1.** With `PAN = 1`, an EL1 `LDR` of an **EL0-accessible** page
   **faults**. The PTE leaf builder (`FUN_9fa0`) lets the task influence only `AP[2]`(RO) and
   `UXN`; the decisive `AP[1]` bit comes from the per-type template `DAT_fffffc0000013540[type]`:
   user-data templates have `AP[1]=1`, kernel-structure (CNode/CTE) templates have **`AP[1]=0`**
   (EL0 no-access).

So the two conditions for forgery are **mutually exclusive**:

| page the attacker points `param_1` at | can attacker control its bytes? | can the kernel `LDR` read it under PAN? |
|---|---|---|
| EL0-writable data page (AP[1]=1) | **yes** | **no** — PAN faults |
| real CNode/CTE page (AP[1]=0) | **no** — EL0 can't even read it | yes |

The attacker can never satisfy "the kernel reads a cap word whose contents I control". An OOB
`param_1` → PAN permission-fault or translation-fault → the data-abort vector, never a cap op.

## Negative control (why the guard can't be dodged)

The PAN argument only holds if PAN is never cleared and no unprivileged load is used for the cap
read. Whole-binary instruction counts over the kernel:

```
msr pan   : 0        ; PAN is never disabled anywhere
ldtr      : 0        ; no unprivileged load (would bypass PAN)
sttr      : 0        ; no unprivileged store
at s1e0   : 0        ; no EL0 address-translation trick
```

All zero ⇒ the mutual-exclusion holds **globally**, not just at the sites we read.

## Secondary note: the Invoke type bound (#2)

The Invoke path (selector 0) calls `PTR_13610[(type)*0xb]` where `type` is the 6-bit
`cap >> 0x3a` (0x00–0x3f) but only 0x00–0x1a have valid descriptors — for 0x1b–0x3f it would read a
function pointer out of the adjacent rodata and call it, with no null/range check (the Delete/Revoke
paths *do* null-check). This is a genuine missing `if (type > 0x1a)` — but it is **gated by the same
precondition as the sink above**: a kernel-written cap never has `type > 0x1a`, and the attacker
can't write a cap word (PAN). So it is a severity amplifier of a non-reachable condition, not an
independent bug. Worth citing to Apple as a cheap defense-in-depth add.

## Watch-list for future revisions

This safety rests on hardware + a template invariant, not a pointer-range check. It would **reopen**
if a future build: (a) adds an EL0-reachable handler that clears PAN (`msr pan,#0`) or uses
`LDTR`/`STTR` for a cap read; or (b) ships an object-type template granting `AP[1]=1` to a type that
is also a valid cap-slot target. Neither exists in 27.0.1 — re-run the two checks above on each new
build.

## Evidence

Key addresses: dispatcher `FUN_fffffc000000842c`; cap deref `0x...8470/8490/8494`; `SCTLR_EL1 =
0x3454DD9D` (SPAN=0); PTE builder `FUN_9fa0`; type template `DAT_fffffc0000013540`. Disasm excerpts
and the full zero-bypass counts are in [`../evidence/`](../evidence/).
