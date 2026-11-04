# Reader-side gating — why corrupting a *cached* RO pointer doesn't help (iOS 27.0.1)

The write-side ([`trust-boundary.md`](trust-boundary.md)) and content-side
([`content-trust.md`](content-trust.md) analyses show the RO substrate (credentials, csflags, code
signing) is immutable under data-only R/W. This report covers the third leg: the RO elements are
reached through pointers **cached in ordinary, writable zones** (`thread.t_tro`, `proc.p_proc_ro`),
so could an attacker just overwrite the cache to redirect readers at a fake "credential"? **No** —
the hot readers re-derive trust on every access with an inline `zone_require_ro`.

Static analysis of `kernelcache.release.iPhone17,2` (24A446). Full disasm + reproduction in
[`../evidence/`](../evidence/).

## The two hot readers

### Thread credentials — `0xfffffff00ac4b5a0` (1058 references)

The single busiest cred reader. Reproduction and full listing:
[`../evidence/cred-reader-ttro.md`](../evidence/cred-reader-ttro.md). Call-site count: **1057 `bl` + 1
tail-call `b` = 1058** (exact grep against the full-fileset disassembly).

```asm
mrs  x0, tpidr_el1            ; current thread
ldr  x1, [x0, #0x418]         ; t_tro  — cached thread_ro ptr (in a WRITABLE zone)
; inline zone_require_ro(thread_ro):
cmp/ccmp vs 0xfffffff007de5e30 ; (1) t_tro ∈ RO-zone range?          else panic
ldrh ... ; and w8,#0x3ff ; cmp w8, #0x3   ; (2) page metadata zone-id == thread_ro?  else panic
ldr  x8, [x1] ; cmp x8, x0    ; (3) t_tro->thread backref == current thread?        else fail
mov  x0, x1 ; retab           ; only now return the pointer
```

### Process credentials — `0xfffffff00b0db174`

Same structure keyed to `proc_ro` (zone id `5`), reading the cache from `proc + 0x18`
([`../evidence/proc-ro-reader.md`](../evidence/proc-ro-reader.md)):

```asm
ldr  x1, [x0, #0x18]          ; p_proc_ro — cached (writable zone)
cmp/ccmp vs 0xfffffff007de5e30 ; RO-zone range                       else panic
and w8,#0x3ff ; cmp w8, #0x5  ; metadata zone-id == proc_ro          else panic
ldr x8,[x1] ; cmp x8, x0      ; pr_proc backref == proc              else fail
ldr x0, [x1, #0x10] ; retab
```

## Why the cache-corruption path fails

An attacker with data-only R/W overwrites `thread+0x418` (or `proc+0x18`) to point at memory they
control. On the next credential check the reader will:

1. **RO-range check** — the forged target is in a regular (attacker-reachable) zone, which is outside
   the RO-zone range `[base,bound]` at anchor `0xfffffff007de5e30` → panic.
2. Even if the attacker places the fake inside the RO range somehow, the **metadata zone-id** of that
   page must read `3` (thread_ro) / `5` (proc_ro). Forging that halfword needs a write to the
   *metadata array* — possible under R/W for regular zones, but the page then also has to *be* in the
   RO range, which it is not.
3. Even past (1)+(2), the **backref** (`[ro_elem] == owner`) must match — a genuine RO element
   belonging to a different thread/proc fails this.

So redirecting a reader to attacker-controlled "credentials" requires a writable RO-range page with a
matching backref — i.e. the RO wall already defeated (code-exec). At **1058** call sites the thread
reader is on essentially every entitlement/credential path; there is no unguarded hot reader to pick
instead.

## The one open lead (honest, unproven) — `fg_cred` / `so_cred`

Not every `ucred *` is reached through a backref-validated accessor. Raw `ucred` pointers are **cached
in regular-zone structures**:

- `struct fileglob.fg_cred` — the credential captured at `open(2)` time, stored in the (regular-zone)
  file glob;
- `struct socket.so_cred` — the credential captured at socket-creation time.

For `t_tro`/`p_proc_ro` the reader re-runs `zone_require_ro` on every use. For `fg_cred`/`so_cred`
the equivalent **reader-side re-validation is NOT confirmed** in this analysis. If some consumer
dereferences `fg_cred`/`so_cred` *without* re-validating it against the RO-zone range + zone-id +
backref, then a data-only overwrite of that cached pointer (both fields live in writable zones) could
redirect a credential check at an attacker-crafted `ucred` — a genuinely data-only-relevant residual.

**Status: OPEN.** This is the single residual data-only lead for the kernel-zone track (it also
appears as question 0 in the top-level `STATUS.md`). What would close it:

- enumerate the dereference sites of `fileglob+<fg_cred off>` and `socket+<so_cred off>`;
- for each, check whether the path funnels through the backref-validating cred accessor
  (`0xfffffff00ac4b5a0`-style `zone_require_ro`) before the `ucred` fields are read;
- if any reaches `posix_cred`/`cr_label` with no RO re-validation, that is an exploitable data-only
  read-redirection; if all re-validate, the lead is closed and the RO wall is complete for
  data-only on this surface too.

This lead could not be anchored by symbol (the kernelcache has no `fg_cred`/`so_cred` symbols); it
requires structure-offset resolution for `fileglob`/`socket`, which is future work.
