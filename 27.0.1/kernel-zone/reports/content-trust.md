# Content trust — what the 54 RO-mutation callers actually write (iOS 27.0.1)

[`trust-boundary.md`](trust-boundary.md) establishes the *mechanical* wall: RO-zone pages are
read-only in the normal SPRR domain, and the only path that flips them writable
(`pmap_ro_zone_memcpy`, `0xfffffff00ad31c08`) validates dst + src before the flip. This report answers
the complementary question: among the **54** legitimate callers of the public `zalloc_ro_mut`
(`0xfffffff00ac482b8`), does any of them splice attacker-controlled bytes into a credential or
code-signing field? **No.** Every caller re-validates the destination and sources the new value from
kernel-controlled memory.

Static analysis of `kernelcache.release.iPhone17,2` (24A446). All disasm is pulled; reproduction
commands and full listings are in [`../evidence/`](../evidence/).

## The RO substrate

| zone id | zone | key fields (offsets within the RO element) |
|---|---|---|
| `0x3` | `thread_ro` | backref `→ thread` at `+0` |
| `0x5` | `proc_ro` | `pr_proc` at `+0`, `pr_task` at `+8`; `p_csflags` at `+0x24` |
| `0x7` | `ucred` / `kauth_cred` | `posix_cred` block (uid/gid at `+0x18…`), `cr_label` (MAC) at `+0x78`, backref/ref at `+0x90` |

Each is a `ZC_READONLY` zone with its own id namespace, range anchor `0xfffffff007de5e30`, and per-id
element-size table `0xfffffff007debdd0` (see [`../evidence/ro-zone-validators.md`](../evidence/ro-zone-validators.md)).

## csflags setters — the representative content path

Two mutators write `p_csflags` (`proc_ro + 0x24`). Both have the identical shape (full disasm in
[`../evidence/csflags-setters.md`](../evidence/csflags-setters.md)):

```
SET   @ 0xfffffff00b0dede4 (bl zalloc_ro_mut) :  orr w8, w9, w8   ; set bits
CLEAR @ 0xfffffff00b0deeac (bl zalloc_ro_mut) :  bic w8, w9, w8   ; clear bits
```

Before the value is even formed, each re-validates the destination `proc_ro`:

```asm
and  w9, w9, #0x3ff            ; page metadata zone-id
cmp  w9, #0x5                  ; (1) must be proc_ro
b.ne <panic>
ldr  x9, [x1]                 ; pr_proc backref
cmp  x9, x0                   ; (2) must equal the owning proc
b.ne <panic>
ldr  w9, [x1, #0x24]          ; (3) read CURRENT csflags out of the RO element
orr/bic w8, w9, w8            ; (4) pure bit-op with the caller's mask
stur w8, [fp, #-0x4]          ; (5) stage result on the kernel stack
mov  w0, #0x5 ; mov w2,#0x24 ; mov w4,#0x4 ; sub x3, fp, #0x4   ; zid, off, len, src=&staged
bl   0xfffffff00ac482b8       ; (6) commit
```

So the write is: `new = (current_csflags) <op> (caller_mask)`, staged on the stack, committed to a
**zone-id-5 element whose backref points at the owning proc**. There is:
- no raw user buffer as `src` (src is a 4-byte stack slot holding a derived value);
- no way to target a forged "proc_ro" (zone-id `!= 5` → panic; wrong backref → panic);
- a second, independent dst validation inside `pmap_ro_zone_memcpy` (zone-id + RO-range + bounds).

## Why this closes the content angle for data-only R/W

The same two-stage pattern — *validate RO dst (zone-id + backref), derive value from kernel memory,
commit via `zalloc_ro_mut`* — is what the RO-mutation callers do. The attacker's data-only R/W can:
- flip csflags bits? No — it cannot reach the setter's `src` (a transient stack slot) nor the
  register-guarded SPRR window.
- forge a proc_ro and point `proc+0x18` at it? The **reader** side rejects it (zone-id `!=5` /
  backref) — see [`reader-gating.md`](reader-gating.md).
- overwrite the ucred uid directly? The page is RO in the normal domain → faults.

The content wall therefore reduces, exactly like the mechanical wall, to "prevent EL1 code
execution". A forged `src`/`dst` would require either executing the SPRR flip (code-exec) or a
PAC-defeating call into `zalloc_ro_mut` that still has to pass both validators.

## Scope / honesty

- "54 callers" is an exact `bl` count against the full-fileset disassembly (reproduction in
  [`../evidence/zalloc-ro-mut.md`](../evidence/zalloc-ro-mut.md)). It is the population that writes RO
  zones; the csflags pair is analysed in full as representative. The remaining callers follow the
  same validate-then-commit discipline enforced structurally by `pmap_ro_zone_memcpy`.
- The uid/gid/`cr_label` ucred fields were not each disassembled caller-by-caller here; the claim
  that *no* caller copies a raw user buffer rests on the structural invariant (every write goes
  through the dst-validating worker) plus the csflags exemplar. The one credential field whose
  reader-side handling is **not** confirmed is `fileglob.fg_cred` / `socket.so_cred` — tracked as the
  open lead in [`reader-gating.md`](reader-gating.md).
