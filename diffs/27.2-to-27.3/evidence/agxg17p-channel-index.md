# AGXG17P "channel-index" OOB read — verification (27.2 / 27.0.1 vs 27.3)

**Kext:** `com.apple.AGXG17P` (Apple GPU kext, iPhone17,2 / G17P)
**Candidate:** byte-indexed pointer-array OOB read, reported fixed in 27.3 beta.

**Verdict (summary):**
- Items 1–3, 5 (fix exists / bug class / liveness / impact bound): **PROVEN** at the instruction level.
  27.3 adds a real `cmp; b.ls` bound check that 27.2 and 27.0.1 both lack, guarding a
  byte-indexed load of a pointer from an array, which is then dereferenced. This is a genuine
  **memory-safety change**, not a cosmetic/robustness reschedule.
- Item 4 (reachability / attacker-control — DECISIVE): **UNRESOLVED / NOT PROVEN.**
  The function is reached only through indirect (vtable/ops-table) dispatch; it has **zero static
  cross-references** anywhere in the kext, symbols are stripped, and no decompiler/xref provider
  (Ghidra/Hopper/IDA) was available in this environment. I could **not** prove that the index byte
  is attacker-controlled from an `IOConnectCallMethod` input, nor prove an entitlement gate.
- **Overall: CONFIRMED real OOB-read hardening, live in 27.2 and 27.0.1 — but DOWNGRADED from
  "proven live sandbox bug" to CANDIDATE**, because attacker-control of the index could not be
  established. It is consistent with either (a) a genuine sandbox-reachable OOB on the GPU
  submit path, or (b) defense-in-depth hardening of a kernel-constrained index. The evidence
  below does not distinguish these, and I did not fabricate a call chain to force a conclusion.

---

## Environment / reproduction base

All disassembly on `ssh kd-app`. Extracted kext bodies:
```
/root/ios-research/analysis/diff272/bins/AGXG17P_2701/com.apple.AGXG17P   # 27.0.1 (24A446)
/root/ios-research/analysis/diff272/bins/AGXG17P_272/com.apple.AGXG17P    # 27.2   (24B119)
/root/ios-research/analysis/diff272/bins/AGXG17P_273/com.apple.AGXG17P    # 27.3   (24C5037i)
```
(Extracted via `ipsw kernel extract <kc> com.apple.AGXG17P -o <dir>`; all three are identical in
size for 27.2/27.3 = 1,122,128 bytes; sha256 of 27.2 body `320b948c...7399`.)

Body-diff alignment (SequenceMatcher over normalized function bodies, handles the +5 inserted
functions 27.2→27.3):

**Claim: there is exactly one small function that gains a bound check.**
```
# command (remote)
python3 -I /tmp/kalign_2.py AGXG17P 272 273      # adapted from kextalign_sm.py, suffixes 272/273
# SUMMARY AGXG17P 272->273: funcs v0=3142 v1=3147 | unchanged=3059 changed=83 inserted=5 deleted=0
# top candidate by lowest-similarity that GROWS:
idx0=2372 idx1=2376 v0=0xfffffff008503b4c v1=0xfffffff00852fc50 insn 23->24 d=+1 sim=0.809
```

---

## 1. The fix exists and where — PROVEN

| version | function start | note |
|---|---|---|
| 27.0.1 | `0xfffffff0084f2710` | no check |
| 27.2   | `0xfffffff008503b4c` | no check |
| 27.3   | `0xfffffff00852fc50` | **check added** |

**Command:**
```
ipsw macho disass <B272> -a 0xfffffff008503b4c -c 30 --quiet
ipsw macho disass <B273> -a 0xfffffff00852fc50 -c 30 --quiet
```

**27.2 (vulnerable):**
```
0xfffffff008503b4c:  bti  c
0xfffffff008503b50:  mov  w8, #0
0xfffffff008503b54:  cbz  x1, 0xfffffff008503ba0
0xfffffff008503b58:  ldr  x9, [x0, #0x8]          ; x9 = this->table
0xfffffff008503b5c:  cbz  x9, 0xfffffff008503ba0
0xfffffff008503b60:  ldrb w8, [x1]                ; w8 = INDEX  (byte, 0..255), from arg struct
0xfffffff008503b64:  ldr  x9, [x9, #0x40]          ; x9 = table->array  (array of pointers)
0xfffffff008503b68:  ldr  x8, [x9, x8, lsl #0x3]   ; x8 = array[INDEX]   <-- OOB READ, no bound
0xfffffff008503b6c:  ldrb w8, [x8, #0x14]          ; deref the (possibly OOB) pointer -> flags byte
0xfffffff008503b70:  tbnz w8, #0x5, 0xfffffff008503b7c
0xfffffff008503b74:  mov  w0, #0
0xfffffff008503b78:  ret
0xfffffff008503b7c:  ldr  x8, [x1, #0x8]           ; x8 = arg->mask (u64)
0xfffffff008503b80:  ldr  x9, [x0, #0x18]          ; x9 = this->mask
0xfffffff008503b84:  tst  x9, x8
0xfffffff008503b88:  b.eq 0xfffffff008503b94
0xfffffff008503b8c:  mov  w0, #0
0xfffffff008503b90:  ret
0xfffffff008503b94:  orr  x8, x9, x8
0xfffffff008503b98:  str  x8, [x0, #0x18]          ; this->mask |= arg->mask
0xfffffff008503b9c:  mov  w8, #0x1
0xfffffff008503ba0:  mov  x0, x8
0xfffffff008503ba4:  ret
```

**27.3 (fixed) — the added instructions:**
```
0xfffffff00852fc64:  ldrb w8,  [x1]               ; w8 = INDEX
0xfffffff00852fc68:  ldr  w10, [x9, #0x48]         ; + w10 = table->count   (ADDED)
0xfffffff00852fc6c:  cmp  w10, w8                  ; + compare count vs index (ADDED)
0xfffffff00852fc70:  b.ls 0xfffffff00852fc94       ; + if count <= index -> bail (ADDED)
0xfffffff00852fc74:  ldr  x9,  [x9, #0x40]         ; x9 = table->array
0xfffffff00852fc78:  ldr  x8,  [x9, w8, uxtw #0x3] ; array[index]  (lsl#3 -> uxtw#3, robustness)
0xfffffff00852fc7c:  ldrb w8,  [x8, #0x14]
0xfffffff00852fc80:  tbz  w8, #0x5, 0xfffffff00852fc94   ; shared bail (merged w0=0 exit)
...
0xfffffff00852fc94:  mov  w0, #0
0xfffffff00852fc98:  ret
```
The bound value is `table->count` at `[table+0x48]`; the array is `table->array` at `[table+0x40]`.
`b.ls` is unsigned `<=`, so 27.3 permits only `index < count`. This is a textbook added bounds check.

## 2. Bug class — PROVEN (OOB read of a pointer, then a dereference)

- The guarded value **is an index** (`w8 = ldrb [x1]`, an 8-bit value) used to index an **array of
  8-byte pointers** (`table->array` at `+0x40`) via `ldr x8, [x9, idx, lsl #3]`.
- The indexed slot is **read** (not written): it loads a pointer, which is then **dereferenced**
  (`ldrb w8, [x8, #0x14]`) and a single bit (bit 5) is tested.
- So this is an **OOB read** that escalates into a **wild pointer dereference** of the OOB-read value.

## 3. Liveness — PROVEN (absent in BOTH 27.0.1 and 27.2)

**27.0.1** (`ipsw macho disass <B2701> -a 0xfffffff0084f2708 -c 22 --quiet`) is byte-for-byte the
same shape as 27.2 — no count load, no compare:
```
0xfffffff0084f2724:  ldrb w8, [x1]
0xfffffff0084f2728:  ldr  x9, [x9, #0x40]
0xfffffff0084f272c:  ldr  x8, [x9, x8, lsl #0x3]   ; OOB, no bound
0xfffffff0084f2730:  ldrb w8, [x8, #0x14]
0xfffffff0084f2734:  tbnz w8, #0x5, 0xfffffff0084f2740
```
=> The unchecked read is **live on shipping 27.2 and on 27.0.1**; first guarded in 27.3.

## 4. Reachability / attacker-control (DECISIVE) — UNRESOLVED

What is proven about the data flow:
- `x1` is a **caller-supplied pointer** (used as `ldrb [x1]`, `ldr [x1,#8]`; never derived from
  `this`). Its layout is a 16-byte struct `{ u8 index @0; u64 mask @8 }`.
- `this` (`x0`) is an object with `table @+0x8`, `mask @+0x18`, plus scalars at `+0x10`/`+0x14`.
  The sibling init method `0xfffffff008503bb4` is `{ str x1,[x0,#8]; strb w2,[x0,#0x10];
  str w3,[x0,#0x14] }`, and another sibling (`0xfffffff008503b34`) `cnt/addv` **popcounts**
  `this->mask` — i.e. this is a small "usage/occupancy bitmask keyed by an index table" helper.

What blocks a reachability proof:
- The function is **vtable/ops-table slot index 4** of a small C++ helper class. Its vtable lives in
  `__DATA_CONST.__const` at `0xfffffff007eca388` (slots → the method cluster
  `0xfffffff008503b04 .. 0xfffffff008503be8`), decoded from the arm64e auth-rebase chained pointers
  (`KCbase=0xfffffff007004000`, target = low-32 of each slot).
- **No direct `bl`/`b` targets any function in the cluster** (`grep` over the full `__text` qasm: 0 hits).
- **No static data or code reference to the vtable address** `0xfffffff007eca388` exists anywhere
  in the kext (scanned every decoded pointer in `__const`, `__data`, `__auth_got`; and every
  `adrp …eca000`+`add` sequence — none compute the vtable offset `0x388`/`0x370`/`0x3a8`).
  => the vptr is installed at runtime by a constructor not visible as a static reference here
     (likely a base-class constructor / OSMetaClass in a companion kext), so the caller cannot be
     reached by static xref.
- Symbols are stripped in both the extracted kext and the full kernelcache, and no
  decompiler/xref provider was configured (`rea` xref returned `provider_unavailable`;
  Ghidra/Hopper/IDA all absent). Manual indirect-dispatch tracing to a userspace selector was
  therefore not completed.

Surrounding-surface context (inference, NOT a proof of this function's path):
- This kext is the GPU command-submission kext: strings include `AGXDeviceUserClient`,
  `AGXCommandQueue`, and `AGXCLChannelSKSM::submitBuffer` with validation messages
  `context_id is out of range`, `priority_type out of bounds`, `event_flag_idx out of bounds`.
  The submit path (`AGXCLChannelSKSM::submitBuffer`, function `0xfffffff008486c10`, 891 insns)
  **already validates** those indices in 27.2 — so those are *not* our bug; our helper is a separate
  lookup. AGX device/command-queue user clients are generally reachable from the ordinary app GPU
  sandbox.
- The **only** entitlement string in the whole kext is `com.apple.private.agx.performance-spi`
  (one occurrence), i.e. the bulk of the surface is not entitlement-gated. This argues the kext is
  broadly sandbox-reachable in general, but does **not** establish that *this* function is on an
  ungated, attacker-controlled path.

Because item 4 is decisive and unproven, I do **not** claim this as the project's first proven live
sandbox bug. To close it, resolve the owning class (needs the companion AGX kext / a decompiler +
xref DB), then trace whether `index` originates from an `IOConnectCallMethod` scalar/struct field
on an ungated user client, or is clamped/kernel-derived before the call.

## 5. Impact bound — PROVEN (given reachability)

- `index` is a **byte** (`ldrb`), range 0..255. The array holds 8-byte pointers, so the OOB read of
  the *slot* reaches at most `(255 - count) * 8` bytes past `table->array` — on the order of ~2 KB
  beyond the array for a small channel table.
- The OOB-read value is then **used as a pointer and dereferenced** (`ldrb [slot+0x14]`). That is
  the more serious primitive: a wild kernel read of whatever 8-byte value sat beyond the array
  (crash/DoS if unmapped/garbage; a controlled read if an attacker can place a chosen value in the
  adjacent allocation).
- Observable feedback to the caller is narrow: only **bit 5** of the dereferenced byte decides
  whether `this->mask |= arg->mask` runs and whether the function returns 1 vs 0 — i.e. at most a
  1-bit oracle per call, plus the side effect on `this->mask`. So the direct info-leak bandwidth is
  low; the dereference-of-OOB-pointer is the real memory-safety hazard.

---

## Reusable artifacts
- Remote scripts: `/tmp/kalign_2.py` (272↔273 alignment), `/tmp/kd_2.py` (per-function normalized
  unified diff). Local kext copies: `scratchpad/agx/{2701,272,273}/com.apple.AGXG17P`.
- Vtable decode: arm64e auth-rebase, `target = KCbase(0xfffffff007004000) + (slot & 0xffffffff)`;
  our function = `__const` slot `0xfffffff007eca3a8`.
