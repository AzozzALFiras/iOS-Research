# Evidence — cL4 VA-addressed capability deref, kept safe by PAN

Backs finding #1 in [`../README.md`](../README.md) and [`../reports/cl4-kernel-pan.md`](../reports/cl4-kernel-pan.md).

## Binary / tooling note

- Binary: `exclavecore_bundle.t8140.RELEASE` → `SYSTEM/kernel`, **carved raw** (the real 165-function
  code region, which `ipsw fw exclave` does not emit — it rebuilds the boot manifest). On kd-app:
  `/root/ios-research/analysis/exclaves/kerncarve/exk_code_2701.bin` (98304 B). Build 27.0.1 (24A446),
  iPhone17,2.
- The carve is the first `0x18000` bytes of the decompressed bundle, so **file offset == VA − base**
  with base `0xfffffc0000000000` (verified: the 98304-byte slice at offset 0 of `raw_bundle.bin`
  equals the carve byte-for-byte).
- The task's suggested `llvm-objdump -b binary -m aarch64` does **not** work on the host toolchain
  (llvm-objdump 18 dropped `-b binary`; the system GNU objdump is an x86-only build and refuses
  `-m aarch64`). The reproducible substitute is to wrap the raw blob in a one-section AArch64 ELF at
  the load base, then use stock `llvm-objdump -d`. The wrapper [`mkelf.py`](mkelf.py) is in this
  directory; it emits an ELF whose `.text` `sh_addr` is the base, so all printed VAs are correct.

## Claim

The cL4 Secure-Kernel names a capability by a **raw caller-supplied pointer** masked to a 36-bit,
64-byte-aligned address and dereferenced **directly** as the capability-table entry, with **no CNode
radix walk and no software CSpace bound** — only a non-null / `type != 0` check. The read is safe
**only** because PAN (Privileged Access Never) is armed (`SCTLR_EL1.SPAN = 0`) and is never cleared
or bypassed anywhere in the kernel, so an EL1 `LDR` of any EL0-writable page faults.

## Reproduction

```sh
cd /root/ios-research/analysis/exclaves/kerncarve
# one-time: wrap the raw carve as an AArch64 ELF at the load base
python3 mkelf.py exk_code_2701.bin exk_code_2701.elf 0xfffffc0000000000

# (a) the capability dereference inside dispatcher FUN_fffffc000000842c
llvm-objdump -d --start-address=0xfffffc0000008470 --stop-address=0xfffffc000000849c exk_code_2701.elf

# (b) the SCTLR_EL1 value that arms PAN
llvm-objdump -d --start-address=0xfffffc0000007afc --stop-address=0xfffffc0000007b08 exk_code_2701.elf

# (c) negative control: no PAN-clear / unprivileged-load / EL0-AT primitive exists
llvm-objdump -d --no-show-raw-insn exk_code_2701.elf > /tmp/exk_full.asm
grep -icE 'msr\s+pan' /tmp/exk_full.asm      # -> 0
grep -icE '\bldtr'    /tmp/exk_full.asm      # -> 0
grep -icE '\bsttr'    /tmp/exk_full.asm      # -> 0
grep -icE 'at\s+s1e0' /tmp/exk_full.asm      # -> 0
```

## Disassembly (pulled 27.0.1)

(a) capability deref — `0x8470`/`0x8490`/`0x8494`:

```
fffffc0000008470: 927a7689   and  x9, x20, #0xfffffffc0   ; x20 = caller cap1, masked to 36-bit / 64B-aligned slot addr
fffffc0000008474: aa0903f2   mov  x18, x9
fffffc0000008478: f9400252   ldr  x18, [x18]
fffffc000000847c: d2800032   mov  x18, #0x1
fffffc0000008480: 52800080   mov  w0, #0x4
fffffc0000008484: f100065f   cmp  x18, #0x1
fffffc0000008488: 540000c1   b.ne 0xfffffc00000084a0
fffffc000000848c: b40000a9   cbz  x9, 0xfffffc00000084a0  ; only guard: non-null
fffffc0000008490: f9400128   ldr  x8, [x9]                ; <-- cap word read from caller-chosen address
fffffc0000008494: d37afd08   lsr  x8, x8, #58             ; bits[58:63] = object TYPE
fffffc0000008498: b5001208   cbnz x8, 0xfffffc00000086d8  ; and type != 0
```

(b) SCTLR_EL1 = 0x3454DD9D:

```
fffffc0000007afc: 529bb3a8   mov  w8, #0xdd9d
fffffc0000007b00: 72a68a88   movk w8, #0x3454, lsl #16    ; w8 = 0x3454DD9D
fffffc0000007b04: d5181008   msr  SCTLR_EL1, x8
```

(c) negative-control counts over the whole kernel:

```
msr pan   : 0
ldtr      : 0
sttr      : 0
at s1e0   : 0
```

The other four `msr SCTLR_EL1` sites (0x2fb4/0x2fc8/0x3018/0x302c) only `orr` in bits
0x80000000, 0x40000000, 0x8000000, 0x2000, 0x800000000, 0x1000000000 — i.e. bits 13/27/30/31/35/36.
None touches **bit 23 (SPAN)**, confirmed by reading those windows.

## Annotation

- `and x9,x20,#0xfffffffc0` keeps bits[6:35] of the caller's register — a 36-bit, 64-byte-aligned
  slot address — and `ldr x8,[x9]` reads the capability word straight from it. There is no bound
  against any CSpace window; the type/object-id are taken from whatever that word contains.
- `0x3454DD9D >> 23 == 0x68` (even) ⇒ **SCTLR_EL1.SPAN = 0**, so the CPU sets `PSTATE.PAN = 1` on
  every exception entry to EL1. With PAN=1 an EL1 `LDR` of an EL0-accessible page (PTE `AP[1]=1`)
  faults. A page the task can write is EL0-accessible; a real CNode/CTE page has `AP[1]=0` (EL0
  no-access) so the task cannot read it either. The two conditions for cap forgery
  ("kernel reads a word whose contents I control") are mutually exclusive.
- The zero counts prove the mutual exclusion holds *globally*: there is no `msr pan,#0` to disarm
  PAN, and no `LDTR`/`STTR`/`AT S1E0` unprivileged primitive that would read the slot while bypassing
  PAN. An out-of-range `cap1` yields a data-abort, never a capability operation.

**Verdict:** hardened / by-design. Safe-by-hardware, not safe-by-software-bound.
