#!/usr/bin/env python3
# Content-anchored function alignment for STRIPPED binaries whose function_starts count
# differs between two builds (so positional index alignment drifts). Aligns the two
# ordered function lists by a SequenceMatcher over normalized body hashes, so an
# inserted/removed function doesn't shift everything after it. Prints each changed pair
# ranked by LOWEST similarity first (= most structurally changed = best bug candidate).
#
# Usage: kextalign_sm.py <label>
# Expects, under <TEXTDUMP>:
#   <label>_a.qasm / <label>_b.qasm     ipsw macho disass <bin> -x __TEXT.__text -q
#   <label>_a.starts / <label>_b.starts one hex function-start address per line
#                                       (function_starts, or Ghidra "@ 0x..." markers)
#
# Depends on fdiff.py (load_insns / load_starts / norm_body); see fdiff-normalization.md.
import sys, bisect, difflib, hashlib

# --- configure these two paths for your environment -------------------------
TEXTDUMP = "<TEXTDUMP>"                 # dir holding the .qasm / .starts dumps
sys.path.insert(0, "<BINDIFF_DIR>")     # dir holding fdiff.py
# ---------------------------------------------------------------------------
import fdiff

lbl = sys.argv[1]
i0 = fdiff.load_insns(f"{TEXTDUMP}/{lbl}_a.qasm"); st0 = sorted(fdiff.load_starts(f"{TEXTDUMP}/{lbl}_a.starts"))
i1 = fdiff.load_insns(f"{TEXTDUMP}/{lbl}_b.qasm"); st1 = sorted(fdiff.load_starts(f"{TEXTDUMP}/{lbl}_b.starts"))

def groups(insns, starts):
    addrs = [t[0] for t in insns]; out = []
    for i, a in enumerate(starts):
        b = starts[i + 1] if i + 1 < len(starts) else a + 0x100000
        body = fdiff.norm_body(insns[bisect.bisect_left(addrs, a):bisect.bisect_left(addrs, b)])
        out.append((a, body))
    return out

g0 = groups(i0, st0); g1 = groups(i1, st1)
h0 = [hashlib.sha1("\n".join(b).encode()).hexdigest() for _, b in g0]
h1 = [hashlib.sha1("\n".join(b).encode()).hexdigest() for _, b in g1]

sm = difflib.SequenceMatcher(a=h0, b=h1, autojunk=False)
unchanged = changed = inserted = deleted = 0
changed_pairs = []
for tag, a0, a1, b0, b1 in sm.get_opcodes():
    if tag == "equal":
        unchanged += (a1 - a0)
    elif tag == "replace":
        n = max(a1 - a0, b1 - b0)
        for k in range(n):
            x, y = a0 + k, b0 + k
            if x < a1 and y < b1:
                changed += 1
                sim = difflib.SequenceMatcher(a=g0[x][1], b=g1[y][1], autojunk=False).ratio()
                changed_pairs.append((x, y, g0[x][0], g1[y][0], len(g0[x][1]), len(g1[y][1]), sim))
            elif x < a1:
                deleted += 1
            else:
                inserted += 1
    elif tag == "insert":
        inserted += (b1 - b0)
    elif tag == "delete":
        deleted += (a1 - a0)

changed_pairs.sort(key=lambda t: t[6])  # lowest similarity first
for x, y, va, vb, la, lb, sim in changed_pairs:
    print(f"idx0={x} idx1={y} a={hex(va)} b={hex(vb)} insn {la}->{lb} d={lb-la:+d} sim={sim:.3f}")
print(f"\n# SUMMARY {lbl}: funcs a={len(g0)} b={len(g1)} | unchanged={unchanged} changed={changed} inserted={inserted} deleted={deleted}")
