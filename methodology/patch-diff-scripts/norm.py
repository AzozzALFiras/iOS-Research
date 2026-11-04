#!/usr/bin/env python3
# Normalize one qasm slice so two builds of the same function compare equal when only
# layout (addresses) differ, while genuine constant changes (sizes/bounds) survive.
#
#   ipsw macho disass <bin> -x __TEXT.__text -q | python3 norm.py
#
# Rule: drop the leading "0xADDR:" column; replace absolute hex operands/branch targets
# with a placeholder, but KEEP small immediates (< 0x1000) — struct offsets, counts and
# bounds are exactly the security-relevant constants we must not erase.
import sys, re

hexre = re.compile(r"0x[0-9a-fA-F]+")

def norm(line):
    parts = line.split(":", 1)
    body = parts[1] if (len(parts) == 2 and parts[0].strip().startswith("0x")) else line
    body = body.strip()

    def repl(m):
        v = int(m.group(0), 16)
        return "#imm" if v < 0x1000 else "ABS"

    return hexre.sub(repl, body)

for l in sys.stdin:
    l = l.rstrip("\n")
    if l.strip():
        print(norm(l))
