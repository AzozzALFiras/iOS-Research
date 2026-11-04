#!/usr/bin/env python3
# Wrap a raw code blob into a minimal AArch64 ELF64 so standard tools
# (llvm-objdump) can disassemble it at a chosen base vaddr.
import struct, sys
raw_path, out_path, base = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
data = open(raw_path, 'rb').read()
shstr = b'\x00.text\x00.shstrtab\x00'
name_text = 1
name_shstr = 7
ehsize = 64
# layout: [ehdr][.text data][.shstrtab][section headers]
text_off = ehsize
shstr_off = text_off + len(data)
# align section header table to 8
sht_off = (shstr_off + len(shstr) + 7) & ~7
shentsize = 64
num_sh = 3  # null, .text, .shstrtab
# ELF header
e_ident = b'\x7fELF' + bytes([2,1,1,0]) + b'\x00'*8
ehdr = e_ident + struct.pack('<HHIQQQIHHHHHH',
    2,        # e_type ET_EXEC
    183,      # e_machine EM_AARCH64
    1,        # e_version
    base,     # e_entry
    0,        # e_phoff (no program headers)
    sht_off,  # e_shoff
    0,        # e_flags
    ehsize,   # e_ehsize
    0,0,      # e_phentsize, e_phnum
    shentsize, num_sh,
    2)        # e_shstrndx
def shdr(name, typ, flags, addr, off, size, link, info, align, entsize):
    return struct.pack('<IIQQQQIIQQ', name, typ, flags, addr, off, size, link, info, align, entsize)
sh_null = shdr(0,0,0,0,0,0,0,0,0,0)
sh_text = shdr(name_text, 1, 0x6, base, text_off, len(data), 0, 0, 4, 0)  # PROGBITS ALLOC+EXEC
sh_shstr = shdr(name_shstr, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)   # STRTAB
blob = bytearray()
blob += ehdr
blob += data
blob += shstr
blob += b'\x00' * (sht_off - (shstr_off + len(shstr)))
blob += sh_null + sh_text + sh_shstr
open(out_path, 'wb').write(blob)
print("wrote", out_path, "base", hex(base), "size", len(data))
