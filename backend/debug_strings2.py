"""
debug_strings2.py — place in backend/, run: python debug_strings2.py
Deep scan of packed Mozi ELF — finds all useful byte patterns for YARA
"""

import os
import re

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "samples")

def find_all_occurrences(data, pattern_bytes):
    results = []
    start = 0
    while True:
        idx = data.find(pattern_bytes, start)
        if idx == -1:
            break
        results.append((idx, data[max(0,idx-20):idx+80]))
        start = idx + 1
    return results

def extract_strings(data, min_len=5):
    pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
    return [(m.start(), m.group().decode('ascii', errors='ignore')) for m in re.finditer(pattern, data)]

def main():
    elf_files = [f for f in os.listdir(SAMPLES_DIR)
                 if f.endswith(('.elf', '.bin', '.sample')) and 'unpacked' not in f]
    if not elf_files:
        print("[!] No packed sample found in data/samples/")
        return

    fname = elf_files[0]
    with open(os.path.join(SAMPLES_DIR, fname), "rb") as f:
        data = f.read()

    print(f"File: {fname} ({len(data)} bytes)")
    print(f"ELF arch byte: 0x{data[4]:02x} (1=32bit, 2=64bit)")
    print(f"ELF endian:    0x{data[5]:02x} (1=LE, 2=BE)")
    print(f"ELF machine:   0x{data[18]:02x} 0x{data[19]:02x} (0x28=ARM, 0x08=MIPS, 0x03=x86)")

    # All printable strings with offsets
    strings = extract_strings(data, min_len=6)

    print("\n\n── INTERESTING STRINGS WITH OFFSETS ──────────────────────")
    skip_noise = True
    for offset, s in strings:
        # Skip pure garbage (less than 2 alpha chars)
        alpha = sum(1 for c in s if c.isalpha())
        if skip_noise and alpha < 3:
            continue
        print(f"  0x{offset:06x}  {s[:120]}")

    print("\n\n── CONTEXT AROUND 'Mo' (Mozi URL fragment) ───────────────")
    for offset, ctx in find_all_occurrences(data, b'/Mo'):
        print(f"  0x{offset:06x}: {ctx!r}")

    print("\n\n── CONTEXT AROUND 'baidu' ─────────────────────────────────")
    for offset, ctx in find_all_occurrences(data, b'baidu'):
        print(f"  0x{offset:06x}: {ctx!r}")

    print("\n\n── CONTEXT AROUND 'proc' ──────────────────────────────────")
    for offset, ctx in find_all_occurrences(data, b'proc'):
        print(f"  0x{offset:06x}: {ctx!r}")

    print("\n\n── CONTEXT AROUND 'HTTP' ──────────────────────────────────")
    for offset, ctx in find_all_occurrences(data, b'HTTP'):
        print(f"  0x{offset:06x}: {ctx!r}")

    print("\n\n── CONTEXT AROUND 'UPX' ───────────────────────────────────")
    for offset, ctx in find_all_occurrences(data, b'UPX'):
        print(f"  0x{offset:06x}: {ctx!r}")

    print("\n\n── ALL READABLE STRINGS (alpha >= 4 chars) ────────────────")
    for offset, s in strings:
        alpha = sum(1 for c in s if c.isalpha())
        if alpha >= 4:
            print(f"  0x{offset:06x}  {s[:120]}")

if __name__ == "__main__":
    main()