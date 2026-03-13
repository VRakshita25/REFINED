"""
debug_strings.py — place in backend/, run: python debug_strings.py
Extracts strings from cached ELF sample to help write accurate YARA rules.
"""

import os
import re

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "samples")

def extract_strings(data, min_len=6):
    pattern = rb'[ -~]{' + str(min_len).encode() + rb',}'
    return [m.group().decode('ascii', errors='ignore') for m in re.finditer(pattern, data)]

def main():
    if not os.path.exists(SAMPLES_DIR):
        print(f"[!] Samples dir not found: {SAMPLES_DIR}")
        return

    elf_files = [f for f in os.listdir(SAMPLES_DIR) if f.endswith(('.elf', '.bin', '.sample'))]
    if not elf_files:
        print("[!] No sample files found in data/samples/")
        return

    for fname in elf_files:
        fpath = os.path.join(SAMPLES_DIR, fname)
        with open(fpath, "rb") as f:
            data = f.read()

        magic = data[:4].hex()
        is_elf = "OK" if data[:4] == b'\x7fELF' else "NOT ELF"

        print(f"\n{'='*60}")
        print(f"File : {fname}  ({len(data)} bytes)")
        print(f"Magic: {magic} ({is_elf})")
        print(f"{'='*60}")

        strings = extract_strings(data)
        print(f"Total strings extracted: {len(strings)}")

        mozi_keywords = [
            "mozi", "Mozi", "MOZI",
            "[N", "NKRUN", "NDIP", "NUPDATE", "NHTTPFLOOD", "NUDPFLOOD", "NABLE", "WAIT_NET",
            "get_peers", "find_node", "announce_peer", "BitTorrent", "d1:ad", "d1:rd",
            "iptables", "busybox", "wget", "tftp", "curl", "chmod",
            "crontab", "/tmp/", "/proc/", "ntp.org",
        ]

        print("\n── Mozi-relevant strings ──────────────────────────────")
        found = []
        for s in strings:
            for kw in mozi_keywords:
                if kw.lower() in s.lower():
                    found.append(s)
                    break
        if found:
            for s in found:
                print(f"  {s[:100]}")
        else:
            print("  (none found — sample may be packed/encrypted)")

        print("\n── Path strings (start with /) ────────────────────────")
        for s in strings:
            if s.startswith('/') and len(s) > 4:
                print(f"  {s[:100]}")

        print("\n── Network strings (http/ftp/ip) ──────────────────────")
        for s in strings:
            sl = s.lower()
            if any(x in sl for x in ['http', 'ftp', '://', '.org', '.com', '.net']):
                print(f"  {s[:100]}")

        print("\n── All strings (first 150) ────────────────────────────")
        for s in strings[:150]:
            print(f"  {s[:100]}")

if __name__ == "__main__":
    main()