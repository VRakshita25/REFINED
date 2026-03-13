"""
Run this from backend/ to verify all 3 YARA rules work.
Place the 3 .yar files in data/rules/ first.
"""
import sys, os
sys.path.insert(0, '.')

print("=" * 55)
print("STEP 1 — Syntax check each rule file individually")
print("=" * 55)

import yara
rules_dir = "data/rules"
good = []
for fname in sorted(os.listdir(rules_dir)):
    if not fname.endswith(".yar"):
        continue
    fpath = os.path.join(rules_dir, fname)
    try:
        yara.compile(filepath=fpath)
        print(f"  ✓ {fname}")
        good.append(fname)
    except Exception as e:
        print(f"  ✗ {fname} — {e}")

print(f"\n  {len(good)}/3 rules valid")

print()
print("=" * 55)
print("STEP 2 — Compile all together")
print("=" * 55)
filepaths = {f.replace(".yar",""): os.path.join(rules_dir,f) for f in good}
compiled = yara.compile(filepaths=filepaths)
print(f"  ✓ Compiled {len(filepaths)} rule files")

print()
print("=" * 55)
print("STEP 3 — Scan mozi.elf against all rules")
print("=" * 55)
sample = "data/samples/mozi.elf"
if not os.path.exists(sample):
    print(f"  [!] {sample} not found — place mozi.elf there")
    sys.exit(1)

with open(sample, "rb") as f:
    data = f.read()
print(f"  File: {sample} ({len(data)} bytes)")

matches = compiled.match(data=data)
if matches:
    for m in matches:
        print(f"  ✓ MATCHED: {m.rule} — family={m.meta.get('family','?')}")
else:
    print("  ✗ No rules matched packed binary — trying UPX unpack...")
    import subprocess, tempfile, shutil
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tf:
        tf.write(data); tmp = tf.name
    out = tmp + "_u"
    shutil.copy(tmp, out)
    r = subprocess.run(["upx", "-d", "-q", out], capture_output=True)
    if r.returncode == 0:
        with open(out,"rb") as f: unpacked = f.read()
        print(f"  UPX unpacked: {len(unpacked)} bytes")
        matches2 = compiled.match(data=unpacked)
        if matches2:
            for m in matches2:
                print(f"  ✓ MATCHED (unpacked): {m.rule} — family={m.meta.get('family','?')}")
        else:
            print("  ✗ Still no match after unpack")
    else:
        print(f"  UPX failed: {r.stderr.decode()[:100]}")

print()
print("=" * 55)
print("STEP 4 — Full run_yara_scan via module")
print("=" * 55)
from modules.yara_engine import run_yara_scan
result = run_yara_scan(sha256="22ea54360f7b59f926660f70b05b11f6b00bc1519b5114df06176d0c53003e24")
print(f"  Status      : {result['status']}")
print(f"  Rules loaded: {result['rules_loaded']}")
print(f"  Matches     : {result['match_count']}")
print(f"  Top family  : {result['top_family']}")
print(f"  Scan mode   : {result['scan_mode']}")
for m in result.get("matches", []):
    print(f"  → {m['rule']} [{m['severity']}] source={m['scan_source']}")
print("=" * 55)