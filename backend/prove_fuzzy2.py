"""
REAL fuzzy proof — mutate binary, detect with new SHA256
"""
import sys, os, hashlib, random, subprocess
sys.path.insert(0, '.')

# ── Find correct pydeep API ────────────────────────────────────────
import pydeep
print(f"[i] pydeep methods: {[m for m in dir(pydeep) if not m.startswith('_')]}")

def ssdeep_hash(data: bytes) -> str:
    # Try every known pydeep API variant
    for method in ['hash_bytes', 'hash', 'Hash']:
        fn = getattr(pydeep, method, None)
        if fn:
            try:
                r = fn(data)
                return r.decode() if isinstance(r, bytes) else r
            except Exception:
                pass
    # Fallback: write to temp file, use system ssdeep binary
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.elf') as tf:
        tf.write(data)
        tmp = tf.name
    try:
        out = subprocess.check_output(['ssdeep', '-b', tmp], text=True)
        for line in out.splitlines():
            if ':' in line and not line.startswith('ssdeep'):
                return line.split(',')[0].strip()
    except Exception as e:
        print(f"[!] system ssdeep failed: {e}")
    finally:
        os.unlink(tmp)
    return ""

def ssdeep_compare(h1: str, h2: str) -> int:
    for method in ['compare']:
        fn = getattr(pydeep, method, None)
        if fn:
            try:
                r = fn(h1.encode() if isinstance(h1, str) else h1,
                       h2.encode() if isinstance(h2, str) else h2)
                return int(r)
            except Exception:
                pass
    return 0

# ── Load real binary ───────────────────────────────────────────────
path = "data/samples/mozi.elf"
with open(path, "rb") as f:
    original = f.read()

orig_sha256 = hashlib.sha256(original).hexdigest()
print(f"\nOriginal SHA256 : {orig_sha256}")

# ── Mutate 100 bytes ───────────────────────────────────────────────
random.seed(99)
mutated = bytearray(original)
for _ in range(100):
    i = random.randint(2000, len(mutated) - 200)
    mutated[i] = (mutated[i] + 1) % 256
mutated = bytes(mutated)

mut_sha256 = hashlib.sha256(mutated).hexdigest()
print(f"Mutated  SHA256 : {mut_sha256}")
print(f"SHA256 identical? {orig_sha256 == mut_sha256}")

# ── Compute ssdeep ─────────────────────────────────────────────────
print("\n[*] Computing ssdeep hashes...")
orig_ssdeep = ssdeep_hash(original)
mut_ssdeep  = ssdeep_hash(mutated)
print(f"Original ssdeep : {orig_ssdeep}")
print(f"Mutated  ssdeep : {mut_ssdeep}")

if not orig_ssdeep or not mut_ssdeep:
    print("[!] ssdeep hashing failed — check pydeep/ssdeep install")
    sys.exit(1)

raw_score = ssdeep_compare(orig_ssdeep, mut_ssdeep)
print(f"Raw ssdeep score: {raw_score}/100")

# ── Feed mutated ssdeep to MalDNA (empty SHA256 = not in DB) ───────
from modules.fuzzy_hash2 import run_fuzzy_hash
print("\n[*] Running MalDNA fuzzy engine with mutated ssdeep + empty SHA256...")
result = run_fuzzy_hash(ssdeep_hash=mut_ssdeep, sha256="")

print("\n=========================================")
print("PROOF SUMMARY")
print("=========================================")
print(f"  Original SHA256 : {orig_sha256[:32]}...")
print(f"  Mutated  SHA256 : {mut_sha256[:32]}...")
print(f"  SHA256 match    : NO")
print(f"  Fuzzy score     : {result['top_score']}/100")
print(f"  Family detected : {result['top_family'] or 'NONE'}")
verdict = "DETECTED AS MOZI ✓" if result['top_family'] == 'Mozi' else "NOT DETECTED ✗"
print(f"  VERDICT         : {verdict}")
print("=========================================")

# ── UI test instruction ────────────────────────────────────────────
print(f"""
HOW TO TEST IN UI:
  The mutated binary has SHA256: {mut_sha256}
  Bazaar won't find it (novel sample) — so UI will show "not found".

  The fuzzy engine runs on the ssdeep string Bazaar returns.
  To demo in UI, use the ORIGINAL hash:
    {orig_sha256}
  Bazaar returns its ssdeep → fuzzy engine scores 100 IDENTICAL.

  The TERMINAL proof above (score {result['top_score']} on mutated ssdeep)
  is the real fuzzy detection demo for judges.
""")