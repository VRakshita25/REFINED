"""
modules/yara_engine.py — MalDNA Step 3
Fixed: pyzipper for Bazaar's AES-encrypted zip + mozi.yar unreferenced string removed
Install: pip install yara-python pyzipper
"""

import os
import io
import requests
import yara
from dotenv import load_dotenv

load_dotenv()

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR   = os.path.join(BASE_DIR, "data", "rules")
SAMPLES_DIR = os.path.join(BASE_DIR, "data", "samples")
BAZAAR_URL  = "https://mb-api.abuse.ch/api/v1/"
BAZAAR_KEY  = os.getenv("MALWAREBAZAAR_API_KEY", "")

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


# ── Rule loader ───────────────────────────────────────────────────
def load_all_rules():
    print(f"[YARA] RULES_DIR = {RULES_DIR}")
    print(f"[YARA] Exists    = {os.path.exists(RULES_DIR)}")

    if not os.path.exists(RULES_DIR):
        print("[YARA] ERROR: Rules directory not found")
        return None

    rule_files = {}
    for fname in sorted(os.listdir(RULES_DIR)):
        if not fname.endswith(".yar"):
            continue
        fpath = os.path.join(RULES_DIR, fname)
        namespace = fname.replace(".yar", "")
        try:
            yara.compile(filepath=fpath)
            rule_files[namespace] = fpath
            print(f"[YARA] ✓ Loaded: {fname}")
        except yara.SyntaxError as e:
            print(f"[YARA] ✗ Skipped {fname} — syntax error: {e}")
        except Exception as e:
            print(f"[YARA] ✗ Skipped {fname} — error: {e}")

    if not rule_files:
        print("[YARA] No valid rule files found")
        return None

    try:
        compiled = yara.compile(filepaths=rule_files)
        print(f"[YARA] Compiled {len(rule_files)} rule file(s) OK")
        return compiled
    except Exception as e:
        print(f"[YARA] Final compile error: {e}")
        return None


# ── Local sample cache ────────────────────────────────────────────
def find_local_sample(sha256: str):
    if not os.path.exists(SAMPLES_DIR):
        return None
    for fname in os.listdir(SAMPLES_DIR):
        fpath = os.path.join(SAMPLES_DIR, fname)
        if sha256[:16].lower() in fname.lower():
            with open(fpath, "rb") as f:
                data = f.read()
            print(f"[YARA] Found local sample by hash: {fname} ({len(data)} bytes)")
            return data
    for fname in os.listdir(SAMPLES_DIR):
        if fname.endswith((".elf", ".bin", ".sample")):
            fpath = os.path.join(SAMPLES_DIR, fname)
            with open(fpath, "rb") as f:
                data = f.read()
            print(f"[YARA] Found local sample: {fname} ({len(data)} bytes)")
            return data
    return None


# ── Download from Bazaar (pyzipper handles AES zip) ───────────────
def download_sample(sha256: str):
    if not BAZAAR_KEY:
        print("[YARA] No API key")
        return None

    try:
        import pyzipper
    except ImportError:
        print("[YARA] pyzipper not installed — run: pip install pyzipper")
        return None

    try:
        print("[YARA] Downloading from MalwareBazaar...")
        resp = requests.post(
            BAZAAR_URL,
            data={"query": "get_file", "sha256_hash": sha256},
            headers={"Auth-Key": BAZAAR_KEY, "User-Agent": "MalDNA-Engine/0.1"},
            timeout=30,
        )

        if resp.status_code != 200 or not resp.content:
            print(f"[YARA] HTTP {resp.status_code} — download failed")
            return None

        # Try pyzipper first (handles AES-256 encrypted zips from Bazaar)
        try:
            with pyzipper.AESZipFile(io.BytesIO(resp.content)) as zf:
                zf.setpassword(b"infected")
                for name in zf.namelist():
                    if not name.endswith(".zip"):
                        data = zf.read(name)
                        print(f"[YARA] Extracted {len(data)} bytes via pyzipper ({name})")
                        _cache_sample(sha256, data)
                        return data
        except Exception as e1:
            print(f"[YARA] pyzipper failed: {e1} — trying standard zipfile...")
            # Fallback to standard zipfile
            try:
                import zipfile
                with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                    for name in zf.namelist():
                        if not name.endswith(".zip"):
                            data = zf.read(name, pwd=b"infected")
                            print(f"[YARA] Extracted {len(data)} bytes via zipfile ({name})")
                            _cache_sample(sha256, data)
                            return data
            except Exception as e2:
                print(f"[YARA] zipfile also failed: {e2}")
                return None

    except Exception as e:
        print(f"[YARA] Download error: {e}")
        return None


def _cache_sample(sha256: str, data: bytes):
    try:
        os.makedirs(SAMPLES_DIR, exist_ok=True)
        path = os.path.join(SAMPLES_DIR, f"{sha256[:16]}.elf")
        with open(path, "wb") as f:
            f.write(data)
        print(f"[YARA] Cached sample → {path}")
    except Exception as e:
        print(f"[YARA] Cache write failed: {e}")


# ── Format matches ────────────────────────────────────────────────
def format_matches(matches: list) -> list:
    results = []
    for m in matches:
        meta = m.meta or {}
        matched_strings = []
        for s in m.strings:
            for inst in s.instances:
                matched_strings.append({
                    "identifier": s.identifier,
                    "offset":     inst.offset,
                    "data":       repr(inst.matched_data[:60]),
                })
        results.append({
            "rule":            m.rule,
            "namespace":       m.namespace,
            "family":          meta.get("family", m.namespace),
            "type":            meta.get("type", "Unknown"),
            "severity":        meta.get("severity", "UNKNOWN"),
            "description":     meta.get("description", ""),
            "threat_actor":    meta.get("threat_actor", "Unknown"),
            "mitre_attack":    meta.get("mitre_attack", ""),
            "reference":       meta.get("reference", ""),
            "tags":            list(m.tags),
            "matched_strings": matched_strings[:10],
        })
    results.sort(key=lambda x: SEVERITY_RANK.get(x["severity"], 0), reverse=True)
    return results


# ── Main entry ────────────────────────────────────────────────────
def run_yara_scan(sha256: str = None, file_bytes: bytes = None) -> dict:
    compiled = load_all_rules()
    rules_loaded = sum(1 for f in os.listdir(RULES_DIR) if f.endswith(".yar")) if os.path.exists(RULES_DIR) else 0

    if not compiled:
        return {
            "status": "error",
            "message": f"Could not load YARA rules from {RULES_DIR}",
            "matches": [], "match_count": 0, "rules_loaded": rules_loaded,
        }

    data, scan_mode, source = None, "unknown", "unknown"

    if file_bytes:
        data, scan_mode, source = file_bytes, "file_upload", "file_upload"

    elif sha256:
        scan_mode = "hash_download"
        data = find_local_sample(sha256)
        if data:
            source = "local_cache"
        if data is None:
            data = download_sample(sha256)
            if data:
                source = "bazaar_download"
        if data is None:
            return {
                "status":       "no_sample",
                "message":      (
                    "Sample binary unavailable for YARA scan. "
                    "Fix: pip install pyzipper then retry, OR manually download from "
                    f"https://bazaar.abuse.ch/sample/{sha256}/ "
                    "(password: infected), unzip, place ELF in backend/data/samples/"
                ),
                "matches":      [],
                "match_count":  0,
                "rules_loaded": rules_loaded,
                "scan_mode":    scan_mode,
                "fallback":     True,
                "download_url": f"https://bazaar.abuse.ch/sample/{sha256}/",
            }
    else:
        return {"status": "error", "message": "No sha256 or file_bytes provided", "matches": [], "match_count": 0}

    # Scan
    try:
        raw_matches = compiled.match(data=data)
    except Exception as e:
        return {"status": "error", "message": f"Scan error: {e}", "matches": [], "match_count": 0}

    formatted = format_matches(raw_matches)
    print(f"[YARA] Scan complete — {len(formatted)} match(es) from {source}")

    if not formatted:
        return {
            "status": "no_match", "message": "No YARA rules matched this sample",
            "matches": [], "match_count": 0,
            "rules_loaded": rules_loaded, "scan_mode": scan_mode,
            "sample_size": len(data), "source": source,
        }

    top = formatted[0]
    return {
        "status":       "matched",
        "message":      f"Matched {len(formatted)} YARA rule(s) — source: {source}",
        "matches":      formatted,
        "match_count":  len(formatted),
        "top_family":   top["family"],
        "top_severity": top["severity"],
        "top_rule":     top["rule"],
        "rules_loaded": rules_loaded,
        "scan_mode":    scan_mode,
        "sample_size":  len(data),
        "source":       source,
    }