"""
modules/yara_engine.py — MalDNA Step 3
Fixed for Python 3.11 on Windows + robust rule loading with per-file error reporting
"""

import os
import io
import zipfile
import requests
import yara
from dotenv import load_dotenv

load_dotenv()

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR  = os.path.join(BASE_DIR, "data", "rules")
BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
BAZAAR_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "")

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


# ── Rule loader ───────────────────────────────────────────────────
def load_all_rules():
    """
    Compile all .yar files from data/rules/.
    Tests each file individually first so bad rules don't block good ones.
    Returns compiled Rules object or None.
    """
    print(f"[YARA] RULES_DIR = {RULES_DIR}")
    print(f"[YARA] Exists    = {os.path.exists(RULES_DIR)}")

    if not os.path.exists(RULES_DIR):
        print(f"[YARA] ERROR: Rules directory not found: {RULES_DIR}")
        return None

    rule_files = {}
    for fname in os.listdir(RULES_DIR):
        if not fname.endswith(".yar"):
            continue
        fpath = os.path.join(RULES_DIR, fname)
        namespace = fname.replace(".yar", "")

        # Test compile each file individually — skip bad ones
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
        print(f"[YARA] Compiled {len(rule_files)} rule file(s) successfully")
        return compiled
    except Exception as e:
        print(f"[YARA] Final compile error: {e}")
        return None


# ── Download sample from Bazaar ───────────────────────────────────
def download_sample(sha256: str):
    if not BAZAAR_KEY:
        print("[YARA] No API key — cannot download sample")
        return None
    try:
        print(f"[YARA] Downloading sample from MalwareBazaar...")
        resp = requests.post(
            BAZAAR_URL,
            data={"query": "get_file", "sha256_hash": sha256},
            headers={"Auth-Key": BAZAAR_KEY, "User-Agent": "MalDNA-Engine/0.1"},
            timeout=30,
        )
        if resp.status_code == 200 and resp.content:
            try:
                zf = zipfile.ZipFile(io.BytesIO(resp.content))
                for name in zf.namelist():
                    if not name.endswith(".zip"):
                        data = zf.read(name, pwd=b"infected")
                        print(f"[YARA] Downloaded {len(data)} bytes ({name})")
                        return data
            except zipfile.BadZipFile:
                print(f"[YARA] Response is not a zip (status {resp.status_code}) — download may be restricted")
                return None
        print(f"[YARA] Download failed — HTTP {resp.status_code}")
        return None
    except Exception as e:
        print(f"[YARA] Download error: {e}")
        return None


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


# ── Main entry point ──────────────────────────────────────────────
def run_yara_scan(sha256: str = None, file_bytes: bytes = None) -> dict:
    compiled = load_all_rules()

    rules_loaded = 0
    if os.path.exists(RULES_DIR):
        rules_loaded = sum(1 for f in os.listdir(RULES_DIR) if f.endswith(".yar"))

    if not compiled:
        return {
            "status":       "error",
            "message":      f"Could not load YARA rules from {RULES_DIR}",
            "matches":      [],
            "match_count":  0,
            "rules_loaded": rules_loaded,
        }

    # Get bytes to scan
    if file_bytes:
        data, scan_mode = file_bytes, "file_upload"

    elif sha256:
        scan_mode = "hash_download"
        data = download_sample(sha256)
        if data is None:
            return {
                "status":       "no_sample",
                "message":      "Sample download from Bazaar failed — YARA skipped. "
                                "Bazaar restricts downloads for some account tiers. "
                                "Bazaar signature used as family fallback.",
                "matches":      [],
                "match_count":  0,
                "rules_loaded": rules_loaded,
                "scan_mode":    scan_mode,
                "fallback":     True,
            }
    else:
        return {"status": "error", "message": "No sha256 or file_bytes provided", "matches": [], "match_count": 0}

    # Scan
    try:
        raw_matches = compiled.match(data=data)
    except Exception as e:
        return {"status": "error", "message": f"Scan error: {e}", "matches": [], "match_count": 0}

    formatted = format_matches(raw_matches)

    if not formatted:
        return {
            "status":       "no_match",
            "message":      "No YARA rules matched this sample",
            "matches":      [],
            "match_count":  0,
            "rules_loaded": rules_loaded,
            "scan_mode":    scan_mode,
            "sample_size":  len(data),
        }

    top = formatted[0]
    return {
        "status":       "matched",
        "message":      f"Matched {len(formatted)} YARA rule(s)",
        "matches":      formatted,
        "match_count":  len(formatted),
        "top_family":   top["family"],
        "top_severity": top["severity"],
        "top_rule":     top["rule"],
        "rules_loaded": rules_loaded,
        "scan_mode":    scan_mode,
        "sample_size":  len(data),
    }