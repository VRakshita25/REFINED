"""
app.py — MalDNA Flask API  Step 4
New: /api/fuzzy-file — upload ANY ELF, get ssdeep computed live + family detection
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from modules.bazaar      import lookup_hash, detect_hash_type
from modules.yara_engine import run_yara_scan
from modules.fuzzy_hash  import run_fuzzy_hash

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online", "engine": "MalDNA v0.1", "step": 4,
        "modules": {
            "bazaar_lookup": True, "yara_engine": True, "fuzzy_hash": True,
            "fuzzy_file_upload": True, "feature_builder": False,
        }
    })

DEMO_SAMPLES = {
    "mirai":  {"sha256": "dc4c4501e56d73d40a8e5fb00f4e0ad74335e2aa8c588373509438af312b1450", "family": "Mirai",  "type": "Botnet",     "arch": "MIPS"},
    "mozi":   {"sha256": "22ea54360f7b59f926660f70b05b11f6b00bc1519b5114df06176d0c53003e24", "family": "Mozi",   "type": "P2P Botnet", "arch": "ARM"},
    "gafgyt": {"sha256": "76847058eeedd24ced98caf9803b6f5eb68ce7476b89d05c54c630fe60c65c8a", "family": "Gafgyt", "type": "DDoS Bot",   "arch": "x86"},
}

@app.route("/api/sample-hashes", methods=["GET"])
def sample_hashes():
    return jsonify({"status": "ok", "samples": DEMO_SAMPLES})

# ── NEW: Upload ANY binary → compute ssdeep live → detect family ───
@app.route("/api/fuzzy-file", methods=["POST"])
def fuzzy_file():
    """
    Judge drops any ELF file here.
    We compute its ssdeep on the fly and run fuzzy detection.
    No SHA256 lookup. No pre-seeded hashes. Pure algorithm.
    """
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"}), 400

    f    = request.files['file']
    data = f.read()

    if len(data) < 64:
        return jsonify({"status": "error", "message": "File too small"}), 400

    import hashlib
    sha256   = hashlib.sha256(data).hexdigest()
    filesize = len(data)
    is_elf   = data[:4] == b'\x7fELF'

    print(f"[FuzzyFile] Received: {f.filename} ({filesize} bytes) SHA256: {sha256[:16]}... ELF: {is_elf}")

    # Compute ssdeep using pydeep
    computed_ssdeep = ""
    ssdeep_method   = ""
    try:
        import pydeep
        # Try all known pydeep API variants
        for method_name in ['hash_bytes', 'hash', 'Hash']:
            fn = getattr(pydeep, method_name, None)
            if fn:
                try:
                    result = fn(data)
                    computed_ssdeep = result.decode() if isinstance(result, bytes) else result
                    ssdeep_method   = f"pydeep.{method_name}"
                    break
                except Exception:
                    continue
    except ImportError:
        pass

    # Fallback: system ssdeep binary
    if not computed_ssdeep:
        import tempfile, subprocess, os
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.elf') as tf:
                tf.write(data)
                tmp = tf.name
            out = subprocess.check_output(['ssdeep', '-b', tmp], text=True, timeout=10)
            for line in out.splitlines():
                if ':' in line and not line.startswith('ssdeep'):
                    computed_ssdeep = line.split(',')[0].strip()
                    ssdeep_method   = "system_binary"
                    break
            os.unlink(tmp)
        except Exception as e:
            print(f"[FuzzyFile] ssdeep binary failed: {e}")

    if not computed_ssdeep:
        return jsonify({
            "status":  "error",
            "message": "Could not compute ssdeep hash — pydeep and system ssdeep both failed",
            "sha256":  sha256,
        }), 500

    print(f"[FuzzyFile] ssdeep ({ssdeep_method}): {computed_ssdeep[:50]}...")

    # Run fuzzy detection — NO SHA256 passed so no DB shortcut
    fuzzy_result = run_fuzzy_hash(ssdeep_hash=computed_ssdeep, sha256="")

    return jsonify({
        "status":         "ok",
        "filename":       f.filename,
        "filesize":       filesize,
        "sha256":         sha256,
        "is_elf":         is_elf,
        "computed_ssdeep": computed_ssdeep,
        "ssdeep_method":  ssdeep_method,
        "fuzzy":          fuzzy_result,
    })

# ── Direct ssdeep string test (for presets) ───────────────────────
@app.route("/api/fuzzy-test", methods=["POST"])
def fuzzy_test():
    body       = request.get_json(silent=True) or {}
    ssdeep_str = (body.get("ssdeep") or "").strip()
    label      = body.get("label", "Unknown sample")
    if not ssdeep_str:
        return jsonify({"status": "error", "message": "No ssdeep provided"}), 400
    result = run_fuzzy_hash(ssdeep_hash=ssdeep_str, sha256="")
    return jsonify({"status": "ok", "label": label, "input_ssdeep": ssdeep_str, "fuzzy": result})

# ── Main analysis ─────────────────────────────────────────────────
@app.route("/api/analyze", methods=["POST"])
def analyze():
    body     = request.get_json(silent=True) or {}
    mode     = body.get("mode", "hash")
    hash_val = (body.get("hash") or "").strip()
    if not hash_val:
        return jsonify({"status": "error", "message": "No hash provided"}), 400
    hash_type = detect_hash_type(hash_val)
    if hash_type == "unknown":
        return jsonify({"status": "error", "message": f"Unrecognized hash length ({len(hash_val)} chars)"}), 400

    print(f"\n[MalDNA] ── Analysis ── {hash_type.upper()}: {hash_val[:20]}...")
    print("[MalDNA] Step 2: Bazaar lookup...")
    bazaar_result = lookup_hash(hash_val)

    print("[MalDNA] Step 3: YARA scan...")
    yara_result = run_yara_scan(sha256=hash_val) if hash_type == "sha256" else {
        "status": "skipped", "message": "YARA requires SHA256.",
        "matches": [], "match_count": 0, "rules_loaded": 0,
        "sample_size": 0, "scan_mode": "", "top_family": "",
        "top_rule": "", "top_severity": "UNKNOWN", "fallback": False,
    }

    print("[MalDNA] Step 4: Fuzzy hash comparison...")
    meta_for_fuzzy = bazaar_result.get("metadata", {})
    ssdeep_hash    = meta_for_fuzzy.get("ssdeep", "")
    sha256_val     = meta_for_fuzzy.get("sha256", hash_val if hash_type == "sha256" else "")
    fuzzy_result   = run_fuzzy_hash(ssdeep_hash=ssdeep_hash, sha256=sha256_val)

    family, family_source = "Unknown", "none"
    if yara_result.get("status") == "matched" and yara_result.get("top_family"):
        family, family_source = yara_result["top_family"], "yara"
    elif fuzzy_result.get("top_score", 0) >= 60 and fuzzy_result.get("top_family"):
        family, family_source = fuzzy_result["top_family"], "fuzzy_match"
    elif bazaar_result.get("status") == "found":
        sig = bazaar_result.get("metadata", {}).get("signature", "")
        if sig: family, family_source = sig, "bazaar_signature"

    meta = bazaar_result.get("metadata", {})
    summary = {
        "family": family, "family_source": family_source,
        "file_name": meta.get("file_name", "unknown"),
        "file_type": meta.get("file_type", ""),
        "tags": meta.get("tags", []),
        "first_seen": meta.get("first_seen", ""),
        "av_hits": meta.get("av_detection_count", 0),
        "ssdeep": meta.get("ssdeep", ""),
        "yara_hits": yara_result.get("match_count", 0),
        "fuzzy_score": fuzzy_result.get("top_score", 0),
        "fuzzy_variant": fuzzy_result.get("top_variant", ""),
        "top_severity": yara_result.get("top_severity", "UNKNOWN"),
    } if bazaar_result.get("status") == "found" else {
        "family": "Unknown", "message": "Hash not in MalwareBazaar"
    }

    return jsonify({
        "status": "ok", "summary": summary,
        "pipeline": {
            "step_1_input":      {"status": "complete", "hash": hash_val, "hash_type": hash_type, "mode": mode},
            "step_2_bazaar":     {"status": bazaar_result["status"], "message": bazaar_result.get("message",""), "metadata": meta},
            "step_3_yara":       {
                "status": yara_result["status"], "message": yara_result.get("message",""),
                "match_count": yara_result.get("match_count",0), "matches": yara_result.get("matches",[]),
                "top_family": yara_result.get("top_family",""), "top_severity": yara_result.get("top_severity",""),
                "top_rule": yara_result.get("top_rule",""), "rules_loaded": yara_result.get("rules_loaded",0),
                "scan_mode": yara_result.get("scan_mode",""), "sample_size": yara_result.get("sample_size",0),
                "fallback": yara_result.get("fallback",False),
            },
            "step_4_fuzzy_hash": {
                "status": fuzzy_result.get("status","error"),
                "message": fuzzy_result.get("message",""),
                "input_hash": fuzzy_result.get("input_hash",""),
                "top_score": fuzzy_result.get("top_score",0),
                "top_family": fuzzy_result.get("top_family",""),
                "top_variant": fuzzy_result.get("top_variant",""),
                "best_match": fuzzy_result.get("best_match"),
                "all_matches": fuzzy_result.get("all_matches",[]),
                "match_count": fuzzy_result.get("match_count",0),
                "metadata": fuzzy_result.get("metadata",{}),
            },
            "step_5_features":   {"status": "pending"},
            "step_6_similarity": {"status": "pending"},
            "step_7_confidence": {"status": "pending"},
            "step_8_threat_map": {"status": "pending"},
            "step_9_mitre":      {"status": "pending"},
            "step_10_contain":   {"status": "pending"},
        }
    })

if __name__ == "__main__":
    print("="*50)
    print("  MalDNA Engine — Step 4 (Fuzzy Hashing)")
    print("  http://localhost:5000")
    print("="*50)
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)