"""
app.py — MalDNA Flask API
Step 3: Bazaar + YARA fully integrated
Run: python app.py
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from modules.bazaar      import lookup_hash, detect_hash_type
from modules.yara_engine import run_yara_scan

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ── Health ────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online", "engine": "MalDNA v0.1", "step": 3,
        "modules": {
            "bazaar_lookup":   True,
            "yara_engine":     True,
            "fuzzy_hash":      False,
            "feature_builder": False,
            "similarity":      False,
            "confidence":      False,
            "threat_mapper":   False,
            "mitre_mapper":    False,
            "containment":     False,
        }
    })

# ── Demo samples — REPLACE sha256 values with real ones ──────────
DEMO_SAMPLES = {
    "mirai":  {"sha256": "dc4c4501e56d73d40a8e5fb00f4e0ad74335e2aa8c588373509438af312b1450", "family": "Mirai",  "type": "Botnet",     "arch": "MIPS"},
    "mozi":   {"sha256": "22ea54360f7b59f926660f70b05b11f6b00bc1519b5114df06176d0c53003e24", "family": "Mozi",   "type": "P2P Botnet", "arch": "ARM"},
    "gafgyt": {"sha256": "76847058eeedd24ced98caf9803b6f5eb68ce7476b89d05c54c630fe60c65c8a", "family": "Gafgyt", "type": "DDoS Bot",   "arch": "x86"},
}

@app.route("/api/sample-hashes", methods=["GET"])
def sample_hashes():
    return jsonify({"status": "ok", "samples": DEMO_SAMPLES})

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

    # ── Step 2: MalwareBazaar ────────────────────────────────────
    print("[MalDNA] Step 2: Bazaar lookup...")
    bazaar_result = lookup_hash(hash_val)

    # ── Step 3: YARA ─────────────────────────────────────────────
    print("[MalDNA] Step 3: YARA scan...")
    if hash_type == "sha256":
        yara_result = run_yara_scan(sha256=hash_val)
    else:
        yara_result = {
            "status":  "skipped",
            "message": "YARA binary download requires SHA256. Provide SHA256 to enable YARA scanning.",
            "matches": [], "match_count": 0,
        }

    # ── Family verdict: YARA > Bazaar > Unknown ──────────────────
    family, family_source = "Unknown", "none"
    if yara_result.get("status") == "matched" and yara_result.get("top_family"):
        family, family_source = yara_result["top_family"], "yara"
    elif bazaar_result.get("status") == "found":
        sig = bazaar_result.get("metadata", {}).get("signature", "")
        if sig: family, family_source = sig, "bazaar_signature"

    # ── Summary ──────────────────────────────────────────────────
    meta = bazaar_result.get("metadata", {})
    summary = {
        "family":        family,
        "family_source": family_source,
        "file_name":     meta.get("file_name", "unknown"),
        "file_type":     meta.get("file_type", ""),
        "tags":          meta.get("tags", []),
        "first_seen":    meta.get("first_seen", ""),
        "av_hits":       meta.get("av_detection_count", 0),
        "ssdeep":        meta.get("ssdeep", ""),
        "yara_hits":     yara_result.get("match_count", 0),
        "top_severity":  yara_result.get("top_severity", "UNKNOWN"),
    } if bazaar_result.get("status") == "found" else {
        "family": "Unknown", "message": "Hash not in MalwareBazaar"
    }

    return jsonify({
        "status":  "ok",
        "summary": summary,
        "pipeline": {
            "step_1_input": {
                "status": "complete", "hash": hash_val, "hash_type": hash_type, "mode": mode,
            },
            "step_2_bazaar": {
                "status":   bazaar_result["status"],
                "message":  bazaar_result.get("message", ""),
                "metadata": meta,
            },
            "step_3_yara": {
                "status":       yara_result["status"],
                "message":      yara_result.get("message", ""),
                "match_count":  yara_result.get("match_count", 0),
                "matches":      yara_result.get("matches", []),
                "top_family":   yara_result.get("top_family", ""),
                "top_severity": yara_result.get("top_severity", ""),
                "top_rule":     yara_result.get("top_rule", ""),
                "rules_loaded": yara_result.get("rules_loaded", 0),
                "scan_mode":    yara_result.get("scan_mode", ""),
                "sample_size":  yara_result.get("sample_size", 0),
                "fallback":     yara_result.get("fallback", False),
            },
            "step_4_fuzzy_hash": {"status": "pending"},
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
    print("  MalDNA Engine — Step 3 (YARA)")
    print("  http://localhost:5000")
    print("="*50)
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)