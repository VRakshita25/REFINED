"""
modules/bazaar.py — MalDNA Step 2
MalwareBazaar API wrapper with Auth-Key header (required 2025)
Get free key: https://auth.abuse.ch/
Add to backend/.env: MALWAREBAZAAR_API_KEY=yourkey
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
BAZAAR_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "")


def lookup_hash(hash_value: str) -> dict:
    hash_value = hash_value.strip().lower()

    if not BAZAAR_KEY:
        return {
            "status":   "error",
            "message":  "MALWAREBAZAAR_API_KEY not set. Get a free key at https://auth.abuse.ch/ then add to backend/.env",
            "metadata": {}
        }

    try:
        response = requests.post(
            BAZAAR_URL,
            data={"query": "get_info", "hash": hash_value},
            headers={"Auth-Key": BAZAAR_KEY, "User-Agent": "MalDNA-Engine/0.1"},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()

    except requests.exceptions.Timeout:
        return {"status": "error", "message": "MalwareBazaar request timed out", "metadata": {}}
    except requests.exceptions.HTTPError as e:
        return {"status": "error", "message": f"HTTP {response.status_code}: Check your Auth-Key in backend/.env — {str(e)}", "metadata": {}}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": f"Network error: {str(e)}", "metadata": {}}
    except ValueError:
        return {"status": "error", "message": "Invalid JSON from MalwareBazaar", "metadata": {}}

    query_status = data.get("query_status", "")

    if query_status == "hash_not_found":
        return {"status": "not_found", "message": f"Hash '{hash_value}' not in MalwareBazaar database", "metadata": {}}

    if query_status != "ok" or not data.get("data"):
        return {"status": "error", "message": f"Unexpected Bazaar status: {query_status}", "metadata": {}}

    sample = data["data"][0]
    return {"status": "found", "message": "Sample found in MalwareBazaar", "metadata": extract_metadata(sample), "raw": sample}


def extract_metadata(sample: dict) -> dict:
    vendor_intel  = sample.get("vendor_intel", {}) or {}
    av_detections = []
    for engine, result in vendor_intel.items():
        if isinstance(result, dict) and result.get("detection"):
            av_detections.append({"engine": engine, "detection": result["detection"], "result": result.get("result", "")})

    tags  = sample.get("tags", []) or []
    intel = sample.get("intelligence", {}) or {}

    return {
        "sha256":          sample.get("sha256_hash", ""),
        "sha1":            sample.get("sha1_hash", ""),
        "md5":             sample.get("md5_hash", ""),
        "ssdeep":          sample.get("ssdeep", ""),
        "tlsh":            sample.get("tlsh", ""),
        "imphash":         sample.get("imphash", ""),
        "file_name":       sample.get("file_name", "unknown"),
        "file_size_bytes": sample.get("file_size", 0),
        "file_type":       sample.get("file_type", ""),
        "mime_type":       sample.get("file_type_mime", ""),
        "signature":       sample.get("signature", ""),
        "tags":            tags,
        "reporter":        sample.get("reporter", ""),
        "origin_country":  sample.get("origin_country", ""),
        "first_seen":      sample.get("first_seen", ""),
        "last_seen":       sample.get("last_seen", ""),
        "av_detections":      av_detections,
        "av_detection_count": len(av_detections),
        "downloads":       intel.get("downloads", 0),
        "uploads":         intel.get("uploads", 0),
    }


def detect_hash_type(hash_value: str) -> str:
    h = hash_value.strip()
    if len(h) == 64: return "sha256"
    if len(h) == 40: return "sha1"
    if len(h) == 32: return "md5"
    return "unknown"