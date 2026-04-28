"""
ThreatLens - VirusTotal Integration
Hash-based file reputation lookup via VirusTotal API v3.
"""

import json
import time
from pathlib import Path


# VirusTotal API v3 endpoint
VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"


def load_api_key():
    """
    Load the VirusTotal API key from config.json.
    
    Returns:
        str or None: The API key, or None if not configured.
    """
    config_path = Path(__file__).parent.parent / "config.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        key = config.get("virustotal_api_key", "")
        enabled = config.get("vt_enabled", True)
        if key and enabled:
            return key
    except Exception:
        pass
    return None


def lookup_hash(file_hash, api_key=None):
    """
    Look up a file hash on VirusTotal.
    
    Args:
        file_hash: SHA256 hash of the file.
        api_key: VT API key (if None, loads from config).
        
    Returns:
        dict: VT results with detection stats, or error info.
    """
    if not api_key:
        api_key = load_api_key()
    
    if not api_key:
        return {"status": "skipped", "reason": "No VirusTotal API key configured"}
    
    try:
        import requests
    except ImportError:
        return {"status": "error", "reason": "requests library not installed (pip install requests)"}
    
    url = VT_API_URL.format(hash=file_hash)
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            return _parse_vt_response(response.json())
        elif response.status_code == 404:
            return {
                "status": "not_found",
                "reason": "File hash not found in VirusTotal database",
                "hash": file_hash,
                "detections": 0,
                "total_engines": 0,
                "detection_rate": "0/0",
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            }
        elif response.status_code == 401:
            return {"status": "error", "reason": "Invalid VirusTotal API key"}
        elif response.status_code == 429:
            return {"status": "error", "reason": "VirusTotal API rate limit exceeded. Wait 60 seconds."}
        else:
            return {"status": "error", "reason": f"VT API returned HTTP {response.status_code}"}
            
    except requests.exceptions.Timeout:
        return {"status": "error", "reason": "VirusTotal API request timed out (30s)"}
    except requests.exceptions.ConnectionError:
        return {"status": "error", "reason": "Cannot connect to VirusTotal (check internet connection)"}
    except Exception as e:
        return {"status": "error", "reason": f"VirusTotal lookup failed: {str(e)}"}


def _parse_vt_response(data):
    """
    Parse the VirusTotal API v3 response into a clean result dict.
    
    Args:
        data: Raw JSON response from VT API.
        
    Returns:
        dict: Parsed results.
    """
    try:
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + undetected + harmless
        
        # Collect which engines detected it
        detections = []
        for engine_name, engine_result in results.items():
            if engine_result.get("category") in ("malicious", "suspicious"):
                detections.append({
                    "engine": engine_name,
                    "result": engine_result.get("result", "Unknown"),
                    "category": engine_result.get("category", ""),
                })
        
        # Sort detections alphabetically by engine name
        detections.sort(key=lambda x: x["engine"])
        
        # Determine severity based on detection ratio
        detection_count = malicious + suspicious
        if total > 0:
            ratio = detection_count / total
        else:
            ratio = 0
            
        if ratio >= 0.5:
            vt_severity = "CRITICAL"
        elif ratio >= 0.25:
            vt_severity = "HIGH"
        elif ratio >= 0.1:
            vt_severity = "MEDIUM"
        elif detection_count > 0:
            vt_severity = "LOW"
        else:
            vt_severity = "CLEAN"
        
        # File metadata from VT
        file_info = {
            "type_description": attributes.get("type_description", "Unknown"),
            "type_tag": attributes.get("type_tag", ""),
            "size": attributes.get("size", 0),
            "first_seen": attributes.get("first_submission_date", ""),
            "last_seen": attributes.get("last_analysis_date", ""),
            "times_submitted": attributes.get("times_submitted", 0),
            "reputation": attributes.get("reputation", 0),
        }
        
        # Popular threat label
        popular = attributes.get("popular_threat_classification", {})
        threat_label = ""
        if popular:
            suggested = popular.get("suggested_threat_label", "")
            if suggested:
                threat_label = suggested
        
        # Tags
        tags = attributes.get("tags", [])
        
        sha256 = attributes.get("sha256", "")
        
        return {
            "status": "found",
            "hash": sha256,
            "detection_count": detection_count,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "undetected_count": undetected,
            "harmless_count": harmless,
            "total_engines": total,
            "detection_rate": f"{detection_count}/{total}",
            "detection_ratio": round(ratio * 100, 1),
            "severity": vt_severity,
            "threat_label": threat_label,
            "detections": detections[:30],  # Top 30 detections
            "file_info": file_info,
            "tags": tags[:10],
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }
        
    except Exception as e:
        return {"status": "error", "reason": f"Error parsing VT response: {str(e)}"}


def get_vt_score_contribution(vt_result):
    """
    Calculate threat score contribution from VirusTotal results.
    
    Args:
        vt_result: dict from lookup_hash().
        
    Returns:
        int: Score contribution (0-35).
    """
    if vt_result.get("status") != "found":
        return 0
    
    ratio = vt_result.get("detection_ratio", 0)
    
    if ratio >= 50:
        return 35
    elif ratio >= 25:
        return 25
    elif ratio >= 10:
        return 15
    elif ratio > 0:
        return 8
    return 0
