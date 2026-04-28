"""
ThreatLens - Report Generator
Generates structured JSON and console-formatted analysis reports.
"""

import json
import datetime
from pathlib import Path

from utils.platform_utils import get_reports_dir


def generate_json_report(analysis_results, file_info, threat_score, severity, breakdown, file_type):
    """
    Generate a comprehensive JSON report and save it to disk.
    
    Args:
        analysis_results: dict from analyzer.
        file_info: dict with file metadata and hashes.
        threat_score: int threat score (0-100).
        severity: str severity level.
        breakdown: dict score breakdown.
        file_type: str "APK" or "EXE".
        
    Returns:
        str: Path to the saved report file.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = file_info.get("filename", "unknown").replace(".", "_")

    report = {
        "tool": "ThreatLens",
        "version": "1.0.0",
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "file_info": {
            "filename": file_info.get("filename", ""),
            "filepath": file_info.get("filepath", ""),
            "size_bytes": file_info.get("size_bytes", 0),
            "file_type": file_type,
            "hashes": file_info.get("hashes", {}),
        },
        "threat_assessment": {
            "score": threat_score,
            "severity": severity,
            "breakdown": breakdown,
        },
        "analysis": analysis_results,
    }

    # Remove non-serializable items
    report = _make_serializable(report)

    # Save report
    reports_dir = get_reports_dir()
    report_path = reports_dir / f"threatlens_{filename}_{timestamp}.json"

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    return str(report_path)


def generate_summary(analysis_results, file_type):
    """
    Generate a summary dict for the summary table.
    
    Args:
        analysis_results: dict from analyzer.
        file_type: str "APK" or "EXE".
        
    Returns:
        dict: Summary data for the summary table.
    """
    summary = {}

    if file_type == "APK":
        perms = analysis_results.get("permissions", [])
        perm_risks = [p.get("risk", "INFO") for p in perms if p.get("risk") != "INFO"]
        summary["Permissions"] = {
            "count": len(perms),
            "highest_risk": _highest_risk(perm_risks),
        }

        combos = analysis_results.get("permission_combinations", [])
        summary["Permission Combos"] = {
            "count": len(combos),
            "highest_risk": "CRITICAL" if combos else "CLEAN",
        }

    elif file_type == "EXE":
        imports = analysis_results.get("suspicious_imports", [])
        import_risks = [i.get("risk", "LOW") for i in imports]
        summary["Suspicious Imports"] = {
            "count": len(imports),
            "highest_risk": _highest_risk(import_risks),
        }

        combos = analysis_results.get("import_combinations", [])
        summary["Import Combos (MITRE)"] = {
            "count": len(combos),
            "highest_risk": "CRITICAL" if combos else "CLEAN",
        }

        entropy = analysis_results.get("entropy", {})
        summary["Entropy/Packing"] = {
            "count": entropy.get("high_entropy_sections", 0),
            "highest_risk": "HIGH" if entropy.get("max_entropy", 0) > 7.0 else "CLEAN",
        }

    # Common sections
    network = analysis_results.get("network", [])
    summary["Network Indicators"] = {
        "count": len(network),
        "highest_risk": "CRITICAL" if any(n.get("confidence", 0) >= 80 for n in network)
                        else "HIGH" if network else "CLEAN",
    }

    yara = analysis_results.get("yara", [])
    yara_risks = [y.get("severity", "MEDIUM") for y in yara]
    summary["YARA Matches"] = {
        "count": len(yara),
        "highest_risk": _highest_risk(yara_risks),
    }

    strings = analysis_results.get("suspicious_strings", [])
    summary["Suspicious Strings"] = {
        "count": len(strings),
        "highest_risk": "MEDIUM" if strings else "CLEAN",
    }

    return summary


def _highest_risk(risks):
    """Get the highest risk level from a list."""
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "CLEAN": 0}
    if not risks:
        return "CLEAN"
    return max(risks, key=lambda r: order.get(r, 0))


def _make_serializable(obj):
    """Make an object JSON-serializable by converting non-serializable types."""
    if isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_make_serializable(i) for i in obj]
    elif isinstance(obj, Path):
        return str(obj)
    elif isinstance(obj, bytes):
        return obj.hex()
    elif isinstance(obj, set):
        return list(obj)
    return obj
