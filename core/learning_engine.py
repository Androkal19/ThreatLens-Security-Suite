"""
ThreatLens - Learning Engine
Auto-trains local threat intelligence database using external scan results.
"""

import json
from pathlib import Path


class LearningEngine:
    """
    Maintains a local threat intelligence database.
    Learns from highly-detected malware to flag future instances locally.
    """

    def __init__(self):
        self.db_path = Path(__file__).parent.parent / "signatures" / "local_threat_intel.json"
        self._ensure_db_exists()
        self.intel = self._load_db()

    def _ensure_db_exists(self):
        """Create the database file if it doesn't exist."""
        if not self.db_path.parent.exists():
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.db_path.exists():
            self._save_db({
                "malicious_hashes": [],
                "malicious_urls": [],
                "malicious_domains": [],
                "malicious_ips": []
            })

    def _load_db(self):
        """Load the database from disk."""
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"malicious_hashes": [], "malicious_urls": [], "malicious_domains": [], "malicious_ips": []}

    def _save_db(self, data=None):
        """Save the database to disk."""
        if data is None:
            data = self.intel
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    def learn_from_scan(self, analysis_results, vt_results):
        """
        Learn from a scan if VirusTotal says it is malicious.
        Extracts hashes and network indicators to the local DB.
        """
        if not vt_results or vt_results.get("status") != "found":
            return False

        # Only learn if detection count is high (e.g., >= 3) to avoid false positives
        detections = vt_results.get("malicious_count", 0) + vt_results.get("suspicious_count", 0)
        if detections < 3:
            return False

        learned_new = False
        
        # Learn Hash
        file_hash = vt_results.get("hash")
        if file_hash and file_hash not in self.intel.get("malicious_hashes", []):
            self.intel.setdefault("malicious_hashes", []).append(file_hash)
            learned_new = True

        # Learn Network Indicators (IPs, URLs, Domains)
        network = analysis_results.get("network", [])
        for net in network:
            val = net.get("value")
            ntype = net.get("type")
            if not val:
                continue
                
            if ntype == "URL" and val not in self.intel.get("malicious_urls", []):
                self.intel.setdefault("malicious_urls", []).append(val)
                learned_new = True
            elif ntype == "Domain" and val not in self.intel.get("malicious_domains", []):
                self.intel.setdefault("malicious_domains", []).append(val)
                learned_new = True
            elif ntype == "IPv4" and val not in self.intel.get("malicious_ips", []):
                self.intel.setdefault("malicious_ips", []).append(val)
                learned_new = True

        if learned_new:
            self._save_db()
            
        return learned_new

    def check_local_intel(self, file_hash, analysis_results):
        """
        Check if current file matches known local intel.
        Returns a list of match dictionaries.
        """
        hits = []
        
        # Check Hash
        if file_hash in self.intel.get("malicious_hashes", []):
            hits.append({"type": "Hash", "value": file_hash, "threat": "Known malicious file hash"})

        # Check Network Indicators
        network = analysis_results.get("network", [])
        for net in network:
            val = net.get("value")
            ntype = net.get("type")
            if not val:
                continue
                
            if ntype == "URL" and val in self.intel.get("malicious_urls", []):
                hits.append({"type": "URL", "value": val, "threat": "Known malicious C2 URL"})
            elif ntype == "Domain" and val in self.intel.get("malicious_domains", []):
                hits.append({"type": "Domain", "value": val, "threat": "Known malicious C2 Domain"})
            elif ntype == "IPv4" and val in self.intel.get("malicious_ips", []):
                hits.append({"type": "IPv4", "value": val, "threat": "Known malicious IP Address"})
        return hits

    def import_custom_db(self, file_path):
        """
        Merge a custom JSON threat intelligence database into the local DB.
        Expected format matches the local_threat_intel.json structure.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                custom_db = json.load(f)
        except Exception as e:
            return False, f"Failed to load custom DB: {e}"

        imported_count = 0
        for category in ["malicious_hashes", "malicious_urls", "malicious_domains", "malicious_ips"]:
            if category in custom_db and isinstance(custom_db[category], list):
                for item in custom_db[category]:
                    if item not in self.intel.get(category, []):
                        self.intel.setdefault(category, []).append(item)
                        imported_count += 1
        
        if imported_count > 0:
            self._save_db()
            
        return True, f"Successfully imported {imported_count} new indicators from {Path(file_path).name}"
