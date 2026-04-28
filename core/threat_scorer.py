"""
ThreatLens - Threat Scorer
Weighted risk scoring engine that aggregates findings into a 0-100 threat score.
"""


class ThreatScorer:
    """
    Calculates a weighted threat score from analysis findings.
    Score: 0-100
    Categories: CRITICAL (80-100), HIGH (60-79), MEDIUM (40-59), LOW (20-39), CLEAN (0-19)
    """

    # Maximum score caps per category (prevents single category from dominating)
    CATEGORY_CAPS = {
        "permissions": 30,
        "imports": 35,
        "network_indicators": 30,
        "entropy": 25,
        "yara_matches": 35,
        "strings": 20,
        "certificate": 15,
        "manifest": 15,
        "combinations": 25,
        "heuristics": 40,
        "virustotal": 35,
        "local_intel": 40,
    }

    def __init__(self):
        self.breakdown = {}
        self.total_score = 0
        self.details = []

    def calculate_apk_score(self, analysis_results):
        """
        Calculate threat score for an APK analysis.
        
        Args:
            analysis_results: dict with keys like 'permissions', 'network', 'yara', etc.
            
        Returns:
            tuple: (score, severity, breakdown_dict)
        """
        self.breakdown = {}
        self.details = []

        # Score permissions
        perms = analysis_results.get("permissions", [])
        perm_score = sum(p.get("score", 0) for p in perms)
        self.breakdown["Permissions"] = min(perm_score, self.CATEGORY_CAPS["permissions"])

        # Score network indicators
        network = analysis_results.get("network", [])
        net_score = sum(min(n.get("confidence", 0) // 5, 10) for n in network)
        self.breakdown["Network Indicators"] = min(net_score, self.CATEGORY_CAPS["network_indicators"])

        # Score YARA matches
        yara = analysis_results.get("yara", [])
        yara_score = 0
        for match in yara:
            sev = match.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                yara_score += 20
            elif sev == "HIGH":
                yara_score += 12
            elif sev == "MEDIUM":
                yara_score += 6
            else:
                yara_score += 3
        self.breakdown["YARA Signatures"] = min(yara_score, self.CATEGORY_CAPS["yara_matches"])

        # Score suspicious strings
        strings = analysis_results.get("suspicious_strings", [])
        str_score = min(len(strings) * 2, self.CATEGORY_CAPS["strings"])
        self.breakdown["Suspicious Strings"] = str_score

        # Score certificate issues
        cert = analysis_results.get("certificate", {})
        cert_score = 0
        if cert.get("self_signed"):
            cert_score += 8
        if cert.get("expired"):
            cert_score += 5
        self.breakdown["Certificate"] = min(cert_score, self.CATEGORY_CAPS["certificate"])

        # Score manifest issues
        manifest = analysis_results.get("manifest", {})
        manifest_score = 0
        if manifest.get("debuggable"):
            manifest_score += 8
        if manifest.get("allow_backup"):
            manifest_score += 3
        if manifest.get("exported_components", 0) > 5:
            manifest_score += 5
        self.breakdown["Manifest Config"] = min(manifest_score, self.CATEGORY_CAPS["manifest"])

        # Score permission combinations
        combos = analysis_results.get("permission_combinations", [])
        combo_score = sum(c.get("score", 0) for c in combos)
        self.breakdown["Permission Combos"] = min(combo_score, self.CATEGORY_CAPS["combinations"])

        # Score Heuristics & Anti-Analysis
        heuristics = analysis_results.get("heuristics", [])
        heuristics_score = 0
        for h in heuristics:
            sev = h.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                heuristics_score += 25
            elif sev == "HIGH":
                heuristics_score += 15
            else:
                heuristics_score += 5
        self.breakdown["Anti-Analysis/Heuristics"] = min(heuristics_score, self.CATEGORY_CAPS["heuristics"])

        # Score VirusTotal results
        vt = analysis_results.get("virustotal", {})
        if vt and vt.get("status") == "found":
            from core.virustotal import get_vt_score_contribution
            vt_score = get_vt_score_contribution(vt)
            self.breakdown["VirusTotal"] = min(vt_score, self.CATEGORY_CAPS["virustotal"])

        # Score Local Intel
        local_intel = analysis_results.get("local_intel", [])
        if local_intel:
            intel_score = min(len(local_intel) * 20, self.CATEGORY_CAPS["local_intel"])
            self.breakdown["Local Intel Matches"] = intel_score

        # Calculate total
        self.total_score = min(100, sum(self.breakdown.values()))
        severity = self._get_severity(self.total_score)

        return self.total_score, severity, self.breakdown

    def calculate_exe_score(self, analysis_results):
        """
        Calculate threat score for an EXE analysis.
        
        Args:
            analysis_results: dict with keys like 'imports', 'network', 'entropy', etc.
            
        Returns:
            tuple: (score, severity, breakdown_dict)
        """
        self.breakdown = {}
        self.details = []

        # Score suspicious imports
        imports = analysis_results.get("suspicious_imports", [])
        imp_score = sum(i.get("score", 0) for i in imports)
        self.breakdown["Suspicious Imports"] = min(imp_score, self.CATEGORY_CAPS["imports"])

        # Score network indicators
        network = analysis_results.get("network", [])
        net_score = sum(min(n.get("confidence", 0) // 5, 10) for n in network)
        self.breakdown["Network Indicators"] = min(net_score, self.CATEGORY_CAPS["network_indicators"])

        # Score entropy
        entropy = analysis_results.get("entropy", {})
        ent_score = 0
        if entropy.get("max_entropy", 0) > 7.5:
            ent_score = 20
        elif entropy.get("max_entropy", 0) > 7.0:
            ent_score = 12
        elif entropy.get("max_entropy", 0) > 6.5:
            ent_score = 5
        packers = analysis_results.get("packers", [])
        if packers:
            ent_score += 10
        self.breakdown["Entropy/Packing"] = min(ent_score, self.CATEGORY_CAPS["entropy"])

        # Score YARA matches
        yara = analysis_results.get("yara", [])
        yara_score = 0
        for match in yara:
            sev = match.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                yara_score += 20
            elif sev == "HIGH":
                yara_score += 12
            elif sev == "MEDIUM":
                yara_score += 6
            else:
                yara_score += 3
        self.breakdown["YARA Signatures"] = min(yara_score, self.CATEGORY_CAPS["yara_matches"])

        # Score suspicious strings
        strings = analysis_results.get("suspicious_strings", [])
        str_score = min(len(strings) * 2, self.CATEGORY_CAPS["strings"])
        self.breakdown["Suspicious Strings"] = str_score

        # Score import combinations
        combos = analysis_results.get("import_combinations", [])
        combo_score = sum(c.get("score", 0) for c in combos)
        self.breakdown["Import Combos (MITRE)"] = min(combo_score, self.CATEGORY_CAPS["combinations"])

        # Score Heuristics & Anti-Analysis
        heuristics = analysis_results.get("heuristics", [])
        heuristics_score = 0
        for h in heuristics:
            sev = h.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                heuristics_score += 25
            elif sev == "HIGH":
                heuristics_score += 15
            else:
                heuristics_score += 5
        self.breakdown["Anti-Analysis/Heuristics"] = min(heuristics_score, self.CATEGORY_CAPS["heuristics"])

        # Score VirusTotal results
        vt = analysis_results.get("virustotal", {})
        if vt and vt.get("status") == "found":
            from core.virustotal import get_vt_score_contribution
            vt_score = get_vt_score_contribution(vt)
            self.breakdown["VirusTotal"] = min(vt_score, self.CATEGORY_CAPS["virustotal"])

        # Score Local Intel
        local_intel = analysis_results.get("local_intel", [])
        if local_intel:
            intel_score = min(len(local_intel) * 20, self.CATEGORY_CAPS["local_intel"])
            self.breakdown["Local Intel Matches"] = intel_score

        # Calculate total
        self.total_score = min(100, sum(self.breakdown.values()))
        severity = self._get_severity(self.total_score)

        return self.total_score, severity, self.breakdown

    def _get_severity(self, score):
        """Map score to severity label."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "CLEAN"
