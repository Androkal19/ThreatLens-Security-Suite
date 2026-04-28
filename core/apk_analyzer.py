"""
ThreatLens - APK Analyzer
Static analysis engine for Android Application Package files.
"""

import json
import zipfile
import re
from pathlib import Path

import logging

# Suppress noisy library loggings
logging.getLogger("androguard").setLevel(logging.CRITICAL)
logging.getLogger("androguard.core.axml").setLevel(logging.CRITICAL)
logging.getLogger("androguard.core.apk").setLevel(logging.CRITICAL)
logging.getLogger("pefile").setLevel(logging.CRITICAL)

from core.network_extractor import NetworkExtractor, extract_strings
from core.heuristics import HeuristicEngine
from core.entropy_analyzer import calculate_entropy


class APKAnalyzer:
    """
    Comprehensive APK static analysis engine.
    
    Capabilities:
    - AndroidManifest.xml parsing (permissions, components, features)
    - DEX string extraction and analysis
    - Certificate verification
    - Native library scanning
    - Resource and asset analysis
    - YARA rule scanning
    """

    def __init__(self):
        self.results = {}
        self._load_permissions_database()

    def _load_permissions_database(self):
        """Load the suspicious permissions database."""
        db_path = Path(__file__).parent.parent / "signatures" / "suspicious_permissions.json"
        try:
            with open(db_path, "r", encoding="utf-8") as f:
                self.perm_db = json.load(f)
        except Exception:
            self.perm_db = {"dangerous_permissions": {}, "dangerous_combinations": []}

    def analyze(self, file_path, progress_callback=None):
        """
        Run complete APK analysis.
        
        Args:
            file_path: Path to the APK file.
            progress_callback: Optional callable(phase, progress) for UI updates.
            
        Returns:
            dict: Complete analysis results.
        """
        self.results = {
            "file_type": "APK",
            "manifest": {},
            "permissions": [],
            "permission_combinations": [],
            "components": {},
            "certificate": {},
            "network": [],
            "suspicious_strings": [],
            "native_libs": [],
            "yara": [],
            "dex_info": {},
            "errors": [],
        }

        # Phase 1: Extract and parse manifest
        if progress_callback:
            progress_callback("Parsing AndroidManifest.xml", 10)
        self._analyze_manifest(file_path)

        # Phase 2: Permission analysis
        if progress_callback:
            progress_callback("Analyzing permissions", 25)
        self._analyze_permissions()

        # Phase 3: Certificate analysis
        if progress_callback:
            progress_callback("Verifying certificate", 35)
        self._analyze_certificate(file_path)

        # Phase 4: DEX analysis and string extraction
        if progress_callback:
            progress_callback("Analyzing DEX files", 50)
        self._analyze_dex(file_path)


        if progress_callback:
            progress_callback("Running Advanced Heuristics...", 75)
        self.results["heuristics"] = self._run_heuristics(file_path)

        if progress_callback:
            progress_callback("Extracting Network Indicators...", 85)
        self._extract_network_indicators(file_path)

        # Phase 6: Native library analysis
        if progress_callback:
            progress_callback("Scanning native libraries", 75)
        self._analyze_native_libs(file_path)

        # Phase 7: Resource/asset analysis
        if progress_callback:
            progress_callback("Scanning resources & assets", 85)
        self._analyze_resources(file_path)

        # Phase 8: YARA scanning
        if progress_callback:
            progress_callback("Running YARA signatures", 95)
        self._run_yara_scan(file_path)

        if progress_callback:
            progress_callback("Analysis complete", 100)

        return self.results

    def _analyze_manifest(self, file_path):
        """Parse AndroidManifest.xml using androguard."""
        try:
            from androguard.core.apk import APK
            apk = APK(str(file_path))

            self.results["manifest"] = {
                "package_name": apk.get_package() or "Unknown",
                "version_name": apk.get_androidversion_name() or "Unknown",
                "version_code": apk.get_androidversion_code() or "Unknown",
                "min_sdk": apk.get_min_sdk_version() or "Unknown",
                "target_sdk": apk.get_target_sdk_version() or "Unknown",
                "max_sdk": apk.get_max_sdk_version() or "N/A",
                "debuggable": apk.get_attribute_value("application", "debuggable") == "true",
                "allow_backup": apk.get_attribute_value("application", "allowBackup") != "false",
                "uses_cleartext": apk.get_attribute_value("application", "usesCleartextTraffic") == "true",
            }

            # Extract permissions
            self._raw_permissions = apk.get_permissions()

            # Extract components
            self.results["components"] = {
                "activities": list(apk.get_activities()),
                "services": list(apk.get_services()),
                "receivers": list(apk.get_receivers()),
                "providers": list(apk.get_providers()),
            }

            # Count exported components
            exported_count = 0
            for act in apk.get_activities():
                # Simple heuristic: main launcher activities are always exported
                exported_count += 1
            self.results["manifest"]["exported_components"] = min(exported_count, len(apk.get_activities()))

            self._apk_obj = apk

        except ImportError:
            self.results["errors"].append("androguard library not installed. Run: pip install androguard")
            self._raw_permissions = []
            self._analyze_manifest_fallback(file_path)
        except Exception as e:
            self.results["errors"].append(f"Manifest analysis error: {e}")
            self._raw_permissions = []
            self._analyze_manifest_fallback(file_path)

    def _analyze_manifest_fallback(self, file_path):
        """Fallback manifest analysis using zipfile + regex (without androguard)."""
        try:
            with zipfile.ZipFile(str(file_path), "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    data = zf.read("AndroidManifest.xml")
                    # Binary XML — try to extract readable strings
                    text = data.decode("utf-8", errors="ignore")

                    # Find permission strings
                    perm_pattern = re.compile(r'android\.permission\.[A-Z_]+')
                    found_perms = perm_pattern.findall(text)
                    self._raw_permissions = list(set(found_perms))

                    self.results["manifest"]["package_name"] = "Unknown (fallback mode)"
                    self.results["manifest"]["note"] = "Install androguard for complete manifest parsing"
        except Exception as e:
            self.results["errors"].append(f"Fallback manifest parsing failed: {e}")

    def _analyze_permissions(self):
        """Analyze permissions against the suspicious permissions database."""
        permissions = []
        dangerous_db = self.perm_db.get("dangerous_permissions", {})

        for perm in getattr(self, "_raw_permissions", []):
            perm_info = dangerous_db.get(perm, None)
            if perm_info:
                permissions.append({
                    "name": perm,
                    "risk": perm_info["risk"],
                    "score": perm_info["score"],
                    "description": perm_info["description"],
                    "legitimate_use": perm_info.get("legitimate_use", ""),
                    "malicious_use": perm_info.get("malicious_use", ""),
                })
            else:
                # Unknown permission — flag as info
                permissions.append({
                    "name": perm,
                    "risk": "INFO",
                    "score": 0,
                    "description": "Standard permission",
                })

        # Sort by score (highest risk first)
        permissions.sort(key=lambda x: x["score"], reverse=True)
        self.results["permissions"] = permissions

        # Check dangerous combinations
        perm_set = set(getattr(self, "_raw_permissions", []))
        combinations = []
        for combo in self.perm_db.get("dangerous_combinations", []):
            combo_perms = set(combo.get("permissions", []))
            if combo_perms.issubset(perm_set):
                combinations.append({
                    "permissions": combo["permissions"],
                    "threat": combo["threat"],
                    "score": combo["score"],
                    "description": combo["description"],
                })

        self.results["permission_combinations"] = combinations

    def _analyze_certificate(self, file_path):
        """Analyze APK signing certificate."""
        try:
            from androguard.core.apk import APK
            apk = APK(str(file_path))

            certs = apk.get_certificates()
            if certs:
                cert = certs[0]  # Primary certificate
                self.results["certificate"] = {
                    "issuer": str(cert.issuer) if hasattr(cert, "issuer") else "Unknown",
                    "subject": str(cert.subject) if hasattr(cert, "subject") else "Unknown",
                    "serial_number": str(cert.serial_number) if hasattr(cert, "serial_number") else "Unknown",
                    "hash_algorithm": str(cert.signature_hash_algorithm) if hasattr(cert, "signature_hash_algorithm") else "Unknown",
                    "self_signed": self._is_self_signed(cert),
                    "valid": True,
                }

                # Check if issuer and subject are the same (self-signed)
                try:
                    issuer_str = str(cert.issuer)
                    subject_str = str(cert.subject)
                    self.results["certificate"]["self_signed"] = issuer_str == subject_str
                except Exception:
                    pass
            else:
                self.results["certificate"] = {"error": "No certificates found", "self_signed": True}

        except ImportError:
            self.results["certificate"] = {"note": "Install androguard for certificate analysis"}
        except Exception as e:
            self.results["certificate"] = {"error": str(e)}

    def _is_self_signed(self, cert):
        """Check if a certificate is self-signed."""
        try:
            return str(cert.issuer) == str(cert.subject)
        except Exception:
            return True

    def _analyze_dex(self, file_path):
        """Analyze DEX files for suspicious code patterns."""
        try:
            with zipfile.ZipFile(str(file_path), "r") as zf:
                dex_files = [n for n in zf.namelist() if n.endswith(".dex")]
                self.results["dex_info"]["dex_count"] = len(dex_files)
                self.results["dex_info"]["dex_files"] = dex_files

                all_suspicious_strings = []

                for dex_name in dex_files:
                    data = zf.read(dex_name)
                    entropy = calculate_entropy(data)
                    self.results["dex_info"][dex_name] = {
                        "size": len(data),
                        "entropy": entropy,
                    }

                    # Extract strings from DEX
                    strings = extract_strings(data, min_length=6)

                    # Find suspicious patterns
                    suspicious_patterns = {
                        "Runtime Execution": ["Runtime.getRuntime", "exec(", "ProcessBuilder",
                                               "/system/bin/su", "su -c"],
                        "Reflection": ["java.lang.reflect", "getDeclaredMethod", "forName",
                                        "invoke(", "Class.forName"],
                        "Dynamic Loading": ["DexClassLoader", "PathClassLoader",
                                             "loadClass", "dalvik.system"],
                        "Crypto": ["javax.crypto", "Cipher", "SecretKey", "AES",
                                    "DES", "RSA", "encrypt", "decrypt"],
                        "Network": ["HttpURLConnection", "URLConnection", "Socket(",
                                     "ServerSocket", "DatagramSocket", "OkHttp"],
                        "Data Access": ["ContentResolver", "getContentResolver",
                                         "query(", "ContactsContract", "CallLog"],
                        "Device Info": ["getDeviceId", "getSubscriberId", "getLine1Number",
                                         "getSimSerialNumber", "ANDROID_ID", "Build.SERIAL"],
                        "Obfuscation": ["base64", "xor", "rot13", "cipher"],
                    }

                    seen = set()
                    for s in strings:
                        value = s["value"]
                        if value in seen:
                            continue
                        for category, keywords in suspicious_patterns.items():
                            for keyword in keywords:
                                if keyword.lower() in value.lower() and value not in seen:
                                    seen.add(value)
                                    all_suspicious_strings.append({
                                        "value": value[:100],
                                        "category": category,
                                        "location": f"{dex_name} @ 0x{s['offset']:08X}",
                                        "encoding": s["encoding"],
                                    })
                                    break

                self.results["suspicious_strings"] = all_suspicious_strings[:100]

        except Exception as e:
            self.results["errors"].append(f"DEX analysis error: {e}")

    def _run_heuristics(self, file_path):
        """Run advanced heuristic analysis on key binary components."""
        findings = []
        try:
            with zipfile.ZipFile(str(file_path), "r") as zf:
                engine = HeuristicEngine()
                
                # Scan classes.dex and libraries
                for name in zf.namelist():
                    if name.endswith(".dex") or name.endswith(".so"):
                        try:
                            data = zf.read(name)
                            hits = engine.analyze_binary(data, name)
                            findings.extend(hits)
                        except Exception:
                            continue
        except Exception as e:
            self.results["errors"].append(f"Heuristics analysis error: {e}")
            
        # Remove duplicates
        unique = {f"{h['description']}_{h['file']}": h for h in findings}
        return list(unique.values())

    def _extract_network_indicators(self, file_path):
        """Extract IPs, URLs, and domains from the entire APK."""
        try:
            with zipfile.ZipFile(str(file_path), "r") as zf:
                extractor = NetworkExtractor()
                all_findings = []

                # Scan key files for network indicators
                target_extensions = {".dex", ".xml", ".json", ".js", ".html", ".txt", ".cfg", ".properties", ".arsc", ".ini", ".yaml"}

                for name in zf.namelist():
                    ext = Path(name).suffix.lower()
                    if ext in target_extensions or name.endswith(".dex"):
                        try:
                            data = zf.read(name)
                            if len(data) > 0:
                                findings = extractor.extract_all(data, source_label=name)
                                all_findings.extend(findings)
                        except Exception:
                            continue

                # Deduplicate by value
                seen_values = set()
                unique_findings = []
                for f in all_findings:
                    if f["value"] not in seen_values:
                        seen_values.add(f["value"])
                        unique_findings.append(f)

                # Sort by confidence
                unique_findings.sort(key=lambda x: x["confidence"], reverse=True)
                self.results["network"] = unique_findings

        except Exception as e:
            self.results["errors"].append(f"Network extraction error: {e}")

    def _analyze_native_libs(self, file_path):
        """Scan for native libraries (.so files) in the APK."""
        try:
            with zipfile.ZipFile(str(file_path), "r") as zf:
                native_libs = []
                for name in zf.namelist():
                    if name.endswith(".so"):
                        info = zf.getinfo(name)
                        data = zf.read(name)
                        entropy = calculate_entropy(data)

                        native_libs.append({
                            "name": name,
                            "size": info.file_size,
                            "compressed_size": info.compress_size,
                            "entropy": entropy,
                            "architecture": self._get_arch_from_path(name),
                        })

                self.results["native_libs"] = native_libs

        except Exception as e:
            self.results["errors"].append(f"Native library analysis error: {e}")

    def _analyze_resources(self, file_path):
        """Scan resources and assets for embedded files."""
        try:
            embedded = []
            with zipfile.ZipFile(str(file_path), "r") as zf:
                for name in zf.namelist():
                    if name.startswith(("assets/", "res/")):
                        ext = Path(name).suffix.lower()
                        suspicious_extensions = {
                            ".dex", ".apk", ".jar", ".so", ".elf",
                            ".sh", ".py", ".js", ".bat", ".ps1", ".exe",
                        }
                        if ext in suspicious_extensions:
                            info = zf.getinfo(name)
                            embedded.append({
                                "path": name,
                                "type": ext,
                                "size": info.file_size,
                                "risk": "HIGH" if ext in {".dex", ".apk", ".exe", ".elf"} else "MEDIUM",
                            })

            if embedded:
                self.results["embedded_files"] = embedded

        except Exception as e:
            self.results["errors"].append(f"Resource analysis error: {e}")

    def _run_yara_scan(self, file_path):
        """Run YARA rules against the APK file."""
        try:
            import yara
            rules_path = Path(__file__).parent.parent / "signatures" / "yara_rules.yar"
            if rules_path.exists():
                rules = yara.compile(filepath=str(rules_path))
                matches = rules.match(str(file_path))

                for match in matches:
                    meta = match.meta if hasattr(match, "meta") else {}
                    self.results["yara"].append({
                        "rule": match.rule,
                        "severity": meta.get("severity", "MEDIUM"),
                        "category": meta.get("category", "unknown"),
                        "description": meta.get("description", ""),
                    })
        except ImportError:
            pass  # YARA is optional
        except Exception as e:
            self.results["errors"].append(f"YARA scan error: {e}")

    def _get_arch_from_path(self, lib_path):
        """Determine architecture from native library path."""
        path_lower = lib_path.lower()
        if "arm64" in path_lower or "aarch64" in path_lower:
            return "ARM64"
        elif "armeabi" in path_lower or "arm" in path_lower:
            return "ARM"
        elif "x86_64" in path_lower:
            return "x86_64"
        elif "x86" in path_lower:
            return "x86"
        elif "mips" in path_lower:
            return "MIPS"
        return "Unknown"
