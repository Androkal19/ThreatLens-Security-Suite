"""
ThreatLens - EXE/PE Analyzer
Static analysis engine for Windows Portable Executable files.
"""

import json
from pathlib import Path

from core.network_extractor import NetworkExtractor, extract_strings
from core.entropy_analyzer import calculate_entropy, classify_entropy, detect_packer
from core.heuristics import HeuristicEngine


class EXEAnalyzer:
    """
    Comprehensive PE/EXE static analysis engine.
    
    Capabilities:
    - PE header analysis (sections, entry point, timestamps)
    - Import table analysis with suspicious API detection
    - Section entropy analysis with packer detection
    - String extraction and C2 indicator detection
    - YARA rule scanning
    """

    def __init__(self):
        self.results = {}
        self._load_import_database()

    def _load_import_database(self):
        """Load the suspicious imports database."""
        db_path = Path(__file__).parent.parent / "signatures" / "suspicious_imports.json"
        try:
            with open(db_path, "r", encoding="utf-8") as f:
                self.import_db = json.load(f)
        except Exception:
            self.import_db = {"categories": {}, "dangerous_combinations": []}

    def analyze(self, file_path, progress_callback=None):
        """
        Run complete PE/EXE analysis.
        
        Args:
            file_path: Path to the EXE file.
            progress_callback: Optional callable(phase, progress) for UI updates.
            
        Returns:
            dict: Complete analysis results.
        """
        self.results = {
            "file_type": "PE/EXE",
            "pe_info": {},
            "sections": [],
            "suspicious_imports": [],
            "import_combinations": [],
            "network": [],
            "entropy": {},
            "packers": [],
            "suspicious_strings": [],
            "yara": [],
            "heuristics": [],
            "errors": [],
        }

        try:
            import pefile
        except ImportError:
            self.results["errors"].append("pefile library not installed. Run: pip install pefile")
            return self.results

        # Load PE file
        if progress_callback:
            progress_callback("Loading PE file", 10)

        try:
            pe = pefile.PE(str(file_path))
        except pefile.PEFormatError as e:
            self.results["errors"].append(f"Invalid PE format: {e}")
            return self.results
        except Exception as e:
            self.results["errors"].append(f"Error loading PE file: {e}")
            return self.results

        # Phase 1: PE Header Analysis
        if progress_callback:
            progress_callback("Analyzing PE headers", 20)
        self._analyze_headers(pe)

        # Phase 2: Section Analysis with Entropy
        if progress_callback:
            progress_callback("Analyzing sections & entropy", 35)
        self._analyze_sections(pe)

        # Phase 3: Import Analysis
        if progress_callback:
            progress_callback("Scanning import table", 50)
        self._analyze_imports(pe)

        # Phase 4: String Extraction & Network Indicators
        if progress_callback:
            progress_callback("Extracting strings & network indicators", 65)
        self._extract_network_indicators(file_path)

        # Phase 5: Suspicious String Analysis
        if progress_callback:
            progress_callback("Analyzing suspicious strings", 80)
        self._analyze_strings(file_path)

        # Phase 6: Heuristics
        if progress_callback:
            progress_callback("Running Advanced Heuristics...", 60)
        self.results["heuristics"] = self._run_heuristics(file_path)

        # Phase 7: YARA Scanning
        if progress_callback:
            progress_callback("Running YARA signatures", 75)
        self._run_yara_scan(file_path)

        # Phase 8: Packer Detection
        if progress_callback:
            progress_callback("Detecting packers", 95)
        self._detect_packers()

        pe.close()

        if progress_callback:
            progress_callback("Analysis complete", 100)

        return self.results

    def _analyze_headers(self, pe):
        """Analyze PE headers for suspicious characteristics."""
        import time as _time

        info = {}

        # File header
        fh = pe.FILE_HEADER
        info["machine"] = hex(fh.Machine)
        info["machine_type"] = self._get_machine_type(fh.Machine)
        info["number_of_sections"] = fh.NumberOfSections
        info["timestamp"] = fh.TimeDateStamp
        try:
            info["compile_time"] = _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime(fh.TimeDateStamp))
        except Exception:
            info["compile_time"] = "Unknown"
        info["characteristics"] = hex(fh.Characteristics)

        # Optional header
        if hasattr(pe, "OPTIONAL_HEADER"):
            oh = pe.OPTIONAL_HEADER
            info["entry_point"] = hex(oh.AddressOfEntryPoint)
            info["image_base"] = hex(oh.ImageBase)
            info["subsystem"] = self._get_subsystem(oh.Subsystem)
            info["dll_characteristics"] = hex(oh.DllCharacteristics)
            info["size_of_image"] = oh.SizeOfImage
            info["size_of_headers"] = oh.SizeOfHeaders

            # Check security features
            info["aslr_enabled"] = bool(oh.DllCharacteristics & 0x0040)
            info["dep_enabled"] = bool(oh.DllCharacteristics & 0x0100)
            info["seh_enabled"] = not bool(oh.DllCharacteristics & 0x0400)

        self.results["pe_info"] = info

    def _analyze_sections(self, pe):
        """Analyze PE sections with entropy calculation."""
        sections = []

        for section in pe.sections:
            try:
                name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            except Exception:
                name = "Unknown"

            data = section.get_data()
            entropy = calculate_entropy(data)
            classification = classify_entropy(entropy)

            # Section characteristics flags
            flags = []
            chars = section.Characteristics
            if chars & 0x00000020:
                flags.append("CODE")
            if chars & 0x00000040:
                flags.append("INIT_DATA")
            if chars & 0x00000080:
                flags.append("UNINIT_DATA")
            if chars & 0x20000000:
                flags.append("EXEC")
            if chars & 0x40000000:
                flags.append("READ")
            if chars & 0x80000000:
                flags.append("WRITE")

            # Suspicious: writable + executable
            is_wx = (chars & 0x20000000) and (chars & 0x80000000)

            sec_info = {
                "name": name,
                "virtual_size": f"0x{section.Misc_VirtualSize:08X}",
                "raw_size": f"0x{section.SizeOfRawData:08X}",
                "virtual_address": f"0x{section.VirtualAddress:08X}",
                "entropy": entropy,
                "entropy_class": classification,
                "flags": " | ".join(flags),
                "writable_executable": is_wx,
                "raw_size_int": section.SizeOfRawData,
                "virtual_size_int": section.Misc_VirtualSize,
            }
            sections.append(sec_info)

        self.results["sections"] = sections
        self.results["entropy"] = {
            "max_entropy": max((s["entropy"] for s in sections), default=0),
            "avg_entropy": sum(s["entropy"] for s in sections) / len(sections) if sections else 0,
            "sections_count": len(sections),
            "high_entropy_sections": sum(1 for s in sections if s["entropy"] > 7.0),
            "wx_sections": sum(1 for s in sections if s.get("writable_executable")),
        }

    def _analyze_imports(self, pe):
        """Analyze import table for suspicious Windows APIs."""
        suspicious = []
        all_imports = {}
        found_import_names = set()

        try:
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        dll_name = entry.dll.decode("utf-8", errors="ignore")
                    except Exception:
                        dll_name = "Unknown"

                    all_imports[dll_name] = []

                    for imp in entry.imports:
                        if imp.name:
                            try:
                                func_name = imp.name.decode("utf-8", errors="ignore")
                            except Exception:
                                func_name = "Unknown"

                            all_imports[dll_name].append(func_name)
                            found_import_names.add(func_name)

                            # Check against database
                            for cat_name, cat_data in self.import_db.get("categories", {}).items():
                                imports_dict = cat_data.get("imports", {})
                                if func_name in imports_dict:
                                    imp_info = imports_dict[func_name]
                                    suspicious.append({
                                        "name": func_name,
                                        "dll": dll_name,
                                        "category": cat_name.replace("_", " ").title(),
                                        "risk": cat_data.get("risk", "MEDIUM"),
                                        "score": imp_info.get("score", 5),
                                        "description": imp_info.get("description", ""),
                                    })
        except Exception as e:
            self.results["errors"].append(f"Import analysis error: {e}")

        self.results["suspicious_imports"] = suspicious
        self.results["all_imports"] = all_imports

        # Check for dangerous combinations
        combinations = []
        for combo in self.import_db.get("dangerous_combinations", []):
            combo_imports = combo.get("imports", [])
            if all(imp in found_import_names for imp in combo_imports):
                combinations.append({
                    "technique": combo.get("technique", "Unknown"),
                    "imports": combo_imports,
                    "score": combo.get("score", 10),
                    "mitre": combo.get("mitre", ""),
                })

        self.results["import_combinations"] = combinations

    def _extract_network_indicators(self, file_path):
        """Extract IPs, ports, URLs, and domains from the binary."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            extractor = NetworkExtractor()
            self.results["network"] = extractor.extract_all(data, source_label="PE binary")
        except Exception as e:
            self.results["errors"].append(f"Network extraction error: {e}")

    def _analyze_strings(self, file_path):
        """Extract and categorize suspicious strings."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            all_strings = extract_strings(data, min_length=6)
            suspicious = []

            suspicious_patterns = {
                "Registry Key": ["HKEY_", "HKLM\\", "HKCU\\", "CurrentVersion\\Run",
                                 "CurrentVersion\\Explorer"],
                "Command Execution": ["cmd.exe", "powershell", "/bin/sh", "/bin/bash",
                                       "WScript.Shell", "schtasks", "net user", "wmic"],
                "Network Keyword": ["socket", "connect", "send", "recv", "http://",
                                     "https://", "ftp://", "upload", "download", "beacon"],
                "Anti-Analysis": ["IsDebuggerPresent", "vmware", "virtualbox", "sandbox",
                                   "wireshark", "fiddler", "ollydbg", "ida"],
                "Crypto/Ransom": ["encrypt", "decrypt", "bitcoin", "wallet", "ransom",
                                   "AES", "RSA", "CryptEncrypt"],
                "Credential": ["password", "credential", "Login Data", "cookies.sqlite",
                                "logins.json", "Chrome", "Firefox"],
                "Persistence": ["\\Run\\", "\\RunOnce\\", "Startup", "schtasks",
                                 "CreateService", "\\services\\"],
                "Mutex": ["Mutex", "CreateMutex", "OpenMutex"],
            }

            seen = set()
            for s in all_strings:
                value = s["value"]
                if value in seen:
                    continue

                for category, keywords in suspicious_patterns.items():
                    for keyword in keywords:
                        if keyword.lower() in value.lower() and value not in seen:
                            seen.add(value)
                            suspicious.append({
                                "value": value[:100],
                                "category": category,
                                "location": f"offset 0x{s['offset']:08X}",
                                "encoding": s["encoding"],
                            })
                            break

            self.results["suspicious_strings"] = suspicious[:100]
        except Exception as e:
            self.results["errors"].append(f"String analysis error: {e}")

    def _run_yara_scan(self, file_path):
        """Run YARA rules against the file."""
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
                        "matched_strings": len(match.strings) if hasattr(match, "strings") else 0,
                    })
        except ImportError:
            pass  # YARA is optional
        except Exception as e:
            self.results["errors"].append(f"YARA scan error: {e}")

    def _detect_packers(self):
        """Detect packers from section analysis."""
        sections = self.results.get("sections", [])
        section_data = [{"name": s["name"], "entropy": s["entropy"]} for s in sections]
        self.results["packers"] = detect_packer(section_data)

    def _get_machine_type(self, machine):
        """Get human-readable machine type."""
        types = {0x14c: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0x1c0: "ARM", 0xaa64: "ARM64"}
        return types.get(machine, f"Unknown (0x{machine:04X})")

    def _get_subsystem(self, subsystem):
        """Get human-readable subsystem name."""
        types = {
            1: "Native", 2: "Windows GUI", 3: "Windows Console",
            5: "OS/2 Console", 7: "POSIX Console",
            9: "Windows CE GUI", 10: "EFI Application",
        }
        return types.get(subsystem, f"Unknown ({subsystem})")

    def _run_heuristics(self, file_path):
        """Run advanced heuristic analysis on EXE."""
        findings = []
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                
            engine = HeuristicEngine()
            hits = engine.analyze_binary(data, Path(file_path).name)
            findings.extend(hits)
        except Exception as e:
            self.results["errors"].append(f"Heuristics analysis error: {e}")
            
        return findings
