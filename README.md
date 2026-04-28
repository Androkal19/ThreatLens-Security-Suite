# 🛡️ ThreatLens — Advanced Malicious APK & EXE Analyzer

**Professional-grade, cross-platform static malware analysis tool** that extracts C2 IP addresses, port numbers, suspicious network indicators, and provides autonomous threat intelligence from APK and EXE files.

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

## ✨ Features

### 🧠 Auto-Training Learning Engine (NEW)
- **Autonomous Evolution** — ThreatLens learns from every scan. If VirusTotal flags a file, ThreatLens automatically extracts its Hash and C2 indicators to its local database.
*   **Offline Detection** — After learning, ThreatLens can detect known threats 100% offline without needing any API calls.
*   **Custom Intel Import** — Inject your own threat intelligence (Hashes, IPs, URLs) using the `--import-intel` command.

### 🔍 Deep Heuristics & Evasion Detection (NEW)
*   **Anti-VM & Anti-Emulator** — Detects checks for QEMU, Goldfish, Genymotion, and VirtualBox.
*   **Anti-Debugging** — Identifies code meant to detect security researchers' debuggers.
*   **Root/Jailbreak Detection** — Scans for `su` binaries, `Superuser.apk`, and hooking frameworks like **Frida** or **Xposed**.
*   **Advanced Packer Detection** — Identifies enterprise-grade obfuscators like **DexGuard**, **Bangcle**, **SecNeo**, and **Tencent Sec**.

### 📱 APK Analysis
- **AndroidManifest.xml** — Full manifest parsing with package info, SDK versions, component extraction.
- **Permission Auditing** — 24+ dangerous permissions scored with risk levels and malicious use cases.
- **Permission Combinations** — Detects 7 dangerous permission combos (Banking Trojan, Spyware, etc.).
- **DEX Analysis** — String extraction, suspicious API detection, and deep code heuristics.
- **Network Scanning** — Scans `.arsc` resources and `.so` libraries for hidden Firebase/C2 URLs.

### 💻 EXE/PE Analysis
- **PE Header Analysis** — Entry point, compile timestamps, and security features (ASLR/DEP).
- **Import Analysis** — 80+ suspicious Windows APIs categorized by attack technique.
- **Import Combinations** — MITRE ATT&CK mapped technique detection (8 patterns).
- **Packer Detection** — UPX, Themida, VMProtect, and many others.

### 🌐 Network Indicator Extraction
- **5-Stage Zero-FP Pipeline** — Zero false-positive detection for IPs, Domains, and URLs.
- **Port Detection** — Context-aware detection of RAT command ports.
- **Base64 Decoding** — Automatically decodes obfuscated indicators.

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
cd tool/

# Install dependencies
pip install -r requirements.txt
```

### Configuration
Update `config.json` with your **VirusTotal API Key** to enable the Learning Engine:
```json
{
    "virustotal_api_key": "YOUR_API_KEY_HERE"
}
```

### Usage

```bash
# Interactive mode (opens GUI file picker if you press Enter)
python threatlens.py

# Analyze a specific file
python threatlens.py --file malware.apk

# Import your own threat database
python threatlens.py --import-intel my_iocs.json

# Batch scan a directory
python threatlens.py --batch ./samples/
```

## 📁 Project Structure

```
tool/
├── threatlens.py              # Main entry point & interactive menu
├── core/
│   ├── learning_engine.py    # Autonomous threat database & training
│   ├── heuristics.py         # Anti-VM, Anti-Debug, and Packer detection
│   ├── apk_analyzer.py       # APK static analysis engine
│   ├── exe_analyzer.py       # PE/EXE static analysis engine
│   ├── network_extractor.py  # Zero-FP C2 indicator extraction
│   └── threat_scorer.py      # Weighted risk scoring engine
├── signatures/
│   ├── local_threat_intel.json # Local "learned" threat database
│   ├── yara_rules.yar        # 15+ YARA rules for malware families
│   └── suspicious_imports.json # Suspicious API database
├── ui/                       # Rich Terminal UI & Dashboard
└── config.json               # API configurations
```

## ⚖️ Disclaimer

This tool is designed for **authorized security analysis only**. Unauthorized use against systems you do not own is illegal and unethical.

## 📝 License

MIT License — see [LICENSE](LICENSE) for details.

