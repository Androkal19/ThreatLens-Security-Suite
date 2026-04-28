"""
ThreatLens - Advanced Heuristics Engine
Detects Anti-Analysis techniques, Anti-VM, Root detection, and advanced behavioral traces.
"""

import re


class HeuristicEngine:
    def __init__(self):
        self.findings = []
        
        # Anti-VM & Anti-Emulator artifacts
        self.anti_vm_signatures = {
            b"qemu_pipe": "QEMU Emulator check detected",
            b"goldfish": "Goldfish Emulator check detected",
            b"genymotion": "Genymotion Emulator check detected",
            b"vbox86p": "VirtualBox Environment check detected",
            b"nox.vbox86": "Nox Player Environment check detected",
            b"build.flavor": "Android build.flavor check (Emulator detection)",
            b"ro.hardware": "Android ro.hardware check (Emulator detection)",
            b"ro.kernel.qemu": "Android ro.kernel.qemu check (Emulator detection)",
        }
        
        # Anti-Debugging & Root Detection
        self.anti_debug_signatures = {
            b"android.os.Debug.isDebuggerConnected": "Anti-Debugging check detected",
            b"android.os.Debug.waitingForDebugger": "Anti-Debugging check detected",
            b"/system/app/Superuser.apk": "Root Detection check (Superuser.apk)",
            b"/system/xbin/su": "Root Detection check (su binary)",
            b"/system/bin/su": "Root Detection check (su binary)",
            b"/sbin/su": "Root Detection check (su binary)",
            b"de.robv.android.xposed": "Xposed Hooking Framework check",
            b"com.saurik.substrate": "Substrate Hooking Framework check",
            b"frida-server": "Frida Instrumentation check",
        }
        
        # Obfuscation & Packers
        self.packer_signatures = {
            b"libsecexe.so": "DexGuard / SecNeo Obfuscation",
            b"libsecmain.so": "DexGuard / SecNeo Obfuscation",
            b"libSecShell.so": "Bangcle Obfuscation",
            b"libtup.so": "Tencent Sec Obfuscation",
            b"libprotectClass.so": "360 Jiagu Obfuscation",
            b"libjiagu.so": "360 Jiagu Obfuscation",
        }

    def analyze_binary(self, data, file_name):
        """Analyze binary data for advanced heuristic signatures."""
        self.findings = []
        
        # Scan for Anti-VM
        for sig, desc in self.anti_vm_signatures.items():
            if sig in data:
                self.findings.append({
                    "category": "Anti-VM",
                    "description": desc,
                    "severity": "HIGH",
                    "file": file_name
                })
                
        # Scan for Anti-Debug & Root
        for sig, desc in self.anti_debug_signatures.items():
            if sig in data:
                self.findings.append({
                    "category": "Evasion",
                    "description": desc,
                    "severity": "CRITICAL",
                    "file": file_name
                })
                
        # Scan for Packers
        for sig, desc in self.packer_signatures.items():
            if sig in data:
                self.findings.append({
                    "category": "Obfuscation",
                    "description": desc,
                    "severity": "HIGH",
                    "file": file_name
                })
                
        return self.findings
