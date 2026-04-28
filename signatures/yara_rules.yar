/*
    ThreatLens YARA Rules v1.0
    Built-in malware detection signatures for APK and EXE analysis
    Categories: RATs, Keyloggers, Ransomware, Banking Trojans, Spyware, C2 Frameworks
*/

// ============================================================================
// GENERIC MALWARE INDICATORS
// ============================================================================

rule Generic_Suspicious_Strings
{
    meta:
        description = "Detects common suspicious strings found in malware"
        author = "ThreatLens"
        severity = "MEDIUM"
        category = "generic"

    strings:
        $s1 = "cmd.exe" ascii wide nocase
        $s2 = "/bin/sh" ascii
        $s3 = "/bin/bash" ascii
        $s4 = "powershell" ascii wide nocase
        $s5 = "WScript.Shell" ascii wide nocase
        $s6 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $s7 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $s8 = "schtasks" ascii wide nocase
        $s9 = "net user" ascii wide nocase
        $s10 = "netsh firewall" ascii wide nocase

    condition:
        3 of them
}

rule Generic_AntiAnalysis
{
    meta:
        description = "Detects anti-analysis and anti-debugging techniques"
        author = "ThreatLens"
        severity = "HIGH"
        category = "evasion"

    strings:
        $aa1 = "IsDebuggerPresent" ascii wide
        $aa2 = "CheckRemoteDebuggerPresent" ascii wide
        $aa3 = "NtQueryInformationProcess" ascii wide
        $aa4 = "OutputDebugString" ascii wide
        $aa5 = "SbieDll.dll" ascii wide  // Sandboxie
        $aa6 = "dbghelp.dll" ascii wide
        $aa7 = "vmware" ascii wide nocase
        $aa8 = "virtualbox" ascii wide nocase
        $aa9 = "vbox" ascii wide nocase
        $aa10 = "qemu" ascii wide nocase
        $aa11 = "sandbox" ascii wide nocase
        $aa12 = "wireshark" ascii wide nocase
        $aa13 = "fiddler" ascii wide nocase
        $aa14 = "procmon" ascii wide nocase
        $aa15 = "ollydbg" ascii wide nocase

    condition:
        3 of them
}

rule Generic_Obfuscation
{
    meta:
        description = "Detects signs of code obfuscation or packing"
        author = "ThreatLens"
        severity = "MEDIUM"
        category = "obfuscation"

    strings:
        $o1 = "VirtualProtect" ascii wide
        $o2 = "VirtualAlloc" ascii wide
        $o3 = "LoadLibraryA" ascii wide
        $o4 = "GetProcAddress" ascii wide
        $o5 = "UPX0" ascii
        $o6 = "UPX1" ascii
        $o7 = ".themida" ascii
        $o8 = "VMProtect" ascii wide

    condition:
        ($o1 and $o2 and $o3 and $o4) or $o5 or $o6 or $o7 or $o8
}

// ============================================================================
// RAT (Remote Access Trojan) SIGNATURES
// ============================================================================

rule RAT_njRAT
{
    meta:
        description = "Detects njRAT remote access trojan"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "rat"
        malware_family = "njRAT"

    strings:
        $s1 = "njRAT" ascii wide nocase
        $s2 = "njq8" ascii wide
        $s3 = "lv|" ascii
        $s4 = "kl|" ascii
        $s5 = "prof|" ascii
        $s6 = "HacKed" ascii wide
        $s7 = "|'|'|" ascii
        $s8 = "netsh firewall add allowedprogram" ascii wide

    condition:
        3 of them
}

rule RAT_DarkComet
{
    meta:
        description = "Detects DarkComet RAT"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "rat"
        malware_family = "DarkComet"

    strings:
        $s1 = "DarkComet" ascii wide nocase
        $s2 = "DC_MUTEX" ascii wide
        $s3 = "#BOT#" ascii wide
        $s4 = "YOURPASSWORD" ascii wide
        $s5 = "FirewallDisable" ascii wide
        $s6 = "EditSERVER" ascii wide

    condition:
        3 of them
}

rule RAT_AsyncRAT
{
    meta:
        description = "Detects AsyncRAT"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "rat"
        malware_family = "AsyncRAT"

    strings:
        $s1 = "AsyncRAT" ascii wide nocase
        $s2 = "AsyncClient" ascii wide
        $s3 = "Pastebin" ascii wide
        $s4 = "ABORRARAUTOINICIO" ascii wide
        $s5 = "Anti_Analysis" ascii wide
        $s6 = "get_Ession" ascii wide

    condition:
        3 of them
}

rule RAT_Quasar
{
    meta:
        description = "Detects Quasar RAT"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "rat"
        malware_family = "QuasarRAT"

    strings:
        $s1 = "Quasar.Client" ascii wide
        $s2 = "QuasarRAT" ascii wide nocase
        $s3 = "quas_client" ascii wide
        $s4 = "GetKeyloggerLogs" ascii wide
        $s5 = "FileManagerHandler" ascii wide
        $s6 = "ReverseProxyHandler" ascii wide

    condition:
        3 of them
}

// ============================================================================
// C2 FRAMEWORK SIGNATURES
// ============================================================================

rule C2_CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike Beacon payload"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "c2_framework"
        malware_family = "CobaltStrike"

    strings:
        $s1 = "%s.4444" ascii
        $s2 = "beacon.dll" ascii wide
        $s3 = "beacon.x86.dll" ascii wide
        $s4 = "beacon.x64.dll" ascii wide
        $s5 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $s6 = "ReflectiveLoader" ascii wide
        $s7 = "libhttps" ascii

    condition:
        3 of them
}

rule C2_Metasploit_Meterpreter
{
    meta:
        description = "Detects Metasploit Meterpreter payload"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "c2_framework"
        malware_family = "Metasploit"

    strings:
        $s1 = "metsrv.dll" ascii wide
        $s2 = "meterpreter" ascii wide nocase
        $s3 = "ext_server_" ascii wide
        $s4 = "stdapi" ascii wide
        $s5 = "ReflectiveDLLInject" ascii wide
        $s6 = "reverse_tcp" ascii wide nocase
        $s7 = "reverse_http" ascii wide nocase
        $s8 = "bind_tcp" ascii wide nocase

    condition:
        3 of them
}

// ============================================================================
// RANSOMWARE SIGNATURES
// ============================================================================

rule Ransomware_Generic
{
    meta:
        description = "Detects generic ransomware behavior patterns"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "ransomware"

    strings:
        $r1 = "Your files have been encrypted" ascii wide nocase
        $r2 = "bitcoin" ascii wide nocase
        $r3 = "ransom" ascii wide nocase
        $r4 = "decrypt" ascii wide nocase
        $r5 = ".onion" ascii wide
        $r6 = "tor browser" ascii wide nocase
        $r7 = "wallet" ascii wide nocase
        $r8 = "payment" ascii wide nocase
        $ext1 = ".encrypted" ascii wide
        $ext2 = ".locked" ascii wide
        $ext3 = ".crypt" ascii wide

    condition:
        4 of ($r*) or (2 of ($r*) and 1 of ($ext*))
}

// ============================================================================
// KEYLOGGER SIGNATURES
// ============================================================================

rule Keylogger_Generic
{
    meta:
        description = "Detects generic keylogger behavior"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "keylogger"

    strings:
        $k1 = "keylog" ascii wide nocase
        $k2 = "GetAsyncKeyState" ascii wide
        $k3 = "SetWindowsHookEx" ascii wide
        $k4 = "GetKeyboardState" ascii wide
        $k5 = "MapVirtualKey" ascii wide
        $k6 = "[ENTER]" ascii wide
        $k7 = "[BACKSPACE]" ascii wide
        $k8 = "[TAB]" ascii wide
        $k9 = "[SHIFT]" ascii wide
        $k10 = "keyboard" ascii wide nocase

    condition:
        ($k2 or $k3) and 2 of ($k*)
}

// ============================================================================
// ANDROID-SPECIFIC MALWARE
// ============================================================================

rule Android_SMS_Stealer
{
    meta:
        description = "Detects Android SMS stealing malware"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "android_malware"

    strings:
        $a1 = "android.provider.Telephony.SMS_RECEIVED" ascii wide
        $a2 = "SmsReceiver" ascii wide
        $a3 = "getMessageBody" ascii wide
        $a4 = "getOriginatingAddress" ascii wide
        $a5 = "RECEIVE_SMS" ascii wide
        $a6 = "READ_SMS" ascii wide
        $a7 = "abortBroadcast" ascii wide
        $a8 = "sendTextMessage" ascii wide

    condition:
        4 of them
}

rule Android_Banking_Trojan
{
    meta:
        description = "Detects Android banking trojan patterns"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "android_malware"

    strings:
        $b1 = "SYSTEM_ALERT_WINDOW" ascii wide
        $b2 = "TYPE_APPLICATION_OVERLAY" ascii wide
        $b3 = "AccessibilityService" ascii wide
        $b4 = "onAccessibilityEvent" ascii wide
        $b5 = "WebView" ascii wide
        $b6 = "loadUrl" ascii wide
        $b7 = "inject" ascii wide nocase
        $b8 = "overlay" ascii wide nocase
        $b9 = "phishing" ascii wide nocase

    condition:
        4 of them
}

rule Android_Spyware
{
    meta:
        description = "Detects Android spyware patterns"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "android_malware"

    strings:
        $sp1 = "getLastKnownLocation" ascii wide
        $sp2 = "getDeviceId" ascii wide
        $sp3 = "getSubscriberId" ascii wide
        $sp4 = "RECORD_AUDIO" ascii wide
        $sp5 = "MediaRecorder" ascii wide
        $sp6 = "TelephonyManager" ascii wide
        $sp7 = "READ_CALL_LOG" ascii wide
        $sp8 = "READ_CONTACTS" ascii wide
        $sp9 = "getSimSerialNumber" ascii wide
        $sp10 = "getCellLocation" ascii wide

    condition:
        5 of them
}

rule Android_Ransomware
{
    meta:
        description = "Detects Android ransomware/device locker"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "android_malware"

    strings:
        $ar1 = "DeviceAdminReceiver" ascii wide
        $ar2 = "BIND_DEVICE_ADMIN" ascii wide
        $ar3 = "lockNow" ascii wide
        $ar4 = "resetPassword" ascii wide
        $ar5 = "wipeData" ascii wide
        $ar6 = "setCameraDisabled" ascii wide
        $ar7 = "bitcoin" ascii wide nocase
        $ar8 = "encrypted" ascii wide nocase

    condition:
        4 of them
}

// ============================================================================
// DATA EXFILTRATION INDICATORS
// ============================================================================

rule Exfiltration_Indicators
{
    meta:
        description = "Detects data exfiltration patterns"
        author = "ThreatLens"
        severity = "HIGH"
        category = "exfiltration"

    strings:
        $e1 = "upload" ascii wide nocase
        $e2 = "exfil" ascii wide nocase
        $e3 = "POST" ascii wide
        $e4 = "multipart/form-data" ascii wide
        $e5 = "base64" ascii wide nocase
        $e6 = "gzip" ascii wide nocase
        $e7 = "compress" ascii wide nocase
        $e8 = "Content-Type" ascii wide
        $e9 = "ftp://" ascii wide nocase
        $e10 = "smtp" ascii wide nocase

    condition:
        4 of them
}

rule Credential_Stealer
{
    meta:
        description = "Detects credential stealing patterns"
        author = "ThreatLens"
        severity = "CRITICAL"
        category = "stealer"

    strings:
        $c1 = "password" ascii wide nocase
        $c2 = "credential" ascii wide nocase
        $c3 = "login" ascii wide nocase
        $c4 = "Chrome" ascii wide
        $c5 = "Firefox" ascii wide
        $c6 = "\\Login Data" ascii wide
        $c7 = "\\cookies.sqlite" ascii wide
        $c8 = "\\logins.json" ascii wide
        $c9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii wide
        $c10 = "wallet.dat" ascii wide

    condition:
        4 of them
}
