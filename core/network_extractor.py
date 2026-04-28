"""
ThreatLens - Network Extractor
Extracts and validates IP addresses, ports, URLs, and domains from binary data.
Implements a 5-stage zero-false-positive validation pipeline.
"""

import re
import ipaddress
import struct
from pathlib import Path


# ============================================================================
# REGEX PATTERNS
# ============================================================================

# IPv4 with strict octet validation
IPV4_PATTERN = re.compile(
    r'(?<![.\d])'  # Negative lookbehind: not preceded by dot or digit
    r'(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
    r'(?![.\d])'   # Negative lookahead: not followed by dot or digit
)

# IPv4 with port (IP:PORT)
IPV4_PORT_PATTERN = re.compile(
    r'(?<![.\d])'
    r'((?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))'
    r':(\d{1,5})'
    r'(?![.\d])'
)

# URL pattern
URL_PATTERN = re.compile(
    r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
)

# Domain pattern (simplified, TLD-aware)
DOMAIN_PATTERN = re.compile(
    r'(?<![a-zA-Z0-9\-.])'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|info|io|co|xyz|top|ru|cn|tk|ml|ga|cf|gq|cc|pw|club|online|site|live|me|pro|biz)'
    r'(?![a-zA-Z0-9])'
)

# Port patterns in various contexts (requires explicit 'port' keyword to avoid IP false matches)
PORT_CONTEXT_PATTERNS = [
    re.compile(r'[Pp]ort\s*[=:]\s*(\d{1,5})'),
    re.compile(r'PORT\s*[=:]\s*(\d{1,5})'),
    re.compile(r'listen\s+(?:on\s+)?port\s+(\d{1,5})\b'),
    re.compile(r'bind\s+(?:to\s+)?port\s+(\d{1,5})\b'),
    re.compile(r'connect\s+(?:to\s+)?port\s+(\d{1,5})\b'),
]

# Base64 pattern (for encoded IPs/URLs)
BASE64_PATTERN = re.compile(
    r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
)


# ============================================================================
# WHITELIST - Known safe IPs and domains
# ============================================================================

SAFE_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    # Loopback range
    "127.0.0.0",
    # Google DNS
    "8.8.8.8", "8.8.4.4",
    # Cloudflare DNS
    "1.1.1.1", "1.0.0.1",
    # Common internal
    "10.0.0.1", "192.168.0.1", "192.168.1.1",
    # Broadcast
    "255.255.255.0",
}

SAFE_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com",
    "android.com", "google-analytics.com",
    "facebook.com", "fbcdn.net",
    "apple.com", "icloud.com",
    "microsoft.com", "windows.com", "live.com",
    "amazon.com", "amazonaws.com",
    "cloudflare.com",
    "github.com", "githubusercontent.com",
    "stackoverflow.com",
    "mozilla.org", "mozilla.com",
    "w3.org", "schema.org",
    "localhost",
}

# Version string patterns to exclude
VERSION_PATTERNS = [
    re.compile(r'[Vv]ersion\s*[=:]\s*\d+\.\d+\.\d+\.\d+'),
    re.compile(r'[Vv]\d+\.\d+\.\d+\.\d+'),
    re.compile(r'\d+\.\d+\.\d+\.\d+[\-.](?:alpha|beta|rc|dev|SNAPSHOT|release|final)', re.IGNORECASE),
    re.compile(r'(?:SDK|API|Build|Min|Target|Compile)\s*[=:]?\s*\d+\.\d+\.\d+\.\d+', re.IGNORECASE),
]


class NetworkExtractor:
    """
    Extracts network indicators from binary/text data with zero-FP validation.
    
    Pipeline stages:
    1. Detection   - Regex pattern matching
    2. Validation  - Format correctness
    3. Context     - Code context analysis
    4. Whitelist   - Known-safe filtering
    5. Confidence  - Score assignment
    """

    def __init__(self):
        self.findings = []
        self.raw_ips = set()
        self.raw_urls = set()
        self.raw_domains = set()
        self.raw_ports = set()

    def extract_all(self, data, source_label="binary"):
        """
        Run the full extraction pipeline on binary or text data.
        
        Args:
            data: bytes or str data to analyze.
            source_label: Label for the data source (for context).
            
        Returns:
            list: Validated findings with confidence scores.
        """
        self.findings = []
        self.raw_ips = set()
        self.raw_urls = set()
        self.raw_domains = set()
        self.raw_ports = set()

        # Convert bytes to string for regex matching
        if isinstance(data, bytes):
            # Try multiple encodings
            text_data = ""
            for encoding in ["utf-8", "ascii", "latin-1"]:
                try:
                    text_data = data.decode(encoding, errors="ignore")
                    break
                except Exception:
                    continue
        else:
            text_data = data

        # Stage 1: Detection
        self._detect_ipv4_with_ports(text_data, source_label)
        self._detect_ipv4(text_data, source_label)
        self._detect_urls(text_data, source_label)
        self._detect_domains(text_data, source_label)
        self._detect_context_ports(text_data, source_label)
        self._detect_base64_encoded(text_data, source_label)

        # Stages 2-5: Validation, Context, Whitelist, Confidence
        validated = []
        for finding in self.findings:
            if self._validate(finding) and self._context_check(finding) and self._whitelist_check(finding):
                finding["confidence"] = self._calculate_confidence(finding)
                if finding["confidence"] >= 40:  # Minimum confidence threshold
                    validated.append(finding)

        # Sort by confidence (highest first)
        validated.sort(key=lambda x: x["confidence"], reverse=True)
        return validated

    def _detect_ipv4_with_ports(self, text, source):
        """Detect IPv4 addresses with port numbers."""
        for match in IPV4_PORT_PATTERN.finditer(text):
            ip = match.group(1)
            port = match.group(2)
            if ip not in self.raw_ips:
                self.raw_ips.add(ip)
                context = self._get_context(text, match.start(), match.end())
                self.findings.append({
                    "type": "IPv4",
                    "value": ip,
                    "port": int(port),
                    "raw_match": match.group(0),
                    "context": context,
                    "source": source,
                    "has_port": True,
                })

    def _detect_ipv4(self, text, source):
        """Detect standalone IPv4 addresses."""
        for match in IPV4_PATTERN.finditer(text):
            ip = match.group(0)
            if ip not in self.raw_ips:
                self.raw_ips.add(ip)
                context = self._get_context(text, match.start(), match.end())
                self.findings.append({
                    "type": "IPv4",
                    "value": ip,
                    "port": None,
                    "raw_match": match.group(0),
                    "context": context,
                    "source": source,
                    "has_port": False,
                })

    def _detect_urls(self, text, source):
        """Detect full URLs."""
        for match in URL_PATTERN.finditer(text):
            url = match.group(0)
            if url not in self.raw_urls:
                self.raw_urls.add(url)
                # Extract port from URL if present
                port = self._extract_port_from_url(url)
                context = self._get_context(text, match.start(), match.end())
                self.findings.append({
                    "type": "URL",
                    "value": url,
                    "port": port,
                    "raw_match": url,
                    "context": context,
                    "source": source,
                    "has_port": port is not None,
                })

    def _detect_domains(self, text, source):
        """Detect domain names."""
        for match in DOMAIN_PATTERN.finditer(text):
            domain = match.group(0)
            if domain not in self.raw_domains and not self._is_safe_domain(domain):
                self.raw_domains.add(domain)
                context = self._get_context(text, match.start(), match.end())
                self.findings.append({
                    "type": "Domain",
                    "value": domain,
                    "port": None,
                    "raw_match": domain,
                    "context": context,
                    "source": source,
                    "has_port": False,
                })

    def _detect_context_ports(self, text, source):
        """Detect port numbers in context (port=, listen, bind, connect)."""
        for pattern in PORT_CONTEXT_PATTERNS:
            for match in pattern.finditer(text):
                port_str = match.group(1)
                try:
                    port = int(port_str)
                    if 1 <= port <= 65535 and port not in self.raw_ports:
                        self.raw_ports.add(port)
                        context = self._get_context(text, match.start(), match.end())
                        self.findings.append({
                            "type": "Port",
                            "value": f"Port {port}",
                            "port": port,
                            "raw_match": match.group(0),
                            "context": context,
                            "source": source,
                            "has_port": True,
                        })
                except ValueError:
                    pass

    def _detect_base64_encoded(self, text, source):
        """Detect and decode base64-encoded IPs/URLs."""
        import base64
        for match in BASE64_PATTERN.finditer(text):
            b64_str = match.group(0)
            if len(b64_str) < 12 or len(b64_str) > 500:
                continue
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                # Check if decoded content contains IPs or URLs
                for ip_match in IPV4_PATTERN.finditer(decoded):
                    ip = ip_match.group(0)
                    if ip not in self.raw_ips:
                        self.raw_ips.add(ip)
                        self.findings.append({
                            "type": "IPv4",
                            "value": ip,
                            "port": None,
                            "raw_match": f"base64({b64_str[:30]}...)",
                            "context": f"Decoded from Base64: {decoded[:60]}",
                            "source": source,
                            "has_port": False,
                            "encoded": True,
                        })
                for url_match in URL_PATTERN.finditer(decoded):
                    url = url_match.group(0)
                    if url not in self.raw_urls:
                        self.raw_urls.add(url)
                        port = self._extract_port_from_url(url)
                        self.findings.append({
                            "type": "URL",
                            "value": url,
                            "port": port,
                            "raw_match": f"base64({b64_str[:30]}...)",
                            "context": f"Decoded from Base64: {decoded[:60]}",
                            "source": source,
                            "has_port": port is not None,
                            "encoded": True,
                        })
            except Exception:
                pass

    # ========================================================================
    # VALIDATION STAGES
    # ========================================================================

    def _validate(self, finding):
        """Stage 2: Validate structural correctness."""
        ftype = finding["type"]

        if ftype == "IPv4":
            try:
                addr = ipaddress.IPv4Address(finding["value"])
                # Exclude multicast, reserved
                if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
                    return False
                return True
            except (ipaddress.AddressValueError, ValueError):
                return False

        if ftype == "Port":
            port = finding.get("port")
            return port is not None and 1 <= port <= 65535

        if ftype in ("URL", "Domain"):
            return len(finding["value"]) > 4

        return True

    def _context_check(self, finding):
        """Stage 3: Check if the finding is in a code/data context (not a version string)."""
        context = finding.get("context", "")
        raw = finding.get("raw_match", "")

        # Check if this looks like a version string
        for pattern in VERSION_PATTERNS:
            if pattern.search(context):
                return False

        # Check for common non-malicious contexts
        benign_contexts = [
            "xmlns", "schema", "doctype", "copyright", "license",
            "gradle", "maven", "dependency", "artifact",
        ]
        context_lower = context.lower()
        for benign in benign_contexts:
            if benign in context_lower:
                return False

        return True

    def _whitelist_check(self, finding):
        """Stage 4: Filter out known-safe values."""
        ftype = finding["type"]

        if ftype == "IPv4":
            ip = finding["value"]
            if ip in SAFE_IPS:
                return False
            try:
                addr = ipaddress.IPv4Address(ip)
                if addr.is_loopback or addr.is_link_local:
                    return False
            except Exception:
                pass

        if ftype == "Domain":
            return not self._is_safe_domain(finding["value"])

        if ftype == "URL":
            url = finding["value"].lower()
            for safe in SAFE_DOMAINS:
                if safe in url:
                    return False

        return True

    def _calculate_confidence(self, finding):
        """Stage 5: Calculate confidence score (0-100)."""
        score = 40  # Start with a lower base score for more dynamic range

        ftype = finding["type"]
        context = finding.get("context", "").lower()

        # IP with port is very suspicious
        if ftype == "IPv4" and finding.get("has_port"):
            score += 30

        # Base64-encoded indicators are very suspicious
        if finding.get("encoded"):
            score += 25

        # Weighted Context-based scoring
        high_risk_context = ["exfil", "beacon", "c2", "callback", "command", "control", "gate", "panel"]
        med_risk_context = ["connect", "socket", "upload", "download", "post", "payload"]
        low_risk_context = ["server", "host", "port", "remote"]

        for word in high_risk_context:
            if word in context:
                score += 15
        for word in med_risk_context:
            if word in context:
                score += 8
        for word in low_risk_context:
            if word in context:
                score += 4

        # Non-standard ports are more suspicious
        port = finding.get("port")
        if port:
            common_ports = {80, 443, 8080, 8443}
            if port not in common_ports:
                score += 12
            # RAT common ports (massive bonus)
            rat_ports = {4444, 5555, 1234, 9999, 31337, 1337, 6666, 7777, 8888}
            if port in rat_ports:
                score += 25

        # Private IPs are less likely to be C2 (but still possible)
        if ftype == "IPv4":
            try:
                addr = ipaddress.IPv4Address(finding["value"])
                if addr.is_private:
                    score -= 15
            except Exception:
                pass

        # URLs with suspicious paths
        if ftype == "URL":
            url = finding["value"].lower()
            sus_paths = ["/gate", "/panel", "/login", "/cmd", "/shell", "/upload", "/bot", "/api/"]
            for path in sus_paths:
                if path in url:
                    score += 10

        return min(100, max(0, score))

    # ========================================================================
    # HELPERS
    # ========================================================================

    def _get_context(self, text, start, end, window=80):
        """Get surrounding context of a match."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        context = text[ctx_start:ctx_end]
        # Clean up non-printable characters
        context = "".join(c if c.isprintable() else " " for c in context)
        return context.strip()

    def _extract_port_from_url(self, url):
        """Extract port number from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.port:
                return parsed.port
        except Exception:
            pass
        return None

    def _is_safe_domain(self, domain):
        """Check if a domain is in the safe list."""
        domain_lower = domain.lower()
        for safe in SAFE_DOMAINS:
            if domain_lower == safe or domain_lower.endswith("." + safe):
                return True
        return False


def extract_strings(data, min_length=4):
    """
    Extract printable ASCII and Unicode strings from binary data.
    
    Args:
        data: Binary data (bytes).
        min_length: Minimum string length to extract.
        
    Returns:
        list: Extracted strings with their offsets.
    """
    strings = []

    # ASCII strings
    ascii_pattern = re.compile(rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}')
    for match in ascii_pattern.finditer(data):
        try:
            s = match.group(0).decode("ascii")
            strings.append({
                "value": s,
                "offset": match.start(),
                "encoding": "ASCII",
            })
        except Exception:
            pass

    # Unicode (UTF-16LE) strings
    unicode_pattern = re.compile(
        rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
    )
    for match in unicode_pattern.finditer(data):
        try:
            s = match.group(0).decode("utf-16-le")
            strings.append({
                "value": s,
                "offset": match.start(),
                "encoding": "UTF-16LE",
            })
        except Exception:
            pass

    return strings
