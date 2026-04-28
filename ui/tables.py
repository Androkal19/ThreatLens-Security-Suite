"""
ThreatLens - Formatted Output Tables
Color-coded Rich tables for displaying analysis results.
"""

from rich.table import Table
from rich.text import Text
from rich import box
from ui.theme import get_severity_style


def create_permissions_table(permissions_data):
    """Create a formatted table for Android permissions analysis."""
    table = Table(
        title="  [*] Android Permissions Analysis",
        box=box.ROUNDED, border_style="cyan", title_style="bold cyan",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Permission", style="white", min_width=35)
    table.add_column("Risk", justify="center", width=10)
    table.add_column("Score", justify="center", width=7)
    table.add_column("Description", style="dim white", min_width=30)

    for i, perm in enumerate(permissions_data, 1):
        risk = perm.get("risk", "LOW")
        style = get_severity_style(risk)
        risk_text = Text(risk, style=style)
        score_text = Text(str(perm.get("score", 0)), style=style)
        table.add_row(str(i), perm.get("name", ""), risk_text, score_text, perm.get("description", ""))
    return table


def create_imports_table(imports_data):
    """Create a formatted table for suspicious Windows API imports."""
    table = Table(
        title="  [!] Suspicious API Imports",
        box=box.ROUNDED, border_style="cyan", title_style="bold cyan",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("API Function", style="bold white", min_width=25)
    table.add_column("DLL", style="dim white", width=15)
    table.add_column("Category", style="cyan", width=18)
    table.add_column("Risk", justify="center", width=10)
    table.add_column("Score", justify="center", width=7)

    for i, imp in enumerate(imports_data, 1):
        risk = imp.get("risk", "LOW")
        style = get_severity_style(risk)
        risk_text = Text(risk, style=style)
        score_text = Text(str(imp.get("score", 0)), style=style)
        table.add_row(str(i), imp.get("name", ""), imp.get("dll", ""), imp.get("category", ""), risk_text, score_text)
    return table


def create_network_table(network_data):
    """Create a formatted table for extracted network indicators (IPs, ports, URLs)."""
    table = Table(
        title="  [*] Network Indicators (C2 / Exfiltration)",
        box=box.ROUNDED, border_style="red", title_style="bold red",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Type", style="cyan", width=8, justify="center")
    table.add_column("Value", style="bold red", min_width=30)
    table.add_column("Port", style="bold dark_orange", width=8, justify="center")
    table.add_column("Context", style="dim white", min_width=25)
    table.add_column("Confidence", justify="center", width=12)

    for i, item in enumerate(network_data, 1):
        conf = item.get("confidence", 0)
        if conf >= 80:
            conf_style = "bold red"
        elif conf >= 60:
            conf_style = "bold dark_orange"
        elif conf >= 40:
            conf_style = "bold yellow"
        else:
            conf_style = "dim green"
        conf_text = Text(f"{conf}%", style=conf_style)
        port_str = str(item.get("port", "—")) if item.get("port") else "—"
        table.add_row(str(i), item.get("type", ""), item.get("value", ""), port_str, item.get("context", ""), conf_text)
    return table


def create_sections_table(sections_data):
    """Create a formatted table for PE section analysis."""
    table = Table(
        title="  [+] PE Section Analysis",
        box=box.ROUNDED, border_style="cyan", title_style="bold cyan",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("Section", style="bold white", width=12)
    table.add_column("VirtSize", style="white", width=12, justify="right")
    table.add_column("RawSize", style="white", width=12, justify="right")
    table.add_column("Entropy", justify="center", width=10)
    table.add_column("Flags", style="dim white", min_width=20)
    table.add_column("Status", justify="center", width=12)

    for sec in sections_data:
        entropy = sec.get("entropy", 0)
        if entropy > 7.0:
            ent_style, status = "bold red", Text("[!] PACKED", style="bold red")
        elif entropy > 6.5:
            ent_style, status = "bold yellow", Text("[!] SUSPECT", style="bold yellow")
        else:
            ent_style, status = "green", Text("[OK] NORMAL", style="green")
        ent_text = Text(f"{entropy:.4f}", style=ent_style)
        table.add_row(sec.get("name", ""), sec.get("virtual_size", ""), sec.get("raw_size", ""),
                      ent_text, sec.get("flags", ""), status)
    return table


def create_strings_table(strings_data):
    """Create a formatted table for suspicious strings found."""
    table = Table(
        title="  [>] Suspicious Strings Extracted",
        box=box.ROUNDED, border_style="yellow", title_style="bold yellow",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Category", style="cyan", width=15)
    table.add_column("String", style="white", min_width=40)
    table.add_column("Location", style="dim", width=15)

    for i, s in enumerate(strings_data[:50], 1):
        table.add_row(str(i), s.get("category", ""), s.get("value", "")[:80], s.get("location", ""))
    return table


def create_yara_table(yara_matches):
    """Create a formatted table for YARA rule matches."""
    table = Table(
        title="  [!] YARA Signature Matches",
        box=box.ROUNDED, border_style="red", title_style="bold red",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Rule", style="bold white", min_width=25)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Category", style="cyan", width=18)
    table.add_column("Description", style="dim white", min_width=30)

    for i, match in enumerate(yara_matches, 1):
        sev = match.get("severity", "MEDIUM")
        style = get_severity_style(sev)
        sev_text = Text(sev, style=style)
        table.add_row(str(i), match.get("rule", ""), sev_text, match.get("category", ""), match.get("description", ""))
    return table


def create_summary_table(findings):
    """Create a compact summary table of all findings."""
    table = Table(
        title="  [=] Analysis Summary",
        box=box.ROUNDED, border_style="cyan", title_style="bold cyan",
        padding=(0, 1),
    )
    table.add_column("Category", style="bold white", min_width=25)
    table.add_column("Findings", justify="center", width=10)
    table.add_column("Highest Risk", justify="center", width=12)

    for cat, data in findings.items():
        count = str(data.get("count", 0))
        risk = data.get("highest_risk", "CLEAN")
        style = get_severity_style(risk)
        risk_text = Text(risk, style=style)
        table.add_row(cat, count, risk_text)
    return table


def create_virustotal_table(vt_result):
    """Create a formatted table for VirusTotal scan results."""
    if vt_result.get("status") != "found":
        return None

    detection_count = vt_result.get("detection_count", 0)
    total = vt_result.get("total_engines", 0)
    ratio = vt_result.get("detection_ratio", 0)
    severity = vt_result.get("severity", "CLEAN")

    # Header info panel
    table = Table(
        title="  [VT] VirusTotal Scan Results",
        box=box.ROUNDED, border_style="magenta", title_style="bold magenta",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("AV Engine", style="bold white", min_width=22)
    table.add_column("Detection", style="bold red", min_width=30)
    table.add_column("Category", justify="center", width=12)

    detections = vt_result.get("detections", [])
    for i, det in enumerate(detections[:25], 1):
        cat = det.get("category", "")
        cat_style = "bold red" if cat == "malicious" else "bold yellow"
        cat_text = Text(cat.upper(), style=cat_style)
        table.add_row(str(i), det.get("engine", ""), det.get("result", ""), cat_text)

    return table

def create_heuristics_table(heuristics_data):
    """Create a styled table for Advanced Heuristics and Anti-Analysis."""
    table = Table(
        title=f"  [HEUR] ADVANCED HEURISTICS & EVASION ({len(heuristics_data)})",
        box=box.MINIMAL_DOUBLE_HEAD, border_style="bold red", title_style="bold red",
        show_lines=True, padding=(0, 1)
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Category", style="bold magenta", width=15)
    table.add_column("Detection", style="bold white", min_width=30)
    table.add_column("Location/File", style="dim cyan", min_width=20)
    table.add_column("Risk", justify="center", width=12)

    for i, h in enumerate(heuristics_data, 1):
        sev = h.get("severity", "MEDIUM")
        sev_text = get_severity_for_score(100 if sev == "CRITICAL" else 75 if sev == "HIGH" else 50)
        table.add_row(str(i), h.get("category", ""), h.get("description", ""), h.get("file", ""), sev_text)
    return table
