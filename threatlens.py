#!/usr/bin/env python3
"""
ThreatLens v1.0.0 — Advanced Malicious APK & EXE Analyzer
Cross-platform static malware analysis tool.

Usage:
    Interactive mode:  python threatlens.py
    CLI mode:          python threatlens.py --file <path> [--output json]
    Batch mode:        python threatlens.py --batch <directory>
"""

import sys
import os
import argparse
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

# Silence noisy libraries (androguard, pefile, etc.)
import logging
logging.getLogger("androguard").setLevel(logging.CRITICAL)
logging.getLogger("androguard.core.axml").setLevel(logging.CRITICAL)
logging.getLogger("pefile").setLevel(logging.CRITICAL)

try:
    from loguru import logger
    logger.remove()  # Remove default handler to stop it from printing to console
except ImportError:
    pass

from ui.theme import RICH_THEME, ICONS, COLORS
from ui.banner import display_banner, display_disclaimer, display_menu
from ui.dashboard import (
    create_progress_bar, display_scan_header,
    display_hash_info, display_threat_score, display_section_header,
    create_status_spinner
)
from ui.tables import (
    create_permissions_table, create_imports_table, create_network_table,
    create_sections_table, create_strings_table, create_yara_table,
    create_summary_table, create_virustotal_table, create_heuristics_table
)
from utils.validators import validate_and_identify, ValidationError, sanitize_path
from utils.hash_calculator import get_file_info
from utils.platform_utils import (
    check_dependencies, get_python_info, clear_screen,
    get_file_size_str, get_reports_dir,
)
from core.apk_analyzer import APKAnalyzer
from core.exe_analyzer import EXEAnalyzer
from core.threat_scorer import ThreatScorer
from core.report_generator import generate_json_report, generate_summary
from core.virustotal import lookup_hash
from core.learning_engine import LearningEngine

# Initialize Rich console with theme
console = Console(theme=RICH_THEME)

# Initialize Learning Engine
learning_engine = LearningEngine()


def main():
    """Main entry point."""
    args = parse_args()

    if args.import_intel:
        # Import custom intel DB
        success, message = learning_engine.import_custom_db(args.import_intel)
        if success:
            console.print(f"  [bold green]{ICONS['shield']} {message}[/]")
        else:
            console.print(f"  [bold red]{ICONS['cross']} {message}[/]")
        sys.exit(0 if success else 1)
        
    if args.file:
        # CLI mode — direct file analysis
        run_cli_analysis(args.file, args.output)
    elif args.batch:
        # Batch mode — scan directory
        run_batch_scan(args.batch, args.output)
    else:
        # Interactive mode
        run_interactive()


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="ThreatLens — Advanced Malicious APK & EXE Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python threatlens.py                          # Interactive mode
  python threatlens.py --file malware.apk       # Analyze single file
  python threatlens.py --file sample.exe -o json # Analyze with JSON output
  python threatlens.py --batch ./samples/       # Batch scan directory
  python threatlens.py --import-intel db.json   # Import custom intel DB
        """
    )
    parser.add_argument("--file", "-f", help="Path to APK or EXE file to analyze")
    parser.add_argument("--batch", "-b", help="Directory path for batch scanning")
    parser.add_argument("--import-intel", help="Path to custom JSON threat intel DB to import")
    parser.add_argument("--output", "-o", choices=["console", "json", "both"],
                        default="both", help="Output format (default: both)")
    return parser.parse_args()


def run_interactive():
    """Run the interactive menu-driven interface."""
    clear_screen()
    display_banner(console, animated=True)
    display_disclaimer(console)

    while True:
        display_menu(console)
        console.print()
        choice = console.input(f"  [bold cyan]{ICONS['arrow_right']} Select option (1-6): [/]").strip()

        if choice == "1":
            interactive_analyze("APK")
        elif choice == "2":
            interactive_analyze("EXE")
        elif choice == "3":
            interactive_batch_scan()
        elif choice == "4":
            view_reports()
        elif choice == "5":
            show_settings()
        elif choice == "6":
            console.print(f"\n  [bold cyan]{ICONS['shield']} ThreatLens shutting down. Stay safe![/]\n")
            sys.exit(0)
        else:
            console.print(f"  [bold red]{ICONS['cross']} Invalid option. Please select 1-6.[/]")
            time.sleep(1)


def interactive_analyze(expected_type=None):
    """Interactively get file path and run analysis."""
    console.print()
    console.print(f"  [bold cyan]{ICONS['scan']} FILE ANALYSIS[/]")
    console.print(f"  [dim]Enter the file path, drag & drop, or [bold white]leave blank to open GUI Picker[/].[/]")
    console.print(f"  [dim]Type 'back' to return to menu.[/]")
    console.print()

    file_path = console.input(f"  [bold cyan]{ICONS['arrow']} File path (Press Enter for GUI): [/]").strip()

    if file_path.lower() in ("back", "exit", "quit", "q"):
        return

    if not file_path:
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            console.print(f"  [cyan]{ICONS['scan']} Opening GUI File Picker...[/]")
            file_path = filedialog.askopenfilename(
                title="Select File for Analysis",
                filetypes=[("All Supported", "*.apk *.exe"), ("APK Files", "*.apk"), ("Executables", "*.exe"), ("All Files", "*.*")]
            )
            if not file_path:
                console.print("  [dim]No file selected. Returning to menu.[/]")
                time.sleep(1)
                return
            console.print(f"  [dim]Selected:[/] {file_path}")
        except Exception:
            console.print(f"  [bold red]{ICONS['cross']} GUI not available. Please type the path manually.[/]")
            time.sleep(1)
            return

    file_path = sanitize_path(file_path)
    path_obj = Path(file_path)
    
    if path_obj.is_dir():
        console.print(f"  [cyan]{ICONS['folder']} Directory detected. Switching to batch scan...[/]")
        run_batch_scan(file_path, "both")
    else:
        run_analysis(file_path, "both")


def run_analysis(file_path, output_format="both"):
    """Run complete analysis on a single file."""
    console.print()

    # === VALIDATION ===
    try:
        validation = validate_and_identify(file_path)
    except ValidationError as e:
        console.print(f"  [bold red]{ICONS['cross']} Validation Error:[/] {e}")
        console.print()
        console.input("  [dim]Press Enter to continue...[/]")
        return

    file_type = validation["type_info"]["type"]
    file_path_obj = validation["path"]

    # === FILE INFO & HASHES ===
    file_info = get_file_info(file_path_obj)
    display_scan_header(console, file_info, validation["type_info"]["description"])
    display_hash_info(console, file_info["hashes"])

    # === ANALYSIS ===
    with create_status_spinner(console, "Initializing Analysis Engine") as status:
        def update_status(phase, pct):
            status.update(f"[bold cyan]{phase}... [dim]({pct}%)[/]")

        if file_type == "APK":
            analyzer = APKAnalyzer()
            results = analyzer.analyze(file_path_obj, progress_callback=update_status)
        elif file_type in ("EXE", "DOS"):
            analyzer = EXEAnalyzer()
            results = analyzer.analyze(file_path_obj, progress_callback=update_status)
        else:
            console.print(f"  [bold red]{ICONS['cross']} Unsupported file type: {file_type}[/]")
            console.input("  [dim]Press Enter to continue...[/]")
            return

        # Local Intel Check
        status.update("[bold magenta]Scanning Local Threat Database...")
        local_intel_hits = learning_engine.check_local_intel(file_info["hashes"]["sha256"], results)
        results["local_intel"] = local_intel_hits

        # VirusTotal Lookup
        status.update("[bold cyan]Querying VirusTotal Intelligence...")
        vt_result = lookup_hash(file_info["hashes"]["sha256"])
        results["virustotal"] = vt_result
            
        # Train Learning Engine
        if learning_engine.learn_from_scan(results, vt_result):
            status.update("[bold green]Updating Local Intelligence Engine...")
            time.sleep(0.5)

    # === THREAT SCORING ===
    scorer = ThreatScorer()
    if file_type == "APK":
        score, severity, breakdown = scorer.calculate_apk_score(results)
    else:
        score, severity, breakdown = scorer.calculate_exe_score(results)

    # === DISPLAY RESULTS ===
    display_threat_score(console, score, breakdown)
    _display_analysis_results(results, file_type)

    # === SUMMARY TABLE ===
    summary = generate_summary(results, file_type)
    console.print()
    console.print(create_summary_table(summary))

    # === ERRORS ===
    errors = results.get("errors", [])
    if errors:
        display_section_header(console, "WARNINGS & ERRORS", ICONS["warning"])
        for err in errors:
            console.print(f"    [yellow][!] {err}[/]")

    # === SAVE REPORT ===
    try:
        report_path = generate_json_report(results, file_info, score, severity, breakdown, file_type)
        console.print()
        console.print(Panel(
            f"  [bold green]{ICONS['check']} Report saved:[/] [white]{report_path}[/]",
            border_style="green",
            box=box.ROUNDED,
        ))
    except Exception as e:
        console.print(f"  [yellow][!] Could not save report: {e}[/]")

    console.print()
    console.input("  [dim]Press Enter to continue...[/]")


def _display_analysis_results(results, file_type):
    """Display detailed analysis results with formatted tables."""

    if file_type == "APK":
        # Manifest info
        manifest = results.get("manifest", {})
        if manifest:
            display_section_header(console, "MANIFEST INFORMATION", ICONS["package"])
            for key, value in manifest.items():
                if key not in ("note",):
                    display_val = str(value)
                    if isinstance(value, bool):
                        display_val = f"[bold red]Yes[/]" if value else f"[green]No[/]"
                    console.print(f"    [dim]{key.replace('_', ' ').title()}:[/] {display_val}")

        # Permissions table
        perms = results.get("permissions", [])
        if perms:
            console.print()
            risk_perms = [p for p in perms if p.get("risk") != "INFO"]
            if risk_perms:
                console.print(create_permissions_table(risk_perms))
            else:
                console.print(f"    [green]{ICONS['check']} No dangerous permissions detected[/]")

        # Permission combinations
        combos = results.get("permission_combinations", [])
        if combos:
            display_section_header(console, "DANGEROUS PERMISSION COMBINATIONS", ICONS['alert'])
            for combo in combos:
                console.print(f"    [bold red][!!] {combo['threat']}[/]")
                console.print(f"       [dim]{combo['description']}[/]")
                console.print(f"       [dim]Permissions: {', '.join(combo['permissions'])}[/]")
                console.print()

        # Certificate
        cert = results.get("certificate", {})
        if cert and not cert.get("error"):
            display_section_header(console, "CERTIFICATE ANALYSIS", ICONS["key"])
            for key, value in cert.items():
                if key not in ("error", "note"):
                    display_val = str(value)
                    if key == "self_signed":
                        display_val = f"[bold red]Yes (SUSPICIOUS)[/]" if value else f"[green]No[/]"
                    console.print(f"    [dim]{key.replace('_', ' ').title()}:[/] {display_val}")

        # Native libraries
        native = results.get("native_libs", [])
        if native:
            display_section_header(console, "NATIVE LIBRARIES", ICONS["package"])
            for lib in native:
                console.print(f"    [white]{lib['name']}[/] | "
                              f"[dim]Size: {get_file_size_str(lib['size'])}[/] | "
                              f"[dim]Arch: {lib['architecture']}[/] | "
                              f"[dim]Entropy: {lib['entropy']:.2f}[/]")

    elif file_type in ("EXE", "DOS"):
        # PE Info
        pe_info = results.get("pe_info", {})
        if pe_info:
            display_section_header(console, "PE HEADER INFORMATION", ICONS["computer"])
            display_items = [
                ("Machine Type", pe_info.get("machine_type", "")),
                ("Entry Point", pe_info.get("entry_point", "")),
                ("Compile Time", pe_info.get("compile_time", "")),
                ("Subsystem", pe_info.get("subsystem", "")),
                ("ASLR", "[green]Enabled[/]" if pe_info.get("aslr_enabled") else "[red]Disabled[/]"),
                ("DEP", "[green]Enabled[/]" if pe_info.get("dep_enabled") else "[red]Disabled[/]"),
            ]
            for label, value in display_items:
                console.print(f"    [dim]{label}:[/] {value}")

        # Sections table
        sections = results.get("sections", [])
        if sections:
            console.print()
            console.print(create_sections_table(sections))

        # Suspicious imports table
        imports = results.get("suspicious_imports", [])
        if imports:
            console.print()
            console.print(create_imports_table(imports))
        else:
            display_section_header(console, "API IMPORTS", ICONS["check"])
            console.print(f"    [green]{ICONS['check']} No suspicious API imports detected[/]")

        # Import combinations (MITRE ATT&CK)
        combos = results.get("import_combinations", [])
        if combos:
            display_section_header(console, "DETECTED ATTACK TECHNIQUES (MITRE ATT&CK)", ICONS["alert"])
            for combo in combos:
                console.print(f"    [bold red][!!] {combo['technique']}[/] "
                              f"[dim](MITRE: {combo.get('mitre', 'N/A')})[/]")
                console.print(f"       [dim]Imports: {', '.join(combo['imports'])}[/]")
                console.print()

        # Packers
        packers = results.get("packers", [])
        if packers:
            display_section_header(console, "PACKER/PROTECTOR DETECTION", ICONS["lock"])
            for p in packers:
                console.print(f"    [bold yellow][!] {p['packer']}[/] "
                              f"[dim](Confidence: {p['confidence']}%, Section: {p['section']})[/]")
                console.print(f"       [dim]{p['description']}[/]")

    # === COMMON SECTIONS ===

    # Advanced Heuristics & Evasion
    heuristics = results.get("heuristics", [])
    if heuristics:
        console.print()
        console.print(create_heuristics_table(heuristics))

    # Local Intel Matches
    local_intel = results.get("local_intel", [])
    if local_intel:
        display_section_header(console, "LOCAL THREAT INTELLIGENCE MATCHES", ICONS["shield"])
        for hit in local_intel:
            console.print(f"    [bold red][!!] {hit['threat']}[/]")
            console.print(f"       [dim]Type:[/] {hit['type']}")
            console.print(f"       [dim]Value:[/] {hit['value']}")
            console.print()

    # VirusTotal table
    vt = results.get("virustotal", {})
    if vt and vt.get("status") == "found":
        console.print()
        vt_table = create_virustotal_table(vt)
        if vt_table:
            console.print(vt_table)
            console.print(f"    [dim]Permalink:[/] [cyan underline]{vt.get('permalink')}[/]")

    # Network indicators table
    network = results.get("network", [])
    if network:
        console.print()
        console.print(create_network_table(network))
    else:
        display_section_header(console, "NETWORK INDICATORS", ICONS["globe"])
        console.print(f"    [green]{ICONS['check']} No suspicious network indicators detected[/]")

    # YARA matches
    yara = results.get("yara", [])
    if yara:
        console.print()
        console.print(create_yara_table(yara))

    # Suspicious strings
    strings = results.get("suspicious_strings", [])
    if strings:
        console.print()
        console.print(create_strings_table(strings[:30]))
        if len(strings) > 30:
            console.print(f"    [dim]... and {len(strings) - 30} more strings (see full report)[/]")


def run_cli_analysis(file_path, output_format):
    """Run analysis in CLI mode (non-interactive)."""
    display_banner(console, animated=False)
    run_analysis(file_path, output_format)


def run_batch_scan(directory, output_format):
    """Scan all APK/EXE files in a directory."""
    console.print()
    display_section_header(console, "BATCH SCAN", ICONS["folder"])

    dir_path = Path(directory)
    if not dir_path.is_dir():
        console.print(f"  [bold red]{ICONS['cross']} Not a valid directory: {directory}[/]")
        return

    # Find all APK and EXE files
    files = []
    for ext in ("*.apk", "*.exe"):
        files.extend(dir_path.glob(ext))
        files.extend(dir_path.rglob(ext))

    # Deduplicate
    files = list(set(files))

    if not files:
        console.print(f"  [yellow][!] No APK or EXE files found in {directory}[/]")
        return

    console.print(f"  [cyan]Found {len(files)} file(s) to analyze[/]")
    console.print()

    for i, file in enumerate(files, 1):
        console.print(f"\n  [bold cyan]=== File {i}/{len(files)}: {file.name} ===[/]")
        try:
            run_analysis(str(file), output_format)
        except Exception as e:
            console.print(f"  [bold red]{ICONS['cross']} Error analyzing {file.name}: {e}[/]")


def interactive_batch_scan():
    """Interactive batch scan prompt."""
    console.print()
    console.print(f"  [bold cyan]{ICONS['folder']} BATCH SCAN[/]")
    console.print(f"  [dim]Enter the directory path, or [bold white]leave blank to open GUI Picker[/].[/]")
    console.print()

    dir_path = console.input(f"  [bold cyan]{ICONS['arrow']} Directory path (Press Enter for GUI): [/]").strip()

    if dir_path.lower() in ("back", "exit", "quit", "q"):
        return

    if not dir_path:
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            console.print(f"  [cyan]{ICONS['folder']} Opening GUI Directory Picker...[/]")
            dir_path = filedialog.askdirectory(title="Select Directory for Batch Scan")
            
            if not dir_path:
                console.print("  [dim]No directory selected. Returning to menu.[/]")
                time.sleep(1)
                return
            console.print(f"  [dim]Selected:[/] {dir_path}")
        except Exception:
            console.print(f"  [bold red]{ICONS['cross']} GUI not available. Please type the path manually.[/]")
            time.sleep(1)
            return

    dir_path = sanitize_path(dir_path)
    run_batch_scan(dir_path, "both")


def view_reports():
    """View previously generated reports."""
    console.print()
    display_section_header(console, "PREVIOUS REPORTS", ICONS["report"])

    reports_dir = get_reports_dir()
    reports = sorted(reports_dir.glob("threatlens_*.json"), reverse=True)

    if not reports:
        console.print(f"    [dim]No reports found in {reports_dir}[/]")
        console.input("\n  [dim]Press Enter to continue...[/]")
        return

    for i, report in enumerate(reports[:20], 1):
        size = get_file_size_str(report.stat().st_size)
        name = report.stem.replace("threatlens_", "")
        console.print(f"    [cyan][{i:2d}][/] {name} [dim]({size})[/]")

    console.print(f"\n    [dim]Reports directory: {reports_dir}[/]")
    console.input("\n  [dim]Press Enter to continue...[/]")


def show_settings():
    """Display settings and system information."""
    console.print()
    display_section_header(console, "SETTINGS & SYSTEM INFO", ICONS["settings"])

    # Python info
    py_info = get_python_info()
    console.print(f"\n    [bold cyan]Python Runtime[/]")
    for key, value in py_info.items():
        console.print(f"    [dim]{key.replace('_', ' ').title()}:[/] {value}")

    # Dependencies
    console.print(f"\n    [bold cyan]Dependencies[/]")
    deps = check_dependencies()
    for pkg, info in deps.items():
        status = f"[bold green]{ICONS['check']} Installed[/]" if info["installed"] else f"[bold red]{ICONS['cross']} Missing[/]"
        req = "[red](required)[/]" if info["required"] else "[dim](optional)[/]"
        console.print(f"    {status}  {pkg:15s} {req} — {info['purpose']}")

    # Missing required dependencies warning
    missing_required = [pkg for pkg, info in deps.items() if info["required"] and not info["installed"]]
    if missing_required:
        console.print()
        console.print(Panel(
            f"  [bold red][!] Missing required dependencies: {', '.join(missing_required)}[/]\n"
            f"  [white]Run: pip install -r requirements.txt[/]",
            border_style="red",
            box=box.ROUNDED,
        ))

    console.input("\n  [dim]Press Enter to continue...[/]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(f"\n  [bold cyan]{ICONS['shield']} Interrupted. Exiting ThreatLens.[/]\n")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n  [bold red]Fatal error: {e}[/]")
        console.print_exception()
        sys.exit(1)
