"""
ThreatLens - ASCII Art Banner
Professional branding and startup display.
"""

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.align import Align
from rich import box
import time

from ui.theme import COLORS, ICONS

VERSION = "1.0.0"
AUTHOR = "ThreatLens Security Research"
CODENAME = "Sentinel"

BANNER_ART = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗██╗     ███████╗███╗   ██╗███████╗  ║
║   ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║     ██╔════╝████╗  ██║██╔════╝  ║
║      ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██║     █████╗  ██╔██╗ ██║███████╗  ║
║      ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║     ██╔══╝  ██║╚██╗██║╚════██║  ║
║      ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ███████╗███████╗██║ ╚████║███████║  ║
║      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝"""

BANNER_SIMPLE = r"""
  _____ _                    _   _
 |_   _| |__  _ __ ___  __ _| |_| |    ___ _ __  ___
   | | | '_ \| '__/ _ \/ _` | __| |   / _ \ '_ \/ __|
   | | | | | | | |  __/ (_| | |_| |__|  __/ | | \__ \
   |_| |_| |_|_|  \___|\__,_|\__|_____\___|_| |_|___/
"""


def display_banner(console: Console, animated=True):
    """
    Display the ThreatLens banner with optional animation.

    Args:
        console: Rich Console instance.
        animated: Whether to show loading animation.
    """
    console.clear()

    # Display the banner
    banner_text = Text(BANNER_SIMPLE, style="bold cyan")

    tagline = Text.assemble(
        ("  ╔══════════════════════════════════════════════════════════════════╗\n", "dim cyan"),
        ("  ║", "dim cyan"),
        ("  🛡️  Advanced Malicious APK & EXE Analyzer", "bold white"),
        ("                       ║\n", "dim cyan"),
        ("  ║", "dim cyan"),
        (f"  Version {VERSION}", "dim white"),
        (" │ ", "dim cyan"),
        (f"Codename: {CODENAME}", "dim yellow"),
        (" │ ", "dim cyan"),
        ("Cross-Platform", "dim green"),
        ("          ║\n", "dim cyan"),
        ("  ╚══════════════════════════════════════════════════════════════════╝\n", "dim cyan"),
    )

    console.print(banner_text)
    console.print(tagline)

    if animated:
        _animated_startup(console)


def _animated_startup(console: Console):
    """Show an animated startup sequence."""
    modules = [
        ("Initializing analysis engine", "✓"),
        ("Loading YARA signature database", "✓"),
        ("Loading suspicious imports database", "✓"),
        ("Loading permissions database", "✓"),
        ("Checking platform compatibility", "✓"),
        ("System ready", "★"),
    ]

    for label, icon in modules:
        console.print(
            f"  [dim cyan]{'─' * 3}[/] [dim white]{label}[/] ", end=""
        )
        time.sleep(0.15)
        console.print(f"[bold green]{icon}[/]")

    console.print()


def display_disclaimer(console: Console):
    """Display the legal disclaimer."""
    disclaimer = (
        "[dim yellow]⚠  DISCLAIMER:[/dim yellow] "
        "[dim white]This tool is designed for authorized security analysis only. "
        "Unauthorized use of this tool against systems you do not own or have "
        "permission to test is illegal and unethical. The authors accept no "
        "liability for misuse of this tool.[/dim white]"
    )

    console.print(
        Panel(
            disclaimer,
            border_style="dim yellow",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    console.print()


def display_menu(console: Console):
    """Display the main interactive menu."""
    menu_items = [
        ("1", f"{ICONS['phone']} Analyze APK File", "Static analysis of Android packages"),
        ("2", f"{ICONS['computer']} Analyze EXE File", "Static analysis of Windows executables"),
        ("3", f"{ICONS['folder']} Batch Scan Directory", "Scan all APK/EXE files in a folder"),
        ("4", f"{ICONS['report']} View Previous Reports", "Browse saved analysis reports"),
        ("5", f"{ICONS['settings']} Settings & Info", "Dependencies, platform info, config"),
        ("6", f"{ICONS['exit']} Exit", "Close ThreatLens"),
    ]

    menu_text = Text()
    for key, label, desc in menu_items:
        menu_text.append(f"\n  [{key}]", style="bold cyan")
        menu_text.append(f"  {label}", style="white")
        menu_text.append(f"  — {desc}", style="dim")

    menu_text.append("\n")

    console.print(
        Panel(
            Align.left(menu_text),
            title="[bold cyan]━━━ MAIN MENU ━━━[/]",
            title_align="center",
            border_style="cyan",
            box=box.DOUBLE_EDGE,
            padding=(0, 2),
        )
    )
