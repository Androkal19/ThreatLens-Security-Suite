"""
ThreatLens - Dashboard
Rich Live display for real-time scan progress and status updates.
"""

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich import box
from ui.theme import ICONS, get_severity_for_score


def create_progress_bar():
    """Create a styled progress bar for scan phases."""
    return Progress(
        SpinnerColumn(spinner_name="dots12", style="bold cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, style="dim", complete_style="cyan", finished_style="green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        transient=True,
    )


def create_status_spinner(console, message):
    """Create a high-tech status spinner."""
    return console.status(
        f"[bold cyan]{message}...",
        spinner="dots12",
        spinner_style="bold cyan"
    )


def display_scan_header(console, file_info, file_type):
    """Display the scan header with file information."""
    size_bytes = file_info.get("size_bytes", 0)
    if size_bytes < 1024 * 1024:
        size_str = f"{size_bytes / 1024:.2f} KB"
    else:
        size_str = f"{size_bytes / (1024 * 1024):.2f} MB"

    text = Text()
    text.append(f"\n  {ICONS['scan']} SCANNING: ", style="bold cyan")
    text.append(f"{file_info.get('filename', 'Unknown')}\n", style="bold white")
    text.append(f"  {'-' * 60}\n", style="dim cyan")
    text.append(f"  Type: ", style="dim")
    text.append(f"{file_type}  |  ", style="white")
    text.append(f"Size: ", style="dim")
    text.append(f"{size_str}\n", style="white")
    text.append(f"  Path: ", style="dim")
    text.append(f"{file_info.get('filepath', 'N/A')}\n", style="dim white")

    console.print(Panel(text, border_style="cyan", box=box.ROUNDED, padding=(0, 1)))


def display_hash_info(console, hashes):
    """Display file hash information."""
    text = Text()
    text.append(f"\n  {ICONS['fingerprint']} FILE HASHES\n", style="bold cyan")
    text.append(f"  {'-' * 60}\n", style="dim cyan")
    for algo, value in hashes.items():
        text.append(f"  {algo.upper():>6}: ", style="dim")
        text.append(f"{value}\n", style="dim white")
    console.print(Panel(text, border_style="dim cyan", box=box.ROUNDED, padding=(0, 1)))


def display_threat_score(console, score, breakdown=None):
    """Display the overall threat score with visual gauge."""
    severity, config = get_severity_for_score(score)
    bar_width = 50
    filled = int((score / 100) * bar_width)
    colors = {80: "red", 60: "dark_orange", 40: "yellow", 20: "green", 0: "bright_green"}
    bar_color = next(c for t, c in sorted(colors.items(), reverse=True) if score >= t)

    text = Text()
    text.append(f"\n  {ICONS['target']} THREAT ASSESSMENT\n", style="bold white")
    text.append(f"  {'-' * 60}\n\n", style="dim cyan")
    text.append(f"  Score: ", style="dim")
    text.append(f"{score}", style=f"bold {bar_color}")
    text.append(f" / 100  |  Level: ", style="dim")
    text.append(f"{config['icon']} {severity}\n\n", style=f"bold {bar_color}")
    text.append(f"  [", style="dim")
    text.append("#" * filled, style=bar_color)
    text.append("." * (bar_width - filled), style="dim")
    text.append(f"] {score}%\n", style="dim")

    if breakdown:
        text.append(f"\n  Score Breakdown:\n", style="dim white")
        for cat, pts in breakdown.items():
            if pts > 0:
                text.append(f"    {cat}: +{pts}\n", style=bar_color)

    console.print(Panel(text, title=f"[bold {bar_color}]=== THREAT SCORE ===[/]",
                        title_align="center", border_style=bar_color, box=box.DOUBLE_EDGE, padding=(0, 1)))


def display_section_header(console, title, icon=""):
    """Display a section header."""
    console.print()
    console.print(f"  [bold cyan]{icon} {title}[/]")
    console.print(f"  [dim cyan]{'-' * 60}[/]")
