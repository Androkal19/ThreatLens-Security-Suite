"""
ThreatLens - Platform Utilities
Cross-platform compatibility helpers for Windows and Linux.
"""

import os
import sys
import platform
import shutil
from pathlib import Path


def get_os_name():
    """Get the normalized OS name."""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "linux":
        return "linux"
    elif system == "darwin":
        return "macos"
    return system


def is_windows():
    """Check if running on Windows."""
    return platform.system().lower() == "windows"


def is_linux():
    """Check if running on Linux."""
    return platform.system().lower() == "linux"


def get_terminal_size():
    """Get terminal width and height with fallback."""
    try:
        size = shutil.get_terminal_size((120, 40))
        return size.columns, size.lines
    except Exception:
        return 120, 40


def supports_color():
    """Check if the terminal supports color output."""
    # Check for NO_COLOR environment variable (standard)
    if os.environ.get("NO_COLOR"):
        return False

    # Check for FORCE_COLOR
    if os.environ.get("FORCE_COLOR"):
        return True

    # Windows Terminal, VS Code, and modern terminals support color
    if is_windows():
        # Check for Windows Terminal or modern PowerShell
        if os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM"):
            return True
        # Enable ANSI escape codes on Windows
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            pass

    # Unix-like systems
    if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        return True

    return False


def normalize_path(path_str):
    """Normalize a file path for the current OS."""
    return str(Path(path_str).resolve())


def get_reports_dir():
    """Get the reports output directory, creating it if needed."""
    base_dir = Path(__file__).parent.parent / "reports"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir


def get_signatures_dir():
    """Get the signatures directory."""
    return Path(__file__).parent.parent / "signatures"


def clear_screen():
    """Clear the terminal screen in a cross-platform way."""
    if is_windows():
        os.system("cls")
    else:
        os.system("clear")


def get_file_size_str(size_bytes):
    """Convert bytes to human-readable file size string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def check_dependencies():
    """Check if all required dependencies are installed and return status."""
    dependencies = {
        "rich": {"required": True, "purpose": "Terminal UI rendering"},
        "pefile": {"required": True, "purpose": "PE/EXE file analysis"},
        "androguard": {"required": True, "purpose": "APK file analysis"},
        "yara": {"required": False, "purpose": "YARA rule scanning (enhanced detection)"},
        "requests": {"required": False, "purpose": "Network lookups and VirusTotal integration"},
        "capstone": {"required": False, "purpose": "Disassembly engine (advanced analysis)"},
    }

    results = {}
    for pkg, info in dependencies.items():
        try:
            __import__(pkg)
            results[pkg] = {"installed": True, **info}
        except ImportError:
            results[pkg] = {"installed": False, **info}

    return results


def get_python_info():
    """Get Python runtime information."""
    return {
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "architecture": platform.architecture()[0],
        "machine": platform.machine(),
    }
