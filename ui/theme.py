"""
ThreatLens - Theme Configuration
Centralized color palette, styles, and icons for consistent UI rendering.
Cybersecurity-inspired design with neon accents on dark background.
"""

from rich.style import Style
from rich.theme import Theme


# ============================================================================
# COLOR PALETTE — Cybersecurity Neon Dark Theme
# ============================================================================

COLORS = {
    # Primary brand colors
    "primary": "#00d4ff",       # Electric cyan
    "primary_dim": "#0098b3",   # Dimmed cyan
    "secondary": "#7c3aed",     # Purple accent
    "accent": "#f59e0b",        # Amber accent

    # Severity colors
    "critical": "#ff1744",      # Bright red
    "high": "#ff6d00",          # Orange
    "medium": "#ffd600",        # Yellow
    "low": "#00e676",           # Green
    "clean": "#00c853",         # Bright green
    "info": "#448aff",          # Blue

    # Background and text
    "bg_dark": "#0a0e17",       # Deep navy
    "bg_panel": "#111827",      # Panel background
    "bg_highlight": "#1e293b",  # Highlighted row
    "text": "#e2e8f0",          # Light gray text
    "text_dim": "#64748b",      # Dimmed text
    "text_muted": "#475569",    # Very dim text

    # Special
    "success": "#10b981",       # Emerald green
    "warning": "#f59e0b",       # Amber
    "error": "#ef4444",         # Red
    "border": "#334155",        # Subtle border
    "highlight": "#06b6d4",     # Cyan highlight
}


# ============================================================================
# SEMANTIC STYLES
# ============================================================================

STYLES = {
    # Severity styles
    "critical": Style(color=COLORS["critical"], bold=True),
    "high": Style(color=COLORS["high"], bold=True),
    "medium": Style(color=COLORS["medium"]),
    "low": Style(color=COLORS["low"]),
    "clean": Style(color=COLORS["clean"]),
    "info": Style(color=COLORS["info"]),

    # UI element styles
    "title": Style(color=COLORS["primary"], bold=True),
    "subtitle": Style(color=COLORS["primary_dim"]),
    "header": Style(color=COLORS["primary"], bold=True, underline=True),
    "label": Style(color=COLORS["text_dim"]),
    "value": Style(color=COLORS["text"]),
    "highlight": Style(color=COLORS["highlight"], bold=True),
    "muted": Style(color=COLORS["text_muted"]),
    "dim": Style(color=COLORS["text_dim"]),

    # Status styles
    "success": Style(color=COLORS["success"], bold=True),
    "warning": Style(color=COLORS["warning"], bold=True),
    "error": Style(color=COLORS["error"], bold=True),

    # Table styles
    "table_header": Style(color=COLORS["primary"], bold=True),
    "table_row": Style(color=COLORS["text"]),
    "table_row_alt": Style(color=COLORS["text_dim"]),
    "table_border": Style(color=COLORS["border"]),

    # Special
    "ip_address": Style(color="#ff6b6b", bold=True),
    "port": Style(color="#ffa726", bold=True),
    "url": Style(color="#42a5f5", underline=True),
    "hash": Style(color=COLORS["text_dim"]),
    "permission": Style(color="#ce93d8"),
    "import_name": Style(color="#80cbc4"),
}


# ============================================================================
# ICONS AND SYMBOLS
# ============================================================================

ICONS = {
    # Status icons
    "check": "v",
    "cross": "x",
    "warning": "!",
    "info": "i",
    "bullet": "*",
    "arrow": "->",
    "arrow_right": ">",
    "star": "*",

    # Category icons
    "shield": "[SHIELD]",
    "lock": "[LOCK]",
    "unlock": "[UNLOCK]",
    "key": "[KEY]",
    "fire": "[FIRE]",
    "skull": "[SKULL]",
    "bug": "[BUG]",
    "eye": "[EYE]",
    "target": "[TARGET]",
    "globe": "[NET]",
    "folder": "[DIR]",
    "file": "[FILE]",
    "phone": "[APK]",
    "computer": "[EXE]",
    "network": "[NET]",
    "alert": "[ALERT]",
    "scan": "[SCAN]",
    "report": "[REPORT]",
    "settings": "[SETTINGS]",
    "exit": "[EXIT]",
    "clock": "[TIME]",
    "package": "[PKG]",
    "chart": "[CHART]",
    "link": "[LINK]",
    "fingerprint": "[FINGERPRINT]",
}


# ============================================================================
# SEVERITY LEVEL CONFIGURATION
# ============================================================================

SEVERITY_CONFIG = {
    "CRITICAL": {
        "color": COLORS["critical"],
        "icon": "[!!]",
        "label": "CRITICAL",
        "style": STYLES["critical"],
        "score_range": (80, 100),
    },
    "HIGH": {
        "color": COLORS["high"],
        "icon": "[!]",
        "label": "HIGH",
        "style": STYLES["high"],
        "score_range": (60, 79),
    },
    "MEDIUM": {
        "color": COLORS["medium"],
        "icon": "[-]",
        "label": "MEDIUM",
        "style": STYLES["medium"],
        "score_range": (40, 59),
    },
    "LOW": {
        "color": COLORS["low"],
        "icon": "[v]",
        "label": "LOW",
        "style": STYLES["low"],
        "score_range": (20, 39),
    },
    "CLEAN": {
        "color": COLORS["clean"],
        "icon": "[OK]",
        "label": "CLEAN",
        "style": STYLES["clean"],
        "score_range": (0, 19),
    },
}


def get_severity_for_score(score):
    """Get severity level configuration based on threat score."""
    score = max(0, min(100, score))
    for severity, config in SEVERITY_CONFIG.items():
        low, high = config["score_range"]
        if low <= score <= high:
            return severity, config
    return "CLEAN", SEVERITY_CONFIG["CLEAN"]


def get_severity_style(severity):
    """Get the Rich style for a severity level."""
    severity = severity.upper()
    if severity in SEVERITY_CONFIG:
        return SEVERITY_CONFIG[severity]["style"]
    return STYLES["info"]


# ============================================================================
# RICH THEME (for Console)
# ============================================================================

RICH_THEME = Theme({
    "critical": "bold red",
    "high": "bold dark_orange",
    "medium": "yellow",
    "low": "green",
    "clean": "bold green",
    "info": "blue",
    "title": "bold cyan",
    "subtitle": "dim cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "muted": "dim",
    "ip": "bold red",
    "port": "bold dark_orange",
    "url": "underline blue",
})
