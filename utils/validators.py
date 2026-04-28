"""
ThreatLens - Input Validators
File validation, type checking, and input sanitization.
"""

import os
import struct
from pathlib import Path


# Magic bytes for file type detection
MAGIC_BYTES = {
    "APK": {
        "signature": b"PK\x03\x04",
        "offset": 0,
        "description": "Android Package (ZIP archive)",
    },
    "EXE": {
        "signature": b"MZ",
        "offset": 0,
        "description": "Windows Portable Executable",
    },
    "ELF": {
        "signature": b"\x7fELF",
        "offset": 0,
        "description": "Linux Executable (ELF)",
    },
    "DEX": {
        "signature": b"dex\n",
        "offset": 0,
        "description": "Android Dalvik Executable",
    },
}

# Maximum file size for analysis (500 MB)
MAX_FILE_SIZE = 500 * 1024 * 1024

# Minimum file size (files smaller than this are unlikely to be valid)
MIN_FILE_SIZE = 100


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


def validate_file_exists(file_path):
    """
    Validate that a file exists and is readable.

    Args:
        file_path: Path to the file to validate.

    Returns:
        Path: Resolved Path object.

    Raises:
        ValidationError: If the file doesn't exist or isn't readable.
    """
    path = Path(file_path).resolve()

    if not path.exists():
        raise ValidationError(f"File not found: {path}")

    if not path.is_file():
        raise ValidationError(f"Not a file: {path}")

    if not os.access(str(path), os.R_OK):
        raise ValidationError(f"File is not readable: {path}")

    return path


def validate_file_size(file_path):
    """
    Validate file size is within acceptable bounds.

    Args:
        file_path: Path to the file.

    Returns:
        int: File size in bytes.

    Raises:
        ValidationError: If file is too large or too small.
    """
    path = Path(file_path)
    size = path.stat().st_size

    if size > MAX_FILE_SIZE:
        raise ValidationError(
            f"File too large: {size / (1024*1024):.1f} MB "
            f"(maximum: {MAX_FILE_SIZE / (1024*1024):.0f} MB)"
        )

    if size < MIN_FILE_SIZE:
        raise ValidationError(
            f"File too small ({size} bytes) — unlikely to be a valid executable"
        )

    return size


def detect_file_type(file_path):
    """
    Detect file type using magic bytes (not file extension).
    This prevents false identification from renamed files.

    Args:
        file_path: Path to the file to analyze.

    Returns:
        dict: File type information with keys: type, description, extension.

    Raises:
        ValidationError: If file type cannot be determined.
    """
    path = Path(file_path)

    try:
        with open(path, "rb") as f:
            header = f.read(64)
    except IOError as e:
        raise ValidationError(f"Cannot read file: {e}")

    if len(header) < 4:
        raise ValidationError("File is too small to identify")

    # Check for APK (ZIP with specific contents)
    if header[:4] == MAGIC_BYTES["APK"]["signature"]:
        # Further verify it's an APK by checking for AndroidManifest.xml
        if _is_apk(path):
            return {
                "type": "APK",
                "description": "Android Application Package",
                "extension": ".apk",
                "mime": "application/vnd.android.package-archive",
            }
        else:
            return {
                "type": "ZIP",
                "description": "ZIP Archive (not an APK)",
                "extension": ".zip",
                "mime": "application/zip",
            }

    # Check for PE/EXE
    if header[:2] == MAGIC_BYTES["EXE"]["signature"]:
        # Verify PE signature at the offset specified in DOS header
        if len(header) >= 64:
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            try:
                with open(path, "rb") as f:
                    f.seek(pe_offset)
                    pe_sig = f.read(4)
                    if pe_sig == b"PE\x00\x00":
                        return {
                            "type": "EXE",
                            "description": "Windows Portable Executable",
                            "extension": ".exe",
                            "mime": "application/x-dosexec",
                        }
            except Exception:
                pass

        return {
            "type": "DOS",
            "description": "DOS Executable (legacy)",
            "extension": ".exe",
            "mime": "application/x-dosexec",
        }

    # Check for ELF
    if header[:4] == MAGIC_BYTES["ELF"]["signature"]:
        return {
            "type": "ELF",
            "description": "Linux ELF Executable",
            "extension": "",
            "mime": "application/x-executable",
        }

    # Check for DEX
    if header[:4] == MAGIC_BYTES["DEX"]["signature"]:
        return {
            "type": "DEX",
            "description": "Android Dalvik Executable",
            "extension": ".dex",
            "mime": "application/x-dex",
        }

    raise ValidationError(
        "Unsupported file type. ThreatLens supports APK and EXE/PE files.\n"
        f"File header bytes: {header[:8].hex()}"
    )


def _is_apk(file_path):
    """Check if a ZIP file is actually an APK by looking for AndroidManifest.xml."""
    import zipfile

    try:
        with zipfile.ZipFile(str(file_path), "r") as zf:
            names = zf.namelist()
            return "AndroidManifest.xml" in names
    except (zipfile.BadZipFile, Exception):
        return False


def validate_directory(dir_path):
    """
    Validate that a directory exists and is accessible.

    Args:
        dir_path: Path to the directory.

    Returns:
        Path: Resolved Path object.

    Raises:
        ValidationError: If directory doesn't exist or isn't accessible.
    """
    path = Path(dir_path).resolve()

    if not path.exists():
        raise ValidationError(f"Directory not found: {path}")

    if not path.is_dir():
        raise ValidationError(f"Not a directory: {path}")

    if not os.access(str(path), os.R_OK):
        raise ValidationError(f"Directory is not readable: {path}")

    return path


def sanitize_path(input_path):
    """
    Sanitize a user-provided file path.
    Strips quotes, whitespace, and normalizes for the current OS.

    Args:
        input_path: Raw user input for file path.

    Returns:
        str: Sanitized file path string.
    """
    # Strip whitespace and quotes (from drag-and-drop)
    cleaned = input_path.strip().strip('"').strip("'").strip()

    # Handle Windows drag-and-drop which may add quotes
    if cleaned.startswith("& '") and cleaned.endswith("'"):
        cleaned = cleaned[3:-1]

    # Normalize path separators
    path = Path(cleaned)

    return str(path)


def validate_and_identify(file_path):
    """
    Full validation pipeline: exists → size → type detection.

    Args:
        file_path: Path to the file to validate.

    Returns:
        dict: Complete validation result with path, size, and type info.

    Raises:
        ValidationError: If any validation step fails.
    """
    sanitized = sanitize_path(file_path)
    path = validate_file_exists(sanitized)
    size = validate_file_size(path)
    file_type = detect_file_type(path)

    return {
        "path": path,
        "size": size,
        "type_info": file_type,
    }
