"""
ThreatLens - Hash Calculator
Compute cryptographic hashes (MD5, SHA1, SHA256) for file identification.
"""

import hashlib
from pathlib import Path


BUFFER_SIZE = 65536  # 64 KB chunks for efficient hashing


def calculate_hashes(file_path):
    """
    Calculate MD5, SHA1, and SHA256 hashes of a file.
    Uses buffered reading for memory efficiency with large files.

    Args:
        file_path: Path to the file.

    Returns:
        dict: Dictionary with 'md5', 'sha1', 'sha256' hash strings.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    path = Path(file_path)

    with open(path, "rb") as f:
        while True:
            data = f.read(BUFFER_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def calculate_section_hash(data):
    """
    Calculate SHA256 hash of a binary data section.

    Args:
        data: bytes data to hash.

    Returns:
        str: SHA256 hex digest.
    """
    return hashlib.sha256(data).hexdigest()


def get_file_info(file_path):
    """
    Get comprehensive file information including hashes and metadata.

    Args:
        file_path: Path to the file.

    Returns:
        dict: File information including size, hashes, and timestamps.
    """
    path = Path(file_path)
    stat = path.stat()

    hashes = calculate_hashes(file_path)

    return {
        "filename": path.name,
        "filepath": str(path.resolve()),
        "size_bytes": stat.st_size,
        "hashes": hashes,
        "modified_time": stat.st_mtime,
        "created_time": stat.st_ctime,
    }
