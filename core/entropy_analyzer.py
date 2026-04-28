"""
ThreatLens - Entropy Analyzer
Shannon entropy calculation for detecting packed/encrypted sections.
"""

import math
from collections import Counter


def calculate_entropy(data):
    """
    Calculate Shannon entropy of binary data.
    
    Entropy ranges:
    - 0.0 to 1.0: Very low (null bytes, repeated data)
    - 1.0 to 3.5: Low (plain text, structured data)
    - 3.5 to 5.0: Moderate (mixed content, code)
    - 5.0 to 6.5: High (native code, compressed resources)
    - 6.5 to 7.5: Very high (compressed data)
    - 7.5 to 8.0: Extremely high (encrypted/packed - suspicious)
    
    Args:
        data: bytes data to analyze.
        
    Returns:
        float: Shannon entropy value (0.0 to 8.0 for byte data).
    """
    if not data:
        return 0.0

    length = len(data)
    byte_counts = Counter(data)
    entropy = 0.0

    for count in byte_counts.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


def analyze_entropy_profile(data, block_size=256):
    """
    Analyze entropy across blocks of data to detect encrypted/packed regions.
    
    Args:
        data: bytes data to analyze.
        block_size: Size of each analysis block.
        
    Returns:
        dict: Entropy profile with statistics and per-block values.
    """
    if not data:
        return {"average": 0.0, "max": 0.0, "min": 0.0, "blocks": [], "packed_regions": []}

    blocks = []
    packed_regions = []

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) >= block_size // 2:
            ent = calculate_entropy(block)
            blocks.append({"offset": i, "entropy": ent, "size": len(block)})
            if ent > 7.0:
                packed_regions.append({"offset": i, "size": len(block), "entropy": ent})

    entropies = [b["entropy"] for b in blocks] if blocks else [0.0]

    return {
        "average": sum(entropies) / len(entropies),
        "max": max(entropies),
        "min": min(entropies),
        "std_dev": _std_dev(entropies),
        "blocks": blocks,
        "packed_regions": packed_regions,
        "total_blocks": len(blocks),
        "packed_block_count": len(packed_regions),
        "packed_percentage": (len(packed_regions) / len(blocks) * 100) if blocks else 0,
    }


def classify_entropy(entropy_value):
    """
    Classify entropy value into a human-readable category.
    
    Args:
        entropy_value: Float entropy value.
        
    Returns:
        dict: Classification with label, risk, and description.
    """
    if entropy_value > 7.5:
        return {"label": "ENCRYPTED/PACKED", "risk": "CRITICAL", "score": 25,
                "description": "Extremely high entropy suggests encryption or packing"}
    elif entropy_value > 7.0:
        return {"label": "LIKELY PACKED", "risk": "HIGH", "score": 18,
                "description": "Very high entropy consistent with packing/compression"}
    elif entropy_value > 6.5:
        return {"label": "SUSPICIOUS", "risk": "MEDIUM", "score": 10,
                "description": "High entropy — may contain compressed or obfuscated data"}
    elif entropy_value > 5.0:
        return {"label": "NATIVE CODE", "risk": "LOW", "score": 0,
                "description": "Normal entropy for compiled native code"}
    elif entropy_value > 3.5:
        return {"label": "MIXED DATA", "risk": "LOW", "score": 0,
                "description": "Normal entropy for mixed code and data"}
    else:
        return {"label": "LOW ENTROPY", "risk": "CLEAN", "score": 0,
                "description": "Very low entropy — plain text or structured data"}


def detect_packer(sections_entropy):
    """
    Detect common packers based on entropy and section characteristics.
    
    Args:
        sections_entropy: List of dicts with 'name' and 'entropy' keys.
        
    Returns:
        list: Detected packer indicators.
    """
    packers = []

    for section in sections_entropy:
        name = section.get("name", "").strip("\x00").lower()
        entropy = section.get("entropy", 0)

        # UPX detection
        if name in ("upx0", "upx1", "upx2", ".upx"):
            packers.append({"packer": "UPX", "confidence": 95, "section": name,
                            "description": "UPX packed executable detected"})

        # Themida/WinLicense
        if name in (".themida", ".winlice"):
            packers.append({"packer": "Themida/WinLicense", "confidence": 90, "section": name,
                            "description": "Themida/WinLicense protection detected"})

        # VMProtect
        if name in (".vmp0", ".vmp1", ".vmp2"):
            packers.append({"packer": "VMProtect", "confidence": 90, "section": name,
                            "description": "VMProtect protection detected"})

        # ASPack
        if name == ".aspack":
            packers.append({"packer": "ASPack", "confidence": 90, "section": name,
                            "description": "ASPack packer detected"})

        # NSPack
        if name in (".nsp0", ".nsp1", ".nsp2"):
            packers.append({"packer": "NSPack", "confidence": 85, "section": name,
                            "description": "NSPack packer detected"})

        # Generic packing: .text section with very high entropy and small raw size
        if name == ".text" and entropy > 7.2:
            packers.append({"packer": "Unknown Packer", "confidence": 70, "section": name,
                            "description": f".text section entropy {entropy:.2f} suggests packing"})

    return packers


def generate_entropy_histogram(data, width=60, height=15, block_size=1024):
    """
    Generate an ASCII histogram of entropy distribution.
    
    Args:
        data: bytes data to analyze.
        width: Width of the histogram in characters.
        height: Height of the histogram.
        block_size: Size of each analysis block.
        
    Returns:
        str: ASCII art histogram string.
    """
    if not data:
        return "No data to analyze."

    profile = analyze_entropy_profile(data, block_size)
    blocks = profile["blocks"]

    if not blocks:
        return "Insufficient data for histogram."

    # Sample blocks to fit width
    step = max(1, len(blocks) // width)
    sampled = [blocks[i]["entropy"] for i in range(0, len(blocks), step)][:width]

    lines = []
    lines.append(f"  Entropy Distribution ({len(blocks)} blocks, {block_size}B each)")
    lines.append(f"  {'─' * (width + 6)}")

    for row in range(height, 0, -1):
        threshold = (row / height) * 8.0
        line = f"  {threshold:4.1f} │"
        for val in sampled:
            if val >= threshold:
                if val > 7.0:
                    line += "█"
                elif val > 6.0:
                    line += "▓"
                elif val > 4.0:
                    line += "▒"
                else:
                    line += "░"
            else:
                line += " "
        lines.append(line)

    lines.append(f"       └{'─' * width}")
    lines.append(f"        {'0':^{width // 2}}File Offset{'→':>{width // 2}}")
    lines.append(f"  Avg: {profile['average']:.2f} | Max: {profile['max']:.2f} | "
                 f"Packed blocks: {profile['packed_block_count']}/{profile['total_blocks']}")

    return "\n".join(lines)


def _std_dev(values):
    """Calculate standard deviation."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)
