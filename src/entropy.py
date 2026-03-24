# src/entropy.py
# Calculates Shannon entropy and byte distribution statistics
# Used to detect hidden/encrypted payloads inside GIF files

import numpy as np
import math
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


def calculate_shannon_entropy(data):
    """
    Shannon entropy formula:
        H = -sum(p(x) * log2(p(x)))  for all byte values x

    Returns a float between 0.0 and 8.0.
        0.0 = perfectly ordered  (e.g. all bytes are 0x00)
        8.0 = perfectly random   (e.g. encrypted or compressed data)

    Normal GIF files score between 4.0 and 7.0.
    """
    if not data:
        return 0.0

    # Convert raw bytes to a numpy array for fast math
    byte_array = np.frombuffer(data, dtype=np.uint8)

    # Count how many times each byte value (0-255) appears
    byte_counts = np.bincount(byte_array, minlength=256)

    # Keep only byte values that actually appear (avoid log(0))
    nonzero_counts = byte_counts[byte_counts > 0]

    # Convert counts to probabilities
    total_bytes   = len(byte_array)
    probabilities = nonzero_counts / total_bytes

    # Apply Shannon's formula: H = -sum(p * log2(p))
    entropy = -np.sum(probabilities * np.log2(probabilities))

    return round(float(entropy), 4)


def calculate_chunk_entropy(data, chunk_size=1024):
    """
    Splits the file into chunks and calculates entropy for each chunk.

    Why this matters:
    A malicious GIF might have NORMAL entropy overall (to avoid detection)
    but contain one highly suspicious chunk where the payload is hidden.
    Chunk analysis catches this — overall entropy alone would miss it.

    Returns a list of (chunk_index, entropy_value) tuples.
    """
    chunks = []
    total_chunks = math.ceil(len(data) / chunk_size)

    for i in range(total_chunks):
        start = i * chunk_size
        end   = start + chunk_size
        chunk = data[start:end]
        chunk_entropy = calculate_shannon_entropy(chunk)
        chunks.append((i, chunk_entropy))

    return chunks


def get_byte_distribution(data):
    """
    Counts how often each byte value (0-255) appears.
    Returns a dict: {byte_value: count}

    Malicious files often show unusual byte distributions —
    for example, a spike at 0x90 (NOP sled in shellcode)
    or unusually uniform distribution (encrypted payload).
    """
    byte_array   = np.frombuffer(data, dtype=np.uint8)
    byte_counts  = np.bincount(byte_array, minlength=256)

    return {i: int(byte_counts[i]) for i in range(256)}


def find_high_entropy_chunks(chunk_entropies, threshold=7.2):
    """
    Filters chunk list to return only chunks above the threshold.
    These are the specific regions of the file that are suspicious.
    Helps us pinpoint WHERE in the file a payload might be hiding.
    """
    suspicious = [
        (idx, ent) for idx, ent in chunk_entropies
        if ent >= threshold
    ]
    return suspicious


def analyze_entropy(raw_bytes):
    """
    MAIN FUNCTION — runs all entropy checks and returns a full report.
    Called by detector.py with the raw_bytes from analyzer.py.
    """
    total_size = len(raw_bytes)

    # ── Overall file entropy ────────────────────────────────────────
    overall_entropy = calculate_shannon_entropy(raw_bytes)

    # ── Chunk-by-chunk entropy ──────────────────────────────────────
    chunk_entropies = calculate_chunk_entropy(raw_bytes, chunk_size=1024)

    # ── Find suspicious high-entropy chunks ────────────────────────
    high_entropy_chunks = find_high_entropy_chunks(
        chunk_entropies,
        threshold=7.2
    )

    # ── Byte distribution ───────────────────────────────────────────
    byte_dist = get_byte_distribution(raw_bytes)

    # ── Summary statistics from chunk entropies ─────────────────────
    entropy_values = [e for _, e in chunk_entropies]
    max_chunk_entropy = max(entropy_values) if entropy_values else 0.0
    min_chunk_entropy = min(entropy_values) if entropy_values else 0.0
    avg_chunk_entropy = round(
        sum(entropy_values) / len(entropy_values), 4
    ) if entropy_values else 0.0

    # ── Determine flags ─────────────────────────────────────────────
    is_high_entropy = overall_entropy >= config.ENTROPY_HIGH_THRESHOLD
    is_low_entropy  = overall_entropy <= config.ENTROPY_LOW_THRESHOLD

    report = {
        'overall_entropy':      overall_entropy,
        'max_chunk_entropy':    round(max_chunk_entropy, 4),
        'min_chunk_entropy':    round(min_chunk_entropy, 4),
        'avg_chunk_entropy':    avg_chunk_entropy,
        'high_entropy_chunks':  high_entropy_chunks,
        'chunk_count':          len(chunk_entropies),
        'suspicious_chunks':    len(high_entropy_chunks),
        'byte_distribution':    byte_dist,
        'total_bytes_analyzed': total_size,
        'is_high_entropy':      is_high_entropy,
        'is_low_entropy':       is_low_entropy,
    }

    return report


def print_entropy_report(report):
    """
    Pretty-prints the entropy report to the console.
    """
    print("\n" + "="*55)
    print("  Entropy Analysis Report")
    print("="*55)
    print(f"  Overall entropy    : {report['overall_entropy']} / 8.0")
    print(f"  Chunk avg entropy  : {report['avg_chunk_entropy']}")
    print(f"  Chunk max entropy  : {report['max_chunk_entropy']}")
    print(f"  Chunk min entropy  : {report['min_chunk_entropy']}")
    print(f"  Total chunks       : {report['chunk_count']}")
    print(f"  Suspicious chunks  : {report['suspicious_chunks']}")
    print(f"  High entropy flag  : {report['is_high_entropy']}")
    print(f"  Low entropy flag   : {report['is_low_entropy']}")

    if report['high_entropy_chunks']:
        print(f"\n  [!] HIGH ENTROPY CHUNKS DETECTED:")
        for idx, ent in report['high_entropy_chunks'][:5]:  # show first 5
            offset = idx * 1024
            print(f"      Chunk {idx:>3} | offset {offset:>6} bytes | entropy {ent}")

    print("="*55 + "\n")


# ── Quick test — run directly ────────────────────────────────────────
if __name__ == '__main__':
    from analyzer import read_raw_bytes

    test_path = sys.argv[1] if len(sys.argv) > 1 else 'data/safe/test_sample.gif'
    raw       = read_raw_bytes(test_path)
    report    = analyze_entropy(raw)
    print_entropy_report(report)