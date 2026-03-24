# src/analyzer.py
# Reads a GIF file at the binary level and extracts all structural information

from PIL import Image
import os
import sys

# Add parent directory to path so we can import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


def read_raw_bytes(filepath):
    """
    Read the entire file as raw bytes.
    We need raw bytes to check the header signature and do entropy analysis later.
    """
    with open(filepath, 'rb') as f:
        return f.read()


def check_gif_header(raw_bytes):
    """
    A valid GIF file must start with either 'GIF87a' or 'GIF89a'.
    If this check fails, the file is not a real GIF — instant red flag.
    Returns: (is_valid, version_string)
    """
    header = raw_bytes[:6]  # First 6 bytes are the signature

    for sig in config.VALID_GIF_SIGNATURES:
        if header == sig:
            return True, sig.decode('ascii')

    return False, header.hex()   # Return hex if invalid, useful for debugging


def get_file_size(filepath):
    """
    Returns file size in both bytes and megabytes.
    Very large or very small GIFs are suspicious.
    """
    size_bytes = os.path.getsize(filepath)
    size_mb    = size_bytes / (1024 * 1024)
    size_kb    = size_bytes / 1024
    return size_bytes, size_kb, size_mb


def extract_gif_metadata(filepath):
    """
    Uses Pillow to open the GIF and extract:
    - Dimensions (width x height)
    - Number of frames
    - Color palette info
    - Any embedded comments (extensions)
    - Animation loop count
    """
    metadata = {
        'width':        0,
        'height':       0,
        'frame_count':  0,
        'mode':         '',
        'format':       '',
        'comments':     [],
        'loop_count':   0,
        'has_transparency': False,
    }

    try:
        img = Image.open(filepath)
        metadata['width']  = img.width
        metadata['height'] = img.height
        metadata['mode']   = img.mode
        metadata['format'] = img.format

        # Count frames by iterating through the animation
        frame_count = 0
        try:
            while True:
                frame_count += 1

                # Check for transparency flag in each frame
                if img.info.get('transparency') is not None:
                    metadata['has_transparency'] = True

                # Extract comments — malicious GIFs sometimes hide code here
                if 'comment' in img.info:
                    comment = img.info['comment']
                    if isinstance(comment, bytes):
                        comment = comment.decode('utf-8', errors='replace')
                    if comment not in metadata['comments']:
                        metadata['comments'].append(comment)

                # Get loop count from first frame
                if frame_count == 1:
                    metadata['loop_count'] = img.info.get('loop', 0)

                img.seek(img.tell() + 1)   # Move to next frame

        except EOFError:
            pass  # Reached the end of frames — this is normal

        metadata['frame_count'] = frame_count

    except Exception as e:
        metadata['error'] = str(e)

    return metadata


def check_suspicious_comments(comments):
    """
    Scans comment strings for patterns commonly found in malicious files.
    Attackers sometimes embed JavaScript, PHP, or shell commands in GIF comments.
    """
    # These patterns appear in known exploit GIFs
    suspicious_patterns = [
        '<script',     # JavaScript injection
        '<?php',       # PHP code
        'eval(',       # Code execution
        'exec(',       # Shell execution
        'base64',      # Encoded payload
        'shellcode',   # Shellcode marker
        '/bin/sh',     # Unix shell
        'cmd.exe',     # Windows shell
        'powershell',  # PowerShell
        'http://',     # External URL (could be C2 server)
        'https://',
    ]

    found = []
    for comment in comments:
        comment_lower = comment.lower()
        for pattern in suspicious_patterns:
            if pattern in comment_lower:
                found.append(f"Pattern '{pattern}' in comment: {comment[:80]}")

    return found


def analyze_gif(filepath):
    """
    MAIN FUNCTION — runs all analysis steps and returns a complete report dict.
    This is what detector.py and main.py will call.
    """
    if not os.path.exists(filepath):
        return {'error': f'File not found: {filepath}'}

    # ── Step 1: Read raw bytes ──────────────────────────────────────
    raw_bytes = read_raw_bytes(filepath)

    # ── Step 2: Validate GIF header ─────────────────────────────────
    is_valid_header, header_value = check_gif_header(raw_bytes)

    # ── Step 3: Get file size info ──────────────────────────────────
    size_bytes, size_kb, size_mb = get_file_size(filepath)

    # ── Step 4: Extract metadata via Pillow ─────────────────────────
    metadata = extract_gif_metadata(filepath)

    # ── Step 5: Check for suspicious comment patterns ───────────────
    suspicious_comments = check_suspicious_comments(metadata.get('comments', []))

    # ── Compile full report ─────────────────────────────────────────
    report = {
        'filepath':            filepath,
        'filename':            os.path.basename(filepath),
        'is_valid_gif_header': is_valid_header,
        'header_value':        header_value,
        'size_bytes':          size_bytes,
        'size_kb':             round(size_kb, 2),
        'size_mb':             round(size_mb, 4),
        'width':               metadata.get('width', 0),
        'height':              metadata.get('height', 0),
        'frame_count':         metadata.get('frame_count', 0),
        'mode':                metadata.get('mode', ''),
        'has_transparency':    metadata.get('has_transparency', False),
        'loop_count':          metadata.get('loop_count', 0),
        'comments':            metadata.get('comments', []),
        'suspicious_comments': suspicious_comments,
        'raw_bytes':           raw_bytes,   # Passed to entropy.py in next phase
    }

    return report


def print_report(report):
    """
    Pretty-prints the analysis report to the console.
    Useful for manual testing and CLI usage.
    """
    print("\n" + "="*55)
    print(f"  GIF Analysis Report")
    print("="*55)
    print(f"  File       : {report['filename']}")
    print(f"  Valid GIF  : {report['is_valid_gif_header']}  ({report['header_value']})")
    print(f"  Size       : {report['size_kb']} KB  ({report['size_mb']} MB)")
    print(f"  Dimensions : {report['width']} x {report['height']} px")
    print(f"  Frames     : {report['frame_count']}")
    print(f"  Mode       : {report['mode']}")
    print(f"  Transparent: {report['has_transparency']}")
    print(f"  Loop count : {report['loop_count']}")

    if report['comments']:
        print(f"  Comments   : {report['comments']}")

    if report['suspicious_comments']:
        print(f"\n  [!] SUSPICIOUS PATTERNS FOUND:")
        for s in report['suspicious_comments']:
            print(f"      - {s}")

    print("="*55 + "\n")


# ── Quick test — run this file directly to test it ──────────────────
if __name__ == '__main__':
    # We'll create a test GIF in a moment
    test_path = sys.argv[1] if len(sys.argv) > 1 else None

    if test_path:
        result = analyze_gif(test_path)
        print_report(result)
    else:
        print("Usage: py src/analyzer.py path/to/file.gif")