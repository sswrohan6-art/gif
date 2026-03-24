import os
import csv
import struct
import random
import sys
from PIL import Image

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.analyzer import analyze_gif
from src.entropy import analyze_entropy

SAFE_DIR = 'data/safe'
MALICIOUS_DIR = 'data/malicious'
DATASET_PATH = 'data/dataset.csv'
NUM_SAFE = 50
NUM_MALICIOUS = 50

os.makedirs(SAFE_DIR, exist_ok=True)
os.makedirs(MALICIOUS_DIR, exist_ok=True)

def generate_safe_gif(filepath):
    width = random.randint(50, 300)
    height = random.randint(50, 300)
    num_frames = random.randint(1, 10)
    duration = random.randint(50, 200)
    frames = []
    for _ in range(num_frames):
        color = (random.randint(0,255), random.randint(0,255), random.randint(0,255))
        frames.append(Image.new('RGB', (width, height), color=color))
    frames[0].save(filepath, save_all=True, append_images=frames[1:], loop=0, duration=duration, format='GIF')

def make_high_entropy_gif(filepath):
    img = Image.new('RGB', (10, 10), color=(255, 0, 0))
    img.save(filepath, format='GIF')
    with open(filepath, 'ab') as f:
        f.write(os.urandom(random.randint(1024, 4096)))

def make_comment_gif(filepath):
    payloads = [
        b'<?php system($_GET["cmd"]); ?>',
        b'<script>document.location="http://evil.com"</script>',
        b'eval(base64_decode("cGhwaW5mbygpOw=="))',
        b'powershell -enc JABjAGwAaQBlAG4AdA==',
    ]
    payload = random.choice(payloads)
    parts = [
        b'GIF89a',
        struct.pack('<HH', 10, 10),
        b'\x00\x00\x00',
        b'\x21\xfe',
        bytes([len(payload)]),
        payload,
        b'\x00',
        b'\x2c',
        struct.pack('<HHHH', 0, 0, 10, 10),
        b'\x00',
        b'\x02\x02\x4c\x01\x00',
        b'\x3b',
    ]
    with open(filepath, 'wb') as f:
        f.write(b''.join(parts))

def make_oversized_gif(filepath):
    img = Image.new('RGB', (50, 50), color=(0, 255, 0))
    img.save(filepath, format='GIF')
    with open(filepath, 'ab') as f:
        f.write(os.urandom(random.randint(500000, 1000000)))

def make_invalid_gif(filepath):
    headers = [b'GIF88a', b'PNG\r\n', b'\x00\x00\x00\x00\x00\x00', b'JFIF\x00']
    with open(filepath, 'wb') as f:
        f.write(random.choice(headers))
        f.write(os.urandom(512))

def generate_malicious_gif(filepath, variant):
    if variant == 1:
        make_high_entropy_gif(filepath)
    elif variant == 2:
        make_comment_gif(filepath)
    elif variant == 3:
        make_oversized_gif(filepath)
    elif variant == 4:
        make_invalid_gif(filepath)

def extract_features(filepath, label):
    try:
        analysis = analyze_gif(filepath)
        raw_bytes = analysis.get('raw_bytes', b'')
        entropy = analyze_entropy(raw_bytes) if raw_bytes else {}
        return {
            'filename':            os.path.basename(filepath),
            'size_kb':             analysis.get('size_kb', 0),
            'size_mb':             analysis.get('size_mb', 0),
            'is_valid_header':     int(analysis.get('is_valid_gif_header', False)),
            'width':               analysis.get('width', 0),
            'height':              analysis.get('height', 0),
            'frame_count':         analysis.get('frame_count', 0),
            'has_transparency':    int(analysis.get('has_transparency', False)),
            'has_comments':        int(len(analysis.get('comments', [])) > 0),
            'suspicious_comments': int(len(analysis.get('suspicious_comments', [])) > 0),
            'overall_entropy':     entropy.get('overall_entropy', 0),
            'max_chunk_entropy':   entropy.get('max_chunk_entropy', 0),
            'min_chunk_entropy':   entropy.get('min_chunk_entropy', 0),
            'avg_chunk_entropy':   entropy.get('avg_chunk_entropy', 0),
            'suspicious_chunks':   entropy.get('suspicious_chunks', 0),
            'is_high_entropy':     int(entropy.get('is_high_entropy', False)),
            'is_low_entropy':      int(entropy.get('is_low_entropy', False)),
            'label':               label,
        }
    except Exception as e:
        print(f"  [!] Failed {filepath}: {e}")
        return None

def build():
    print("\n" + "="*50)
    print("  Building GIF Malware Dataset")
    print("="*50)
    all_features = []

    print(f"\n  Generating {NUM_SAFE} safe GIFs...")
    for i in range(NUM_SAFE):
        path = os.path.join(SAFE_DIR, f'safe{i:03d}.gif')
        try:
            generate_safe_gif(path)
            f = extract_features(path, 0)
            if f:
                all_features.append(f)
                print(f"    [OK] safe{i:03d}.gif  entropy={f['overall_entropy']}")
        except Exception as e:
            print(f"    [!] safe{i:03d}.gif ERROR: {e}")

    print(f"\n  Generating {NUM_MALICIOUS} malicious GIFs...")
    for i in range(NUM_MALICIOUS):
        path = os.path.join(MALICIOUS_DIR, f'mal{i:03d}.gif')
        variant = (i % 4) + 1
        try:
            generate_malicious_gif(path, variant)
            f = extract_features(path, 1)
            if f:
                all_features.append(f)
                print(f"    [OK] mal{i:03d}.gif  variant={variant}  entropy={f['overall_entropy']}")
        except Exception as e:
            print(f"    [!] mal{i:03d}.gif ERROR: {e}")

    if not all_features:
        print("\n  [!] No features extracted.")
        return

    with open(DATASET_PATH, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(all_features[0].keys()))
        writer.writeheader()
        writer.writerows(all_features)

    safe_count = sum(1 for r in all_features if r['label'] == 0)
    mal_count  = sum(1 for r in all_features if r['label'] == 1)
    print(f"\n  Dataset saved to {DATASET_PATH}")
    print(f"  Total : {len(all_features)}")
    print(f"  Safe  : {safe_count}")
    print(f"  Mal   : {mal_count}")
    print("="*50 + "\n")

if __name__ == '__main__':
    build()