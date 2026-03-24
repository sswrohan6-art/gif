# visualize_entropy.py
# Draws a bar chart showing entropy per chunk across the file

import matplotlib.pyplot as plt
import sys
from src.analyzer import read_raw_bytes
from src.entropy  import calculate_chunk_entropy

def plot_entropy(filepath):
    raw    = read_raw_bytes(filepath)
    chunks = calculate_chunk_entropy(raw, chunk_size=512)

    indices   = [i for i, _ in chunks]
    entropies = [e for _, e in chunks]

    plt.figure(figsize=(12, 4))
    bars = plt.bar(indices, entropies, color=[
        '#e24b4a' if e >= 7.2 else   # red   = suspicious
        '#639922' if e >= 4.0 else   # green = normal
        '#BA7517'                     # amber = suspiciously low
        for e in entropies
    ])

    plt.axhline(y=7.2, color='red',   linestyle='--', linewidth=1, label='High threshold (7.2)')
    plt.axhline(y=4.0, color='orange',linestyle='--', linewidth=1, label='Low threshold (4.0)')
    plt.axhline(y=8.0, color='gray',  linestyle=':',  linewidth=1, label='Max possible (8.0)')

    plt.xlabel('Chunk index (each = 512 bytes)')
    plt.ylabel('Shannon entropy')
    plt.title(f'Entropy per chunk — {filepath}')
    plt.legend()
    plt.tight_layout()
    plt.savefig('entropy_chart.png', dpi=150)
    plt.show()
    print("Chart saved as entropy_chart.png")

path = sys.argv[1] if len(sys.argv) > 1 else 'data/safe/test_sample.gif'
plot_entropy(path)