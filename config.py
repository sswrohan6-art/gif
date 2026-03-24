# config.py

# ── Entropy thresholds ──────────────────────────────────────────────
# Shannon entropy is measured 0.0 (perfectly ordered) to 8.0 (perfectly random)
# Normal GIFs typically fall between 4.0 and 7.0
ENTROPY_HIGH_THRESHOLD = 7.5   # Above this → suspicious (possible payload)
ENTROPY_LOW_THRESHOLD  = 1.0   # Below this → suspicious (possible padding exploit)

# ── File size limits ────────────────────────────────────────────────
MAX_SAFE_FILE_SIZE_MB  = 50    # GIFs larger than this get flagged
MIN_SAFE_FILE_SIZE_KB  = 1     # Tiny files (< 1 KB) are suspicious too

# ── GIF structural rules ────────────────────────────────────────────
MAX_SAFE_FRAME_COUNT   = 500   # Abnormally high frame counts can hide payloads
VALID_GIF_SIGNATURES   = [b'GIF87a', b'GIF89a']  # The only valid GIF headers

# ── Scoring system ──────────────────────────────────────────────────
# Each anomaly adds points to the risk score
# Final score >= MALICIOUS_THRESHOLD → classified as malicious
SCORE_MALICIOUS_THRESHOLD = 3

SCORE_WEIGHTS = {
    'invalid_header':      5,   # Instant fail — not a real GIF
    'high_entropy':        2,
    'low_entropy':         2,
    'oversized_file':      1,
    'undersized_file':     1,
    'excessive_frames':    2,
    'suspicious_comment':  2,   # Malicious GIFs sometimes embed code in comments
    'ml_malicious':        3,   # ML model vote
}

# ── Paths ───────────────────────────────────────────────────────────
import os
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DATA_SAFE_DIR   = os.path.join(BASE_DIR, 'data', 'safe')
DATA_MAL_DIR    = os.path.join(BASE_DIR, 'data', 'malicious')
MODEL_PATH      = os.path.join(BASE_DIR, 'models', 'classifier.pkl')