# src/detector.py
# Rule-based detection engine — combines all analysis into a final verdict

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from src.analyzer import analyze_gif
from src.entropy  import analyze_entropy


# ── Verdict labels ───────────────────────────────────────────────────
VERDICT_SAFE       = 'SAFE'
VERDICT_SUSPICIOUS = 'SUSPICIOUS'
VERDICT_MALICIOUS  = 'MALICIOUS'


def apply_header_rules(analysis_report, score, flags):
    """
    Rule 1: Invalid GIF header.
    If the header is wrong, flag it immediately with max points.
    """
    if not analysis_report['is_valid_gif_header']:
        score += config.SCORE_WEIGHTS['invalid_header']
        flags.append({
            'rule':     'invalid_header',
            'severity': 'critical',
            'detail':   f"Invalid header: {analysis_report['header_value']}"
        })
    return score, flags


def apply_entropy_rules(entropy_report, score, flags):
    """
    Rule 2: High entropy — possible encrypted/compressed payload.
    Rule 3: Low entropy  — possible padding-based exploit.
    Rule 4: Multiple suspicious chunks.
    """
    if entropy_report['is_high_entropy']:
        score += config.SCORE_WEIGHTS['high_entropy']
        flags.append({
            'rule':     'high_entropy',
            'severity': 'high',
            'detail':   f"Overall entropy {entropy_report['overall_entropy']} "
                        f">= threshold {config.ENTROPY_HIGH_THRESHOLD}"
        })

    if entropy_report['is_low_entropy']:
        score += config.SCORE_WEIGHTS['low_entropy']
        flags.append({
            'rule':     'low_entropy',
            'severity': 'medium',
            'detail':   f"Overall entropy {entropy_report['overall_entropy']} "
                        f"<= threshold {config.ENTROPY_LOW_THRESHOLD}"
        })

    if entropy_report['suspicious_chunks'] >= 3:
        score += 1
        flags.append({
            'rule':     'multiple_suspicious_chunks',
            'severity': 'high',
            'detail':   f"{entropy_report['suspicious_chunks']} chunks exceed entropy threshold"
        })

    return score, flags


def apply_size_rules(analysis_report, score, flags):
    """
    Rule 5: File too large — may contain appended payload.
    Rule 6: File too small — may be a malformed exploit stub.
    """
    if analysis_report['size_mb'] > config.MAX_SAFE_FILE_SIZE_MB:
        score += config.SCORE_WEIGHTS['oversized_file']
        flags.append({
            'rule':     'oversized_file',
            'severity': 'medium',
            'detail':   f"File size {analysis_report['size_mb']} MB "
                        f"> limit {config.MAX_SAFE_FILE_SIZE_MB} MB"
        })

    if analysis_report['size_kb'] < config.MIN_SAFE_FILE_SIZE_KB:
        score += config.SCORE_WEIGHTS['undersized_file']
        flags.append({
            'rule':     'undersized_file',
            'severity': 'medium',
            'detail':   f"File size {analysis_report['size_kb']} KB "
                        f"< minimum {config.MIN_SAFE_FILE_SIZE_KB} KB"
        })

    return score, flags


def apply_frame_rules(analysis_report, score, flags):
    """
    Rule 7: Too many frames — can hide data or exhaust parser memory.
    """
    if analysis_report['frame_count'] > config.MAX_SAFE_FRAME_COUNT:
        score += config.SCORE_WEIGHTS['excessive_frames']
        flags.append({
            'rule':     'excessive_frames',
            'severity': 'medium',
            'detail':   f"Frame count {analysis_report['frame_count']} "
                        f"> limit {config.MAX_SAFE_FRAME_COUNT}"
        })

    return score, flags


def apply_comment_rules(analysis_report, score, flags):
    """
    Rule 8: Suspicious content in GIF comment extensions.
    """
    if analysis_report['suspicious_comments']:
        score += config.SCORE_WEIGHTS['suspicious_comment']
        for comment in analysis_report['suspicious_comments']:
            flags.append({
                'rule':     'suspicious_comment',
                'severity': 'high',
                'detail':   comment
            })

    return score, flags


def apply_ml_rules(filepath, score, flags):
    """
    Rule 9: ML model prediction.
    Adds ML vote to the score if model exists.
    Returns updated score, flags, prediction and confidence.
    """
    ml_prediction = None
    ml_confidence = 0.0

    try:
        from src.ml_model import predict as ml_predict
        ml_prediction, ml_confidence = ml_predict(filepath, config.MODEL_PATH)

        if ml_prediction == 1:
            score += config.SCORE_WEIGHTS['ml_malicious']
            flags.append({
                'rule':     'ml_malicious',
                'severity': 'high',
                'detail':   f"ML model says malicious with {ml_confidence}% confidence"
            })

    except Exception as e:
        pass  # ML is optional — silently skip if unavailable

    return score, flags, ml_prediction, ml_confidence


def determine_verdict(score):
    """
    Converts final numeric score into a human-readable verdict.
    """
    if score >= config.SCORE_MALICIOUS_THRESHOLD + 2:   # >= 5
        return VERDICT_MALICIOUS
    elif score >= config.SCORE_MALICIOUS_THRESHOLD:      # >= 3
        return VERDICT_SUSPICIOUS
    else:
        return VERDICT_SAFE


def detect(filepath):
    """
    MAIN FUNCTION — runs the full detection pipeline on a GIF file.

    Steps:
        1. Static analysis  (analyzer.py)
        2. Entropy analysis (entropy.py)
        3. Rule-based scoring
        4. ML model vote    (ml_model.py)
        5. Final verdict
    """
    result = {
        'filepath':       filepath,
        'filename':       os.path.basename(filepath),
        'score':          0,
        'verdict':        None,
        'flags':          [],
        'analysis':       None,
        'entropy':        None,
        'ml_prediction':  None,
        'ml_confidence':  0.0,
        'error':          None,
    }

    # ── Step 1: Static analysis ─────────────────────────────────────
    try:
        analysis = analyze_gif(filepath)
        if 'error' in analysis and 'raw_bytes' not in analysis:
            result['error'] = analysis['error']
            return result
        result['analysis'] = analysis
    except Exception as e:
        result['error'] = f"Analysis failed: {e}"
        return result

    # ── Step 2: Entropy analysis ────────────────────────────────────
    try:
        entropy = analyze_entropy(analysis['raw_bytes'])
        result['entropy'] = entropy
    except Exception as e:
        result['error'] = f"Entropy failed: {e}"
        return result

    # ── Step 3: Apply rule-based scoring ────────────────────────────
    score = 0
    flags = []

    score, flags = apply_header_rules(analysis, score, flags)
    score, flags = apply_entropy_rules(entropy,  score, flags)
    score, flags = apply_size_rules(analysis,    score, flags)
    score, flags = apply_frame_rules(analysis,   score, flags)
    score, flags = apply_comment_rules(analysis, score, flags)

    # ── Step 4: ML model vote ────────────────────────────────────────
    score, flags, ml_prediction, ml_confidence = apply_ml_rules(
        filepath, score, flags
    )
    result['ml_prediction'] = ml_prediction
    result['ml_confidence'] = ml_confidence

    # ── Step 5: Final verdict ────────────────────────────────────────
    result['score']   = score
    result['flags']   = flags
    result['verdict'] = determine_verdict(score)

    return result


def print_detection_result(result):
    """
    Prints a clean detection report to the console.
    """
    verdict_icons = {
        VERDICT_SAFE:       '[  SAFE  ]',
        VERDICT_SUSPICIOUS: '[ WARNING ]',
        VERDICT_MALICIOUS:  '[MALICIOUS]',
    }

    print("\n" + "="*55)
    print("  GIF Malware Detection Result")
    print("="*55)
    print(f"  File    : {result['filename']}")
    print(f"  Score   : {result['score']} / 10")
    print(f"  Verdict : {verdict_icons.get(result['verdict'], result['verdict'])}")

    if result['error']:
        print(f"\n  ERROR: {result['error']}")

    if result['flags']:
        print(f"\n  Flags triggered ({len(result['flags'])}):")
        for flag in result['flags']:
            sev = flag['severity'].upper()
            print(f"    [{sev}] {flag['rule']}")
            print(f"           {flag['detail']}")
    else:
        print("\n  No suspicious flags detected.")

    if result['entropy']:
        print(f"\n  Entropy : {result['entropy']['overall_entropy']} / 8.0")

    if result['ml_prediction'] is not None:
        verdict = 'MALICIOUS' if result['ml_prediction'] == 1 else 'SAFE'
        print(f"  ML vote : {verdict} ({result['ml_confidence']}% confidence)")

    print("="*55 + "\n")


# ── Quick test ───────────────────────────────────────────────────────
if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'data/safe/test_sample.gif'
    result = detect(path)
    print_detection_result(result)