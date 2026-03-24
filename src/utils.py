# src/utils.py
# Shared utility functions

import os
import json
import datetime


def is_gif_file(filepath):
    """Returns True if file exists and has .gif extension."""
    return (
        os.path.exists(filepath) and
        filepath.lower().endswith('.gif')
    )


def format_verdict(verdict):
    """Returns a colored verdict string for terminal output."""
    icons = {
        'SAFE':       '[  SAFE  ]',
        'SUSPICIOUS': '[ WARNING ]',
        'MALICIOUS':  '[MALICIOUS]',
    }
    return icons.get(verdict, f'[{verdict}]')


def result_to_dict(result):
    """
    Converts a detection result to a clean JSON-serializable dict.
    Removes raw_bytes which can't be serialized.
    """
    clean = {
        'filename':      result.get('filename'),
        'verdict':       result.get('verdict'),
        'score':         result.get('score'),
        'ml_prediction': result.get('ml_prediction'),
        'ml_confidence': result.get('ml_confidence'),
        'flags':         result.get('flags', []),
        'scanned_at':    datetime.datetime.now().isoformat(),
    }

    if result.get('entropy'):
        clean['entropy'] = {
            'overall':          result['entropy']['overall_entropy'],
            'max_chunk':        result['entropy']['max_chunk_entropy'],
            'suspicious_chunks':result['entropy']['suspicious_chunks'],
        }

    if result.get('analysis'):
        clean['analysis'] = {
            'valid_header':  result['analysis']['is_valid_gif_header'],
            'width':         result['analysis']['width'],
            'height':        result['analysis']['height'],
            'frame_count':   result['analysis']['frame_count'],
            'size_kb':       result['analysis']['size_kb'],
        }

    return clean


def save_json_report(result, output_path):
    """
    Saves a detection result as a JSON report file.
    Useful for integrating with other security tools.
    """
    clean = result_to_dict(result)
    with open(output_path, 'w') as f:
        json.dump(clean, f, indent=2)
    print(f"  Report saved → {output_path}")


def get_project_stats(safe_dir, malicious_dir, model_path):
    """
    Returns a summary of the current project state.
    """
    safe_count = len([
        f for f in os.listdir(safe_dir)
        if f.endswith('.gif')
    ]) if os.path.exists(safe_dir) else 0

    mal_count = len([
        f for f in os.listdir(malicious_dir)
        if f.endswith('.gif')
    ]) if os.path.exists(malicious_dir) else 0

    return {
        'safe_samples':     safe_count,
        'malicious_samples':mal_count,
        'total_samples':    safe_count + mal_count,
        'model_trained':    os.path.exists(model_path),
        'model_size_kb':    round(os.path.getsize(model_path)/1024, 2)
                            if os.path.exists(model_path) else 0,
    }