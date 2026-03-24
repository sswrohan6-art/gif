# tests/test_analyzer.py

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analyzer import (
    check_gif_header,
    check_suspicious_comments,
    analyze_gif,
)


def test_valid_gif_header():
    assert check_gif_header(b'GIF89a\x00') == (True, 'GIF89a')
    assert check_gif_header(b'GIF87a\x00') == (True, 'GIF87a')
    print("  [OK] test_valid_gif_header")


def test_invalid_gif_header():
    valid, _ = check_gif_header(b'PNG\r\n\x00')
    assert valid == False
    print("  [OK] test_invalid_gif_header")


def test_suspicious_comments():
    comments = ['<?php eval($_GET[cmd]); ?>']
    findings = check_suspicious_comments(comments)
    assert len(findings) > 0
    print("  [OK] test_suspicious_comments")


def test_clean_comments():
    comments = ['Made with GIMP', 'Copyright 2024']
    findings = check_suspicious_comments(comments)
    assert len(findings) == 0
    print("  [OK] test_clean_comments")


def test_analyze_gif_safe():
    path = 'data/safe/test_sample.gif'
    if not os.path.exists(path):
        print("  [SKIP] test_analyze_gif — file not found")
        return
    result = analyze_gif(path)
    assert result['is_valid_gif_header'] == True
    assert result['frame_count'] >= 1
    assert result['width'] > 0
    print("  [OK] test_analyze_gif_safe")


def run_all():
    print("\n" + "="*45)
    print("  Unit Tests — analyzer.py")
    print("="*45)
    test_valid_gif_header()
    test_invalid_gif_header()
    test_suspicious_comments()
    test_clean_comments()
    test_analyze_gif_safe()
    print("="*45)
    print("  All tests passed!")
    print("="*45 + "\n")


if __name__ == '__main__':
    run_all()