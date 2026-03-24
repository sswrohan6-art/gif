# tests/test_detector.py

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detector import determine_verdict, VERDICT_SAFE, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS


def test_safe_verdict():
    assert determine_verdict(0) == VERDICT_SAFE
    assert determine_verdict(1) == VERDICT_SAFE
    assert determine_verdict(2) == VERDICT_SAFE
    print("  [OK] test_safe_verdict")


def test_suspicious_verdict():
    assert determine_verdict(3) == VERDICT_SUSPICIOUS
    assert determine_verdict(4) == VERDICT_SUSPICIOUS
    print("  [OK] test_suspicious_verdict")


def test_malicious_verdict():
    assert determine_verdict(5) == VERDICT_MALICIOUS
    assert determine_verdict(9) == VERDICT_MALICIOUS
    print("  [OK] test_malicious_verdict")


def run_all():
    print("\n" + "="*45)
    print("  Unit Tests — detector.py")
    print("="*45)
    test_safe_verdict()
    test_suspicious_verdict()
    test_malicious_verdict()
    print("="*45)
    print("  All tests passed!")
    print("="*45 + "\n")


if __name__ == '__main__':
    run_all()