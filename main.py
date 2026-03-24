# main.py
# GIF Malware Detector — main entry point
# Usage:
#   py -3.11 main.py scan   path/to/file.gif
#   py -3.11 main.py batch  path/to/folder
#   py -3.11 main.py train
#   py -3.11 main.py test

import sys
import os
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.detector import detect, print_detection_result


def cmd_scan(filepath):
    """
    Scans a single GIF file and prints the result.
    """
    if not os.path.exists(filepath):
        print(f"\n  [!] File not found: {filepath}\n")
        sys.exit(1)

    print(f"\n  Scanning: {filepath}")
    result = detect(filepath)
    print_detection_result(result)
    return result


def cmd_batch(folder):
    """
    Scans all GIF files in a folder.
    Prints a summary table at the end.
    """
    if not os.path.exists(folder):
        print(f"\n  [!] Folder not found: {folder}\n")
        sys.exit(1)

    files = [
        f for f in os.listdir(folder)
        if f.lower().endswith('.gif')
    ]

    if not files:
        print(f"\n  [!] No GIF files found in {folder}\n")
        sys.exit(1)

    print(f"\n  Batch scan: {len(files)} files in {folder}")
    print("  " + "-"*53)

    results   = []
    start     = time.time()

    for filename in sorted(files):
        filepath = os.path.join(folder, filename)
        result   = detect(filepath)
        results.append(result)

        verdict = result['verdict']
        score   = result['score']
        entropy = result['entropy']['overall_entropy'] if result['entropy'] else 0

        print(f"  {filename:<30} {verdict:<12} score={score}  entropy={entropy}")

    total_time = round(time.time() - start, 2)

    # Summary
    safe_count = sum(1 for r in results if r['verdict'] == 'SAFE')
    susp_count = sum(1 for r in results if r['verdict'] == 'SUSPICIOUS')
    mal_count  = sum(1 for r in results if r['verdict'] == 'MALICIOUS')

    print("  " + "-"*53)
    print(f"\n  Total   : {len(results)} files  ({total_time}s)")
    print(f"  Safe    : {safe_count}")
    print(f"  Warning : {susp_count}")
    print(f"  Malicious: {mal_count}")
    print()


def cmd_train():
    """
    Trains the ML model on the dataset.
    """
    from src.ml_model import train_model
    import config

    dataset = 'data/dataset.csv'
    if not os.path.exists(dataset):
        print(f"\n  [!] Dataset not found.")
        print(f"  Run: py -3.11 build.py first\n")
        sys.exit(1)

    train_model(dataset, config.MODEL_PATH)


def cmd_test():
    """
    Runs all unit tests.
    """
    import tests.test_analyzer as ta
    import tests.test_detector as td
    ta.run_all()
    td.run_all()


def print_usage():
    print("""
  GIF Malware Detector
  ════════════════════════════════════════
  Usage:
    py -3.11 main.py scan  <file.gif>     scan one file
    py -3.11 main.py batch <folder>       scan all GIFs in folder
    py -3.11 main.py train                retrain ML model
    py -3.11 main.py test                 run unit tests

  Examples:
    py -3.11 main.py scan  data/safe/safe000.gif
    py -3.11 main.py batch data/malicious
    py -3.11 main.py train
    py -3.11 main.py test
    """)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == 'scan' and len(sys.argv) >= 3:
        cmd_scan(sys.argv[2])

    elif command == 'batch' and len(sys.argv) >= 3:
        cmd_batch(sys.argv[2])

    elif command == 'train':
        cmd_train()

    elif command == 'test':
        cmd_test()

    else:
        print_usage()