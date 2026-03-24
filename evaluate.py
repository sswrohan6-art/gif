# evaluate.py
# Full evaluation of the GIF malware detector
# Tests all files in data/safe and data/malicious
# and generates a complete performance report

import os
import sys
import csv
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.detector import detect, VERDICT_SAFE, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS


# ── Config ───────────────────────────────────────────────────────────
SAFE_DIR      = 'data/safe'
MALICIOUS_DIR = 'data/malicious'
REPORT_PATH   = 'data/evaluation_report.csv'


def scan_folder(folder, expected_label):
    """
    Scans all GIF files in a folder and returns results.
    expected_label: 'safe' or 'malicious'
    """
    results = []

    if not os.path.exists(folder):
        print(f"  [!] Folder not found: {folder}")
        return results

    files = [f for f in os.listdir(folder) if f.endswith('.gif')]
    files.sort()

    print(f"\n  Scanning {len(files)} files in {folder}...")

    for i, filename in enumerate(files):
        filepath = os.path.join(folder, filename)

        start_time = time.time()
        result     = detect(filepath)
        scan_time  = round(time.time() - start_time, 3)

        verdict  = result['verdict']
        score    = result['score']
        entropy  = result['entropy']['overall_entropy'] if result['entropy'] else 0
        ml_vote  = result['ml_prediction']
        ml_conf  = result['ml_confidence']

        # Determine if detection was correct
        if expected_label == 'safe':
            is_correct = verdict == VERDICT_SAFE
        else:
            is_correct = verdict in [VERDICT_SUSPICIOUS, VERDICT_MALICIOUS]

        status = 'OK' if is_correct else 'WRONG'

        print(f"    [{status}] {filename:<25} "
              f"verdict={verdict:<12} "
              f"score={score}  "
              f"entropy={entropy}")

        results.append({
            'filename':      filename,
            'expected':      expected_label,
            'verdict':       verdict,
            'score':         score,
            'entropy':       entropy,
            'ml_vote':       ml_vote,
            'ml_confidence': ml_conf,
            'is_correct':    is_correct,
            'scan_time':     scan_time,
            'flags':         len(result['flags']),
        })

    return results


def calculate_metrics(results):
    """
    Calculates precision, recall, F1, and accuracy
    from the full results list.
    """
    tp = 0  # malicious correctly detected
    tn = 0  # safe correctly cleared
    fp = 0  # safe wrongly flagged as malicious
    fn = 0  # malicious wrongly cleared as safe

    for r in results:
        predicted_mal = r['verdict'] in [VERDICT_SUSPICIOUS, VERDICT_MALICIOUS]
        actual_mal    = r['expected'] == 'malicious'

        if actual_mal and predicted_mal:
            tp += 1
        elif not actual_mal and not predicted_mal:
            tn += 1
        elif not actual_mal and predicted_mal:
            fp += 1
        elif actual_mal and not predicted_mal:
            fn += 1

    total    = tp + tn + fp + fn
    accuracy  = round((tp + tn) / total * 100, 2)       if total        else 0
    precision = round(tp / (tp + fp) * 100, 2)          if (tp + fp)    else 0
    recall    = round(tp / (tp + fn) * 100, 2)          if (tp + fn)    else 0
    f1        = round(2 * tp / (2*tp + fp + fn) * 100, 2) if (2*tp+fp+fn) else 0

    return {
        'tp':        tp,
        'tn':        tn,
        'fp':        fp,
        'fn':        fn,
        'total':     total,
        'accuracy':  accuracy,
        'precision': precision,
        'recall':    recall,
        'f1':        f1,
    }


def save_report(results, report_path):
    """
    Saves all results to a CSV file for further analysis.
    """
    if not results:
        return

    with open(report_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    print(f"\n  Report saved → {report_path}")


def print_summary(metrics, total_time):
    """
    Prints the final evaluation summary.
    """
    print("\n" + "="*55)
    print("  Evaluation Summary")
    print("="*55)
    print(f"  Total files scanned : {metrics['total']}")
    print(f"  Total scan time     : {round(total_time, 2)}s")
    print(f"  Avg time per file   : {round(total_time/metrics['total'], 3)}s")
    print()
    print(f"  True  Positives     : {metrics['tp']}  (malicious caught)")
    print(f"  True  Negatives     : {metrics['tn']}  (safe cleared)")
    print(f"  False Positives     : {metrics['fp']}  (safe wrongly flagged)")
    print(f"  False Negatives     : {metrics['fn']}  (malicious missed!)")
    print()
    print(f"  Accuracy            : {metrics['accuracy']}%")
    print(f"  Precision           : {metrics['precision']}%")
    print(f"  Recall              : {metrics['recall']}%")
    print(f"  F1 Score            : {metrics['f1']}%")

    print()
    if metrics['fn'] == 0:
        print("  No malicious files were missed.")
    else:
        print(f"  WARNING: {metrics['fn']} malicious file(s) were missed!")

    if metrics['fp'] == 0:
        print("  No safe files were wrongly flagged.")
    else:
        print(f"  NOTE: {metrics['fp']} safe file(s) were wrongly flagged.")

    print("="*55 + "\n")


def run_evaluation():
    """
    MAIN FUNCTION — runs the full evaluation pipeline.
    """
    print("\n" + "="*55)
    print("  GIF Malware Detector — Full Evaluation")
    print("="*55)

    start_time = time.time()
    all_results = []

    # ── Scan safe files ──────────────────────────────────────────────
    safe_results = scan_folder(SAFE_DIR, 'safe')
    all_results.extend(safe_results)

    # ── Scan malicious files ─────────────────────────────────────────
    mal_results = scan_folder(MALICIOUS_DIR, 'malicious')
    all_results.extend(mal_results)

    total_time = time.time() - start_time

    if not all_results:
        print("\n  [!] No files found to evaluate.")
        return

    # ── Calculate metrics ────────────────────────────────────────────
    metrics = calculate_metrics(all_results)

    # ── Save CSV report ──────────────────────────────────────────────
    save_report(all_results, REPORT_PATH)

    # ── Print summary ────────────────────────────────────────────────
    print_summary(metrics, total_time)


if __name__ == '__main__':
    run_evaluation()