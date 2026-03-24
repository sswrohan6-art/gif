# GIF Malware Detector

A Python tool that detects malicious GIF files using static
analysis, entropy analysis, and machine learning.

## How It Works

1. Static Analysis  — validates GIF headers, structure, comments
2. Entropy Analysis — detects hidden/encrypted payloads
3. Rule-based Score — accumulates risk points from all flags
4. ML Model         — Random Forest classifier adds final vote

## Setup

    py -3.11 -m pip install -r requirements.txt

## Usage

    # Scan a single file
    py -3.11 main.py scan path/to/file.gif

    # Scan an entire folder
    py -3.11 main.py batch data/malicious

    # Retrain the ML model
    py -3.11 main.py train

    # Run unit tests
    py -3.11 main.py test

## Project Structure

    f_malware_detector/
    ├── main.py              CLI entry point
    ├── config.py            tunable thresholds
    ├── build.py             dataset generator
    ├── trainmodel.py        ML training script
    ├── evaluate.py          full evaluation suite
    ├── src/
    │   ├── analyzer.py      GIF parser
    │   ├── entropy.py       Shannon entropy
    │   ├── detector.py      rule-based engine
    │   ├── ml_model.py      Random Forest classifier
    │   └── utils.py         shared helpers
    ├── data/
    │   ├── safe/            benign GIF samples
    │   ├── malicious/       suspicious GIF samples
    │   └── dataset.csv      feature dataset
    ├── models/
    │   └── classifier.pkl   trained ML model
    └── tests/
        ├── test_analyzer.py
        └── test_detector.py

## Detection Verdicts

| Verdict    | Score | Meaning                        |
|------------|-------|--------------------------------|
| SAFE       | 0-2   | No suspicious indicators       |
| SUSPICIOUS | 3-4   | Some red flags, review manually|
| MALICIOUS  | 5+    | High confidence threat         |

## Evaluation Results

- Accuracy  : 100%
- Precision : 100%
- Recall    : 100%
- F1 Score  : 100%
- Dataset   : 100 samples (50 safe, 50 malicious)