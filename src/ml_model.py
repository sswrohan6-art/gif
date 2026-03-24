# src/ml_model.py
# Trains a Random Forest classifier on dataset.csv
# and provides prediction functions for the detector

import os
import sys
import pickle
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

try:
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        classification_report,
        confusion_matrix,
        accuracy_score
    )
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


# ── Feature columns the model trains on ─────────────────────────────
# Must match exactly what extract_features() produces in build.py
FEATURE_COLUMNS = [
    'size_kb',
    'size_mb',
    'is_valid_header',
    'width',
    'height',
    'frame_count',
    'has_transparency',
    'has_comments',
    'suspicious_comments',
    'overall_entropy',
    'max_chunk_entropy',
    'min_chunk_entropy',
    'avg_chunk_entropy',
    'suspicious_chunks',
    'is_high_entropy',
    'is_low_entropy',
]


def load_dataset(dataset_path):
    """
    Loads dataset.csv into a pandas DataFrame.
    Separates features (X) from labels (y).
    """
    if not ML_AVAILABLE:
        raise ImportError("pandas/sklearn not installed")

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)

    print(f"  Dataset loaded: {len(df)} samples")
    print(f"  Safe      : {len(df[df['label']==0])}")
    print(f"  Malicious : {len(df[df['label']==1])}")
    print(f"  Features  : {len(FEATURE_COLUMNS)}")

    X = df[FEATURE_COLUMNS].values
    y = df['label'].values

    return X, y, df


def train_model(dataset_path, model_save_path):
    """
    Trains a Random Forest classifier and saves it to disk.

    Steps:
        1. Load dataset
        2. Split into train/test sets (80/20)
        3. Train Random Forest with 100 trees
        4. Evaluate on test set
        5. Save model to .pkl file
    """
    if not ML_AVAILABLE:
        print("  [!] scikit-learn not available. Skipping ML training.")
        return None

    print("\n" + "="*55)
    print("  Training Random Forest Classifier")
    print("="*55)

    # ── Load data ────────────────────────────────────────────────────
    X, y, df = load_dataset(dataset_path)

    # ── Split 80% train / 20% test ───────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,      # fixed seed = reproducible results
        stratify=y            # keeps class balance in both splits
    )

    print(f"\n  Train samples : {len(X_train)}")
    print(f"  Test samples  : {len(X_test)}")

    # ── Train the model ──────────────────────────────────────────────
    print("\n  Training Random Forest (100 trees)...")
    model = RandomForestClassifier(
        n_estimators=100,     # 100 decision trees
        max_depth=10,         # prevents overfitting
        min_samples_split=2,
        random_state=42,
        n_jobs=-1             # use all CPU cores
    )
    model.fit(X_train, y_train)
    print("  Training complete!")

    # ── Evaluate on test set ─────────────────────────────────────────
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n  Accuracy : {accuracy * 100:.2f}%")
    print("\n  Classification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=['Safe', 'Malicious']
    ))

    print("  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"              Predicted Safe  Predicted Malicious")
    print(f"  Actual Safe       {cm[0][0]:<6}        {cm[0][1]}")
    print(f"  Actual Malicious  {cm[1][0]:<6}        {cm[1][1]}")

    # ── Feature importance ───────────────────────────────────────────
    print("\n  Top 5 most important features:")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    for i in range(min(5, len(FEATURE_COLUMNS))):
        feat = FEATURE_COLUMNS[indices[i]]
        imp  = importances[indices[i]]
        print(f"    {i+1}. {feat:<25} {imp:.4f}")

    # ── Save model ───────────────────────────────────────────────────
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    model_data = {
        'model':           model,
        'feature_columns': FEATURE_COLUMNS,
        'accuracy':        accuracy,
    }
    with open(model_save_path, 'wb') as f:
        pickle.dump(model_data, f)

    print(f"\n  Model saved → {model_save_path}")
    print("="*55 + "\n")

    return model


def load_model(model_path):
    """
    Loads a previously trained model from disk.
    Returns the model and feature column list.
    """
    if not os.path.exists(model_path):
        return None, None

    with open(model_path, 'rb') as f:
        model_data = pickle.load(f)

    return model_data['model'], model_data['feature_columns']


def predict(filepath, model_path):
    """
    Runs ML prediction on a single GIF file.
    Returns prediction (0/1) and confidence percentage.
    Called by detector.py to add ML vote to the score.
    """
    if not ML_AVAILABLE:
        return None, 0.0

    model, feature_cols = load_model(model_path)
    if model is None:
        return None, 0.0

    # Import here to avoid circular imports
    from src.analyzer import analyze_gif
    from src.entropy  import analyze_entropy

    try:
        analysis  = analyze_gif(filepath)
        raw_bytes = analysis.get('raw_bytes', b'')
        entropy   = analyze_entropy(raw_bytes) if raw_bytes else {}

        # Build feature vector in the same order as training
        features = {
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
        }

        X = np.array([[features[col] for col in feature_cols]])

        prediction   = model.predict(X)[0]
        probability  = model.predict_proba(X)[0]
        confidence   = round(float(max(probability)) * 100, 2)

        return int(prediction), confidence

    except Exception as e:
        print(f"  [!] ML prediction failed: {e}")
        return None, 0.0