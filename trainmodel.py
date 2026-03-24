# trainmodel.py
# Run this to train the ML model on your dataset
# Usage: py -3.11 trainmodel.py

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.ml_model import train_model
import config

if __name__ == '__main__':
    dataset  = 'data/dataset.csv'
    savepath = config.MODEL_PATH

    if not os.path.exists(dataset):
        print(f"\n[!] Dataset not found: {dataset}")
        print("    Run build.py first to generate the dataset.\n")
        sys.exit(1)

    model = train_model(dataset, savepath)

    if model:
        print("Model training complete!")
        print(f"Saved to: {savepath}")
    else:
        print("Training failed.")