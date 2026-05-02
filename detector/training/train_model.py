"""Train Isolation Forest on collected normal DNS traffic features.

Usage:
  python train_model.py \
    --input data/normal_features.parquet \
    --output data/iforest.joblib

To score later:
  import joblib, numpy as np
  model = joblib.load("iforest.joblib")
  # score_samples: higher (less negative) = more normal
  score = model.score_samples(vec.reshape(1, -1))[0]
"""
import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from features import FEATURE_NAMES


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest on DNS features")
    parser.add_argument("--input", required=True, help="Parquet file from generate_training_data.py")
    parser.add_argument("--output", required=True, help="Output joblib model path")
    parser.add_argument("--contamination", type=float, default=0.01,
                        help="Expected fraction of outliers in training data (default 0.01)")
    parser.add_argument("--n-estimators", type=int, default=100,
                        help="Number of trees (default 100)")
    args = parser.parse_args()

    df = pd.read_parquet(args.input)
    print(f"Loaded {len(df)} samples, {len(df.columns)} features")
    assert list(df.columns) == FEATURE_NAMES, \
        f"Column mismatch. Expected {FEATURE_NAMES}, got {list(df.columns)}"
    assert not df.isnull().any().any(), "NaN values found in training data"
    zero_var = df.columns[df.var() == 0].tolist()
    if zero_var:
        print(f"Warning: zero-variance features: {zero_var}")

    X = df.values.astype(np.float32)
    X_train, X_val = train_test_split(X, test_size=0.1, random_state=42)
    print(f"Train: {len(X_train)}, Val: {len(X_val)}")

    model = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)

    train_scores = model.score_samples(X_train)
    val_scores = model.score_samples(X_val)
    print(f"Train scores  mean={train_scores.mean():.4f}  std={train_scores.std():.4f}")
    print(f"Val scores    mean={val_scores.mean():.4f}  std={val_scores.std():.4f}")

    gap = abs(train_scores.mean() - val_scores.mean())
    if gap > train_scores.std():
        print(f"Warning: train/val mean gap ({gap:.4f}) exceeds train std — possible overfit")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, out)
    print(f"Saved model to {out}")
    print(f"Feature order: {FEATURE_NAMES}")


if __name__ == "__main__":
    main()
