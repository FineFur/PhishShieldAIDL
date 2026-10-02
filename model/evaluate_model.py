"""
PhishShield AI - Model Evaluation Script

Loads the trained model and evaluates it on the test set.
Prints a comprehensive evaluation report.

Usage:
    python model/evaluate_model.py
"""

import os
import sys
import json
import numpy as np

np.random.seed(42)

import tensorflow as tf
tf.random.set_seed(42)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from preprocess import run_preprocessing, MODEL_DIR
from train_model import compute_metrics

MODEL_PATH = os.path.join(MODEL_DIR, "phishshield_model.keras")
METRICS_PATH = os.path.join(MODEL_DIR, "training_metrics.json")


def evaluate_model():
    """Load trained model, evaluate on test set, print report."""
    print("=" * 60)
    print("  PHISHSHIELD AI - MODEL EVALUATION")
    print("=" * 60)

    # Check model exists
    if not os.path.exists(MODEL_PATH):
        print(f"[ERROR] Model not found at: {MODEL_PATH}")
        print("Please run train_model.py first.")
        sys.exit(1)

    # Preprocess (same pipeline as training)
    print("\n[1/3] Loading and preprocessing data...")
    data = run_preprocessing()

    X_test = data["X_test"]
    y_test = data["y_test"]

    # Load model
    print("[2/3] Loading trained model...")
    model = tf.keras.models.load_model(MODEL_PATH)
    print(f"  Model input shape: {model.input_shape}")

    # Predict
    print("[3/3] Running predictions on test set...")
    y_pred_proba = model.predict(X_test, verbose=0).flatten()
    y_pred = (y_pred_proba >= 0.5).astype(int)

    # Metrics
    metrics = compute_metrics(y_test, y_pred, y_pred_proba)
    cm = metrics["confusion_matrix"]
    acc = metrics["accuracy"]
    prec = metrics["precision"]
    rec = metrics["recall"]
    f1 = metrics["f1_score"]
    roc = metrics["roc_auc"]

    # Report
    print("\n" + "=" * 60)
    print("  PHISHSHIELD AI MODEL EVALUATION REPORT")
    print("=" * 60)
    print(f"\n  Accuracy:    {acc:.4f}  ({acc * 100:.2f}%)")
    print(f"  Precision:   {prec:.4f}  ({prec * 100:.2f}%)")
    print(f"  Recall:      {rec:.4f}  ({rec * 100:.2f}%)")
    print(f"  F1 Score:    {f1:.4f}  ({f1 * 100:.2f}%)")
    print(f"  ROC-AUC:     {roc:.4f}  ({roc * 100:.2f}%)")

    print(f"\n  Confusion Matrix (Phishing positive):")
    print(f"  ┌─────────────┬──────────────┬──────────────┐")
    print(f"  │             │ Pred Legit   │ Pred Phish   │")
    print(f"  ├─────────────┼──────────────┼──────────────┤")
    print(f"  │ True Legit  │ TN = {cm[0][0]:<6} │ FP = {cm[0][1]:<6} │")
    print(f"  │ True Phish  │ FN = {cm[1][0]:<6} │ TP = {cm[1][1]:<6} │")
    print(f"  └─────────────┴──────────────┴──────────────┘")

    print(f"\n  Phishing Recall (sensitivity): {rec:.4f}")
    print(f"    -> {rec * 100:.1f}% of actual phishing URLs were correctly detected.")
    print(f"\n  Phishing Precision: {prec:.4f}")
    print(f"    -> {prec * 100:.1f}% of URLs flagged as phishing were actually phishing.")

    # Update metrics file
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, "r") as f:
            existing = json.load(f)
        existing.update(metrics)
        metrics = existing

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\n  Metrics updated -> {METRICS_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    evaluate_model()
