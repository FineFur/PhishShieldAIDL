"""
PhishShield AI - Model Training Script

Trains a feed-forward neural network (MLP) for phishing URL detection
using 16 engineered URL features.

Architecture:
    Input(16) → Dense(128, relu) → BatchNorm → Dropout(0.30)
              → Dense(64, relu)  → Dropout(0.20)
              → Dense(32, relu)
              → Dense(1, sigmoid)

Output: Phishing probability (sigmoid)

Usage:
    python model/train_model.py
"""

import os
import sys
import json
import numpy as np

# Set seeds for reproducibility
np.random.seed(42)

import tensorflow as tf
tf.random.set_seed(42)

from tensorflow import keras
from tensorflow.keras import layers, callbacks

# Add project root to path so we can import preprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from preprocess import run_preprocessing, MODEL_DIR


# ── Paths ──────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(MODEL_DIR, "phishshield_model.keras")
METRICS_PATH = os.path.join(MODEL_DIR, "training_metrics.json")

# ── Hyperparameters ────────────────────────────────────────────────────
BATCH_SIZE = 256
EPOCHS = 30
VALIDATION_SPLIT = 0.15


def compute_metrics(y_true, y_pred, y_pred_proba):
    """Compute classification metrics without scikit-learn."""
    y_true = np.asarray(y_true, dtype=int).flatten()
    y_pred = np.asarray(y_pred, dtype=int).flatten()
    y_pred_proba = np.asarray(y_pred_proba, dtype=float).flatten()

    # Confusion matrix
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    # Accuracy
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

    # Precision
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

    # Recall
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    # F1
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    # ROC-AUC (trapezoidal rule)
    roc_auc = compute_roc_auc(y_true, y_pred_proba)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "roc_auc": roc_auc,
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def compute_roc_auc(y_true, y_scores):
    """Compute ROC-AUC using the trapezoidal rule."""
    y_true = np.asarray(y_true, dtype=int)
    y_scores = np.asarray(y_scores, dtype=float)

    # Sort by score descending
    desc_score_indices = np.argsort(y_scores)[::-1]
    y_scores_sorted = y_scores[desc_score_indices]
    y_true_sorted = y_true[desc_score_indices]

    # Get distinct thresholds
    distinct_indices = np.where(np.diff(y_scores_sorted))[0]
    threshold_indices = np.concatenate([distinct_indices, [len(y_true) - 1]])

    tps = np.cumsum(y_true_sorted)[threshold_indices]
    fps = threshold_indices + 1 - tps

    total_pos = np.sum(y_true == 1)
    total_neg = np.sum(y_true == 0)

    if total_pos == 0 or total_neg == 0:
        return 0.5

    tpr = np.concatenate([[0], tps / total_pos])
    fpr = np.concatenate([[0], fps / total_neg])

    # Trapezoidal rule
    auc = np.trapz(tpr, fpr)
    return float(auc)


def build_model(input_dim: int = 16) -> keras.Model:
    """
    Build the PhishShield MLP model.

    Architecture designed for tabular URL features:
    - Moderate depth (4 dense layers)
    - BatchNorm after first hidden layer for training stability
    - Dropout for regularization
    - Sigmoid output for phishing probability
    """
    model = keras.Sequential([
        layers.Input(shape=(input_dim,), name="url_features"),

        layers.Dense(128, activation="relu", name="dense_1"),
        layers.BatchNormalization(name="batch_norm_1"),
        layers.Dropout(0.30, name="dropout_1"),

        layers.Dense(64, activation="relu", name="dense_2"),
        layers.Dropout(0.20, name="dropout_2"),

        layers.Dense(32, activation="relu", name="dense_3"),

        layers.Dense(1, activation="sigmoid", name="output"),
    ])

    model.compile(
        optimizer=keras.optimizers.Adam(),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            keras.metrics.Precision(name="precision"),
            keras.metrics.Recall(name="recall"),
            keras.metrics.AUC(name="auc"),
        ],
    )

    return model


def train_model():
    """Full training pipeline."""
    print("=" * 60)
    print("  PHISHSHIELD AI - MODEL TRAINING")
    print("=" * 60)

    # ── Step 1: Preprocessing ──────────────────────────────────────
    print("\n[PHASE 1] Preprocessing data...")
    data = run_preprocessing()

    X_train = data["X_train"]
    X_test = data["X_test"]
    y_train = data["y_train"]
    y_test = data["y_test"]

    print(f"\nTraining samples: {X_train.shape[0]}")
    print(f"Test samples:     {X_test.shape[0]}")
    print(f"Feature count:    {X_train.shape[1]}")

    # ── Step 2: Build model ────────────────────────────────────────
    print("\n[PHASE 2] Building model...")
    model = build_model(input_dim=X_train.shape[1])
    model.summary()

    # ── Step 3: Callbacks ──────────────────────────────────────────
    early_stop = callbacks.EarlyStopping(
        monitor="val_loss",
        patience=5,
        restore_best_weights=True,
        verbose=1,
    )

    reduce_lr = callbacks.ReduceLROnPlateau(
        monitor="val_loss",
        factor=0.5,
        patience=3,
        min_lr=1e-6,
        verbose=1,
    )

    # ── Step 4: Train ─────────────────────────────────────────────
    print("\n[PHASE 3] Training model...")
    history = model.fit(
        X_train, y_train,
        batch_size=BATCH_SIZE,
        epochs=EPOCHS,
        validation_split=VALIDATION_SPLIT,
        callbacks=[early_stop, reduce_lr],
        verbose=1,
    )

    # ── Step 5: Save model ────────────────────────────────────────
    print("\n[PHASE 4] Saving model...")
    model.save(MODEL_PATH)
    print(f"Model saved -> {MODEL_PATH}")

    # ── Step 6: Evaluate on test set ──────────────────────────────
    print("\n[PHASE 5] Evaluating on test set...")
    y_pred_proba = model.predict(X_test, verbose=0).flatten()
    y_pred = (y_pred_proba >= 0.5).astype(int)

    metrics = compute_metrics(y_test, y_pred, y_pred_proba)
    cm = metrics["confusion_matrix"]

    print("\n" + "=" * 60)
    print("  PHISHSHIELD AI - TEST SET EVALUATION")
    print("=" * 60)
    print(f"  Accuracy:   {metrics['accuracy']:.4f}")
    print(f"  Precision:  {metrics['precision']:.4f}")
    print(f"  Recall:     {metrics['recall']:.4f}")
    print(f"  F1 Score:   {metrics['f1_score']:.4f}")
    print(f"  ROC-AUC:    {metrics['roc_auc']:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    print("=" * 60)

    # ── Step 7: Save metrics ──────────────────────────────────────
    # Extract training history (convert numpy types to Python types)
    hist = {}
    for key, values in history.history.items():
        hist[key] = [float(v) for v in values]

    full_metrics = {
        "accuracy": float(metrics["accuracy"]),
        "precision": float(metrics["precision"]),
        "recall": float(metrics["recall"]),
        "f1_score": float(metrics["f1_score"]),
        "roc_auc": float(metrics["roc_auc"]),
        "confusion_matrix": cm,
        "epochs_trained": len(history.history["loss"]),
        "batch_size": BATCH_SIZE,
        "training_history": hist,
    }

    with open(METRICS_PATH, "w") as f:
        json.dump(full_metrics, f, indent=2)
    print(f"\nMetrics saved -> {METRICS_PATH}")

    print("\n[DONE] Training complete!")
    return model, full_metrics


if __name__ == "__main__":
    train_model()
