"""
PhishShield AI - Data Preprocessing Module

Handles loading, cleaning, splitting, imputing, and scaling
the URL features dataset for the deep-learning model.

IMPORTANT:
- Scaler is fit ONLY on training data (no data leakage).
- Imputation statistics are computed ONLY from training data.
- Feature order is preserved and saved for inference consistency.

NOTE: This module avoids scikit-learn dependency to work on systems
with DLL loading restrictions. StandardScaler is implemented manually.
"""

import os
import json
import math
import random
import pandas as pd
import numpy as np
import pickle

# ── Feature columns (exact order for model input) ─────────────────────
FEATURE_COLUMNS = [
    "url_length",
    "has_ip_address",
    "dot_count",
    "https_flag",
    "url_entropy",
    "token_count",
    "subdomain_count",
    "query_param_count",
    "tld_length",
    "path_length",
    "has_hyphen_in_domain",
    "number_of_digits",
    "tld_popularity",
    "suspicious_file_extension",
    "domain_name_length",
    "percentage_numeric_chars",
    "uses_free_hosting",   # NEW: detects zphisher-style hosting (ngrok, 000webhost, etc.)
    "brand_in_path",       # NEW: detects brand impersonation in path/subdomain
]

# ── Paths ──────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATASET_PATH = os.path.join(PROJECT_ROOT, "dataset", "url_features_extracted1.csv")
MODEL_DIR = BASE_DIR  # model/ folder
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
FEATURE_COLUMNS_PATH = os.path.join(MODEL_DIR, "feature_columns.pkl")


class ManualStandardScaler:
    """
    A simple StandardScaler implementation that does not require scikit-learn.
    Computes z-score normalization: (x - mean) / std

    Compatible with the scikit-learn API: fit(), transform(), fit_transform().
    """

    def __init__(self):
        self.mean_ = None
        self.scale_ = None
        self.var_ = None
        self.n_features_in_ = None

    def fit(self, X):
        """Compute mean and std from training data."""
        X = np.asarray(X, dtype=np.float64)
        self.n_features_in_ = X.shape[1]
        self.mean_ = np.mean(X, axis=0)
        self.var_ = np.var(X, axis=0)
        self.scale_ = np.sqrt(self.var_)
        # Prevent division by zero
        self.scale_[self.scale_ == 0] = 1.0
        return self

    def transform(self, X):
        """Apply z-score normalization."""
        X = np.asarray(X, dtype=np.float64)
        return (X - self.mean_) / self.scale_

    def fit_transform(self, X):
        """Fit and transform in one step."""
        self.fit(X)
        return self.transform(X)


def load_dataset(path: str = DATASET_PATH) -> pd.DataFrame:
    """Load the CSV dataset."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found at: {path}")
    df = pd.read_csv(path)
    print(f"[INFO] Loaded dataset: {df.shape[0]} rows, {df.shape[1]} columns")
    return df


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Remove missing labels and duplicates."""
    initial = len(df)
    df = df.dropna(subset=["ClassLabel"])
    df = df.drop_duplicates()
    print(f"[INFO] Cleaned dataset: {initial} -> {len(df)} rows")
    return df


def prepare_features_and_labels(df: pd.DataFrame):
    """
    Extract feature matrix X and convert ClassLabel to phishing target y.

    ClassLabel semantics in dataset:
        0 = phishing
        1 = legitimate

    We convert to y_phishing:
        1 = phishing  (ClassLabel == 0)
        0 = legitimate (ClassLabel == 1)

    So the sigmoid output directly represents PHISHING PROBABILITY.
    """
    # Verify all feature columns exist
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing feature columns in dataset: {missing}")

    X = df[FEATURE_COLUMNS].copy()
    y = (df["ClassLabel"] == 0).astype(int)  # phishing = 1
    print(f"[INFO] Label distribution: phishing={y.sum()}, legitimate={len(y) - y.sum()}")
    return X, y


def stratified_train_test_split(X, y, test_size=0.20, random_state=42):
    """
    Stratified train/test split without scikit-learn.
    Ensures class proportions are maintained.
    """
    random.seed(random_state)
    np.random.seed(random_state)

    y_arr = np.asarray(y)
    indices = np.arange(len(y_arr))

    # Separate indices by class
    class_0_idx = indices[y_arr == 0].tolist()
    class_1_idx = indices[y_arr == 1].tolist()

    # Shuffle each class
    random.shuffle(class_0_idx)
    random.shuffle(class_1_idx)

    # Split each class
    n_test_0 = int(len(class_0_idx) * test_size)
    n_test_1 = int(len(class_1_idx) * test_size)

    test_idx = class_0_idx[:n_test_0] + class_1_idx[:n_test_1]
    train_idx = class_0_idx[n_test_0:] + class_1_idx[n_test_1:]

    # Shuffle final indices
    random.shuffle(test_idx)
    random.shuffle(train_idx)

    if isinstance(X, pd.DataFrame):
        X_train = X.iloc[train_idx].copy()
        X_test = X.iloc[test_idx].copy()
    else:
        X_train = X[train_idx]
        X_test = X[test_idx]

    if isinstance(y, pd.Series):
        y_train = y.iloc[train_idx].copy()
        y_test = y.iloc[test_idx].copy()
    else:
        y_train = y[train_idx]
        y_test = y[test_idx]

    print(f"[INFO] Train: {len(X_train)}, Test: {len(X_test)}")
    return X_train, X_test, y_train, y_test


def impute_missing_values(X_train: pd.DataFrame, X_test: pd.DataFrame):
    """
    Handle invalid subdomain_count values.
    -1 is treated as missing → replaced with NaN → filled with training median.
    Imputation statistics computed ONLY from training data.
    """
    # Replace -1 with NaN in subdomain_count
    X_train["subdomain_count"] = X_train["subdomain_count"].replace(-1, np.nan)
    X_test["subdomain_count"] = X_test["subdomain_count"].replace(-1, np.nan)

    # Compute median from training data ONLY
    train_median = X_train["subdomain_count"].median()
    print(f"[INFO] subdomain_count training median: {train_median}")

    # Fill NaN with training median
    X_train["subdomain_count"] = X_train["subdomain_count"].fillna(train_median)
    X_test["subdomain_count"] = X_test["subdomain_count"].fillna(train_median)

    return X_train, X_test, train_median


def scale_features(X_train: pd.DataFrame, X_test: pd.DataFrame):
    """
    Fit ManualStandardScaler on training data ONLY, transform both sets.
    No data leakage.
    """
    scaler = ManualStandardScaler()
    X_train_scaled = scaler.fit_transform(X_train.values)
    X_test_scaled = scaler.transform(X_test.values)
    print("[INFO] Features scaled with StandardScaler (fit on training data only)")
    return X_train_scaled, X_test_scaled, scaler


def save_artifacts(scaler, feature_columns, scaler_path=SCALER_PATH, fc_path=FEATURE_COLUMNS_PATH):
    """Save scaler and feature column order for inference."""
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    with open(fc_path, "wb") as f:
        pickle.dump(feature_columns, f)
    print(f"[INFO] Saved scaler -> {scaler_path}")
    print(f"[INFO] Saved feature_columns -> {fc_path}")


def run_preprocessing(dataset_path: str = DATASET_PATH):
    """
    Full preprocessing pipeline. Returns processed data and artifacts.
    """
    df = load_dataset(dataset_path)
    df = clean_dataset(df)
    X, y = prepare_features_and_labels(df)
    X_train, X_test, y_train, y_test = stratified_train_test_split(X, y)
    X_train, X_test, subdomain_median = impute_missing_values(X_train, X_test)
    X_train_scaled, X_test_scaled, scaler = scale_features(X_train, X_test)
    save_artifacts(scaler, FEATURE_COLUMNS)

    return {
        "X_train": X_train_scaled,
        "X_test": X_test_scaled,
        "y_train": y_train.values if hasattr(y_train, 'values') else np.asarray(y_train),
        "y_test": y_test.values if hasattr(y_test, 'values') else np.asarray(y_test),
        "scaler": scaler,
        "feature_columns": FEATURE_COLUMNS,
        "subdomain_median": subdomain_median,
    }


if __name__ == "__main__":
    data = run_preprocessing()
    print(f"\n[DONE] X_train shape: {data['X_train'].shape}")
    print(f"[DONE] X_test shape: {data['X_test'].shape}")
