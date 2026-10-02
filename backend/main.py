"""
PhishShield AI - FastAPI Backend

Provides REST API endpoints for URL phishing detection using a
TensorFlow/Keras deep-learning model with 16 engineered URL features.

Endpoints:
    GET  /           - API status
    GET  /health     - Health check (model loaded status)
    GET  /model-info - Model metadata and training metrics
    POST /predict    - Analyze a URL for phishing probability

SECURITY: This backend performs STATIC URL analysis only.
It never visits, crawls, or requests the submitted website.

Usage:
    uvicorn main:app --reload --host 127.0.0.1 --port 8000
"""

import os
import re
import sys
import json
import logging
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import numpy as np
import pickle
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from schemas import (
    PredictRequest, PredictResponse, HealthResponse,
    ModelInfoResponse, ErrorResponse,
)
from feature_extractor import extract_url_features

# Add model to path for import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model.train_numpy_mlp import NumpyMLP

# ── Logging ────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("phishshield")

# ── Paths ──────────────────────────────────────────────────────────────
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
MODEL_DIR = os.path.join(PROJECT_ROOT, "model")

MODEL_PATH = os.path.join(MODEL_DIR, "numpy_mlp_weights.json")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
FEATURE_COLUMNS_PATH = os.path.join(MODEL_DIR, "feature_columns.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "training_metrics.json")

# ── Risk thresholds (configurable in one place) ───────────────────────
RISK_THRESHOLDS = {
    "low_max": 0.29,
    "medium_max": 0.69,
    # anything above medium_max is "High"
}

# ── Blocked URL schemes ───────────────────────────────────────────────
ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_SCHEMES = {"javascript", "file", "data", "ftp", "mailto", "tel"}

# ── Max URL length ────────────────────────────────────────────────────
MAX_URL_LENGTH = 2048

# ── Global model artifacts ─────────────────────────────────────────────
model = None
scaler = None
feature_columns = None
training_metrics = None


# Add model directory to sys.path so pickle can find ManualStandardScaler
if MODEL_DIR not in sys.path:
    sys.path.insert(0, MODEL_DIR)

def load_artifacts():
    """Load model artifacts at startup."""
    global model, scaler, feature_columns, training_metrics

    logger.info("Loading model artifacts...")

    # Load model
    if not os.path.exists(MODEL_PATH):
        logger.error(f"Model file not found: {MODEL_PATH}")
        logger.error("Please run: python model/train_model.py")
        return

    try:
        model = NumpyMLP(input_dim=18, hidden_dim1=128, hidden_dim2=64)
        model.load(MODEL_PATH)
        logger.info(f"NumpyMLP model loaded: {MODEL_PATH}")
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return

    # Load scaler
    if not os.path.exists(SCALER_PATH):
        logger.error(f"Scaler file not found: {SCALER_PATH}")
        return
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    logger.info(f"Scaler loaded: {SCALER_PATH}")

    # Load feature columns
    if not os.path.exists(FEATURE_COLUMNS_PATH):
        logger.error(f"Feature columns file not found: {FEATURE_COLUMNS_PATH}")
        return
    with open(FEATURE_COLUMNS_PATH, "rb") as f:
        feature_columns = pickle.load(f)
    logger.info(f"Feature columns loaded: {len(feature_columns)} features")

    # Validate dimensions
    if len(feature_columns) != 18:
        logger.warning(f"Feature columns count {len(feature_columns)} != 18")

    # Load training metrics
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, "r") as f:
            training_metrics = json.load(f)
        logger.info("Training metrics loaded")
    else:
        logger.warning("Training metrics file not found")

    logger.info("All artifacts loaded successfully!")


@asynccontextmanager
async def lifespan(app):
    """Lifespan context manager - load artifacts on startup."""
    load_artifacts()
    yield
    logger.info("Shutting down PhishShield AI API")


# ── FastAPI App ────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishShield AI API",
    description=(
        "Intelligent Phishing Website Detection Using Deep Learning. "
        "Analyzes URL features to determine phishing probability."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── URL Validation ─────────────────────────────────────────────────────

def validate_and_normalize_url(url: str) -> str:
    """
    Validate and normalize user-submitted URL.

    Handles:
    - Empty/whitespace input
    - Missing protocol (defaults to https://)
    - Blocked schemes (javascript:, file:, data:, ftp:)
    - Extremely long URLs
    - Invalid domains
    - Malformed URLs

    Returns normalized URL string.
    Raises HTTPException on invalid input.
    """
    # Strip whitespace
    url = url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # Check length
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"URL exceeds maximum length of {MAX_URL_LENGTH} characters.",
        )

    # Check for blocked schemes
    url_lower = url.lower()
    for scheme in BLOCKED_SCHEMES:
        if url_lower.startswith(f"{scheme}:"):
            raise HTTPException(
                status_code=400,
                detail=f"URL scheme '{scheme}' is not allowed. Only http:// and https:// are supported.",
            )

    # Add https:// if no scheme provided
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = "https://" + url

    # Parse and validate
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed URL.")

    # Check scheme
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise HTTPException(
            status_code=400,
            detail=f"URL scheme '{parsed.scheme}' is not supported. Only http:// and https:// are allowed.",
        )

    # Check hostname exists
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid URL: no domain found.")

    # Check for unusual characters in hostname
    hostname = parsed.hostname
    if not re.match(r'^[a-zA-Z0-9.\-:\[\]]+$', hostname):
        # Allow through but log - some phishing URLs have unusual characters
        logger.warning(f"URL hostname contains unusual characters: {hostname}")

    return url


# ── Risk Classification ───────────────────────────────────────────────

def classify_risk(phishing_prob: float) -> str:
    """
    Classify risk level based on phishing probability.
    Application-level risk bands (not universal cybersecurity standards).
    """
    if phishing_prob <= RISK_THRESHOLDS["low_max"]:
        return "Low"
    elif phishing_prob <= RISK_THRESHOLDS["medium_max"]:
        return "Medium"
    else:
        return "High"


def generate_recommendation(phishing_prob: float, risk_level: str, features: dict) -> str:
    """Generate a human-readable recommendation based on analysis results."""
    if risk_level == "Low":
        return (
            "The URL appears relatively low risk based on its URL structure. "
            "Standard security practices are still recommended."
        )
    elif risk_level == "Medium":
        return (
            "The URL shows some characteristics that may be associated with phishing. "
            "Exercise caution and verify the website's authenticity before entering any sensitive information."
        )
    else:
        return (
            "The URL exhibits multiple characteristics commonly associated with phishing websites. "
            "It is strongly recommended to avoid entering personal or financial information on this website."
        )


def generate_feature_explanations(features: dict) -> list:
    """
    Generate contextual explanations for notable features.
    Explanations are based on actual extracted values, not assumptions.
    """
    explanations = []

    if features.get("https_flag") == 0:
        explanations.append({
            "feature": "HTTPS",
            "value": "Not Enabled",
            "status": "warning",
            "explanation": "The URL does not use HTTPS encrypted transport."
        })
    else:
        explanations.append({
            "feature": "HTTPS",
            "value": "Enabled",
            "status": "safe",
            "explanation": "Encrypted transport (HTTPS) is present."
        })

    if features.get("has_ip_address") == 1:
        explanations.append({
            "feature": "IP Address",
            "value": "Detected",
            "status": "warning",
            "explanation": "The URL uses an IP address rather than a conventional domain name."
        })
    else:
        explanations.append({
            "feature": "IP Address",
            "value": "Not Detected",
            "status": "safe",
            "explanation": "The URL uses a conventional domain name."
        })

    url_len = features.get("url_length", 0)
    if url_len > 75:
        explanations.append({
            "feature": "URL Length",
            "value": str(url_len),
            "status": "warning",
            "explanation": "The URL is unusually long, which can be a phishing indicator."
        })
    else:
        explanations.append({
            "feature": "URL Length",
            "value": str(url_len),
            "status": "safe",
            "explanation": "The URL length is within a typical range."
        })

    sub_count = features.get("subdomain_count", 0)
    if sub_count > 2:
        explanations.append({
            "feature": "Subdomains",
            "value": str(int(sub_count)),
            "status": "warning",
            "explanation": "Multiple subdomains detected, which may indicate URL complexity."
        })
    else:
        explanations.append({
            "feature": "Subdomains",
            "value": str(int(sub_count)),
            "status": "safe",
            "explanation": "The subdomain count is within a normal range."
        })

    digit_count = features.get("number_of_digits", 0)
    if digit_count > 5:
        explanations.append({
            "feature": "Digits",
            "value": str(digit_count),
            "status": "warning",
            "explanation": "The URL contains a high number of digit characters."
        })
    else:
        explanations.append({
            "feature": "Digits",
            "value": str(digit_count),
            "status": "safe",
            "explanation": "The digit count in the URL is within a typical range."
        })

    if features.get("suspicious_file_extension") == 1:
        explanations.append({
            "feature": "File Extension",
            "value": "Suspicious",
            "status": "warning",
            "explanation": "The URL points to a potentially suspicious file type."
        })

    if features.get("has_hyphen_in_domain") == 1:
        explanations.append({
            "feature": "Hyphen in Domain",
            "value": "Present",
            "status": "info",
            "explanation": "The domain name contains a hyphen, sometimes used to mimic legitimate domains."
        })

    entropy = features.get("url_entropy", 0)
    if entropy > 4.5:
        explanations.append({
            "feature": "URL Entropy",
            "value": f"{entropy:.2f}",
            "status": "warning",
            "explanation": "High entropy suggests randomness in the URL, which can be a phishing characteristic."
        })

    path_len = features.get("path_length", 0)
    if path_len > 30:
        explanations.append({
            "feature": "Path Length",
            "value": str(path_len),
            "status": "info",
            "explanation": "The URL has a relatively long path component."
        })

    return explanations


# ── API Endpoints ──────────────────────────────────────────────────────

@app.get("/", tags=["Status"])
async def root():
    """API root endpoint."""
    return {"message": "PhishShield AI API", "status": "running"}


@app.get("/health", response_model=HealthResponse, tags=["Status"])
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy" if model is not None else "degraded",
        "model_loaded": model is not None,
    }


@app.get("/model-info", response_model=ModelInfoResponse, tags=["Model"])
async def model_info():
    """Return model metadata and training metrics."""
    if feature_columns is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded.")

    # Prepare safe metrics (exclude training_history to keep response small)
    safe_metrics = None
    if training_metrics:
        safe_metrics = {
            k: v for k, v in training_metrics.items()
            if k != "training_history"
        }

    return {
        "model_name": "PhishShield AI",
        "feature_count": len(feature_columns),
        "features": list(feature_columns),
        "model_type": "Feed-Forward Neural Network (MLP)",
        "framework": "TensorFlow/Keras",
        "training_metrics": safe_metrics,
    }


@app.post(
    "/predict",
    response_model=PredictResponse,
    responses={400: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
    tags=["Prediction"],
)
async def predict(request: PredictRequest):
    """
    Analyze a URL for phishing probability.

    Process:
    1. Validate and normalize URL
    2. Extract 16 URL features
    3. Scale features using training scaler
    4. Run TensorFlow model inference
    5. Generate risk assessment and explanations
    """
    # Check model loaded
    if model is None or scaler is None or feature_columns is None:
        raise HTTPException(
            status_code=503,
            detail="Model artifacts not loaded. Please ensure the model is trained and artifacts exist.",
        )

    # 1. Validate and normalize URL
    url = validate_and_normalize_url(request.url)

    # 2. Extract features
    try:
        features = extract_url_features(url)
    except Exception as e:
        logger.error(f"Feature extraction error: {e}")
        raise HTTPException(status_code=400, detail="Unable to extract features from the provided URL.")

    # 3. Prepare feature vector in correct order
    try:
        feature_vector = np.array(
            [[features[col] for col in feature_columns]],
            dtype=np.float32,
        )
    except KeyError as e:
        logger.error(f"Missing feature: {e}")
        raise HTTPException(status_code=500, detail="Feature extraction mismatch.")

    # 4. Scale features
    try:
        feature_vector_scaled = scaler.transform(feature_vector)
    except Exception as e:
        logger.error(f"Scaling error: {e}")
        raise HTTPException(status_code=500, detail="Error during feature scaling.")

    # 5. Model prediction
    try:
        prediction = model.predict(feature_vector_scaled)
        phishing_prob = float(prediction[0][0])
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail="Error during model prediction.")

    # 6. Calculate results
    legitimate_prob = 1.0 - phishing_prob
    risk_level = classify_risk(phishing_prob)
    verdict = "Phishing" if phishing_prob >= 0.5 else "Legitimate"
    recommendation = generate_recommendation(phishing_prob, risk_level, features)
    explanations = generate_feature_explanations(features)

    logger.info(f"Prediction: {url} → {verdict} ({phishing_prob:.4f})")

    return {
        "url": url,
        "verdict": verdict,
        "phishing_probability": round(phishing_prob, 4),
        "legitimate_probability": round(legitimate_prob, 4),
        "risk_level": risk_level,
        "recommendation": recommendation,
        "features": {
            **features,
            "explanations": explanations,
        },
    }
