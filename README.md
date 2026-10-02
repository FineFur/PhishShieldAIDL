# PhishShield AI 🛡️

## Intelligent Phishing Website Detection Using Deep Learning

PhishShield AI detects phishing websites by analyzing **18 engineered URL features** using a pure-Numpy deep-learning model — no TensorFlow required. It comes with a **Chrome Extension** for real-time browser protection, a **FastAPI backend**, and a **React dashboard**.

> **Core Philosophy:** SCAN → DETECT → EXPLAIN → RECORD

---

## ⚡ Quick Start — Extension Only (Recommended for New Users)

> Just want to use the Chrome extension? You only need **Python** installed. No Node.js, no frontend setup needed.

### Step 1 — Clone the Repository

```bash
git clone https://github.com/FineFur/PhishShieldAIDL.git
cd PhishShieldAIDL
```

### Step 2 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Start the Backend

```bash
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000
```

✅ You should see:
```
INFO: Feature columns loaded: 18 features
INFO: All artifacts loaded successfully!
INFO: Uvicorn running on http://127.0.0.1:8000
```

> **Note:** The trained model weights (`model/numpy_mlp_weights.json`) and scaler (`model/scaler.pkl`) are already included in the repo — **no training needed**.

### Step 4 — Load the Chrome Extension

1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **"Load unpacked"**
4. Select the `extension/` folder from the cloned repo
5. The PhishShield 🛡️ icon will appear in your toolbar

### Step 5 — Browse & Protect

- Click the extension icon on any website to scan the current URL
- A **SAFE** (green) or **RISK** (red) badge appears on the icon automatically
- The popup shows phishing probability, risk level, and feature breakdown

---

## Features

- 🛡️ **Chrome Extension** — Real-time URL scanning on every page you visit
- 🔍 **URL Scanning** — Analyzes any URL for phishing indicators
- 🧠 **Deep Learning Model** — Pure-Numpy 2-layer MLP (no TensorFlow required)
- 🎯 **Zphisher Detection** — Catches modern phishing toolkits (ngrok, 000webhost, Google Sites, loca.lt)
- 📊 **Risk Assessment** — Low / Medium / High risk classification with probabilities
- 💡 **Explainable Results** — Feature-level explanations for each analysis
- 📋 **Scan History** — Persistent scan records in browser localStorage
- 🔒 **Security Tips** — Educational content about phishing awareness
- 🛡️ **Safe Analysis** — Static URL feature extraction only; **never visits target websites**

---

## Technology Stack

| Layer        | Technologies                                        |
| ------------ | --------------------------------------------------- |
| **Extension**| Chrome Extension (Manifest V3), JavaScript          |
| **Frontend** | React.js, Vite, JavaScript, Axios, CSS              |
| **Backend**  | Python, FastAPI, Uvicorn, Pydantic                  |
| **ML/DL**    | Pure NumPy MLP (no TensorFlow), Pandas              |
| **Storage**  | Browser localStorage                                |

---

## System Architecture

```
Browser visits a URL
        ↓
Chrome Extension (content.js detects page load)
        ↓
POST http://127.0.0.1:8000/predict
        ↓
FastAPI Backend
        ↓
URL Feature Extraction (18 features)
        ↓
StandardScaler preprocessing
        ↓
NumpyMLP (18 → 128 → 64 → 1)
        ↓
Phishing probability (sigmoid output)
        ↓
Risk level + Explanation
        ↓
Extension badge (SAFE/RISK) + Popup display
```

---

## Dataset & Features

The model uses **18 engineered URL features**:

| # | Feature | Description |
|---|---------|-------------|
| 1 | `url_length` | Total length of the URL string |
| 2 | `has_ip_address` | URL contains IP address (1/0) |
| 3 | `dot_count` | Number of dots in URL |
| 4 | `https_flag` | Uses HTTPS protocol (1/0) |
| 5 | `url_entropy` | Shannon entropy of URL string |
| 6 | `token_count` | Number of URL tokens |
| 7 | `subdomain_count` | Number of subdomains |
| 8 | `query_param_count` | Number of query parameters |
| 9 | `tld_length` | Length of top-level domain |
| 10 | `path_length` | Length of URL path |
| 11 | `has_hyphen_in_domain` | Domain contains hyphen (1/0) |
| 12 | `number_of_digits` | Count of digit characters |
| 13 | `tld_popularity` | TLD popularity score (1/0) |
| 14 | `suspicious_file_extension` | Suspicious file extension (1/0) |
| 15 | `domain_name_length` | Length of domain name |
| 16 | `percentage_numeric_chars` | Percentage of numeric characters |
| 17 | `uses_free_hosting` | ⭐ Detects ngrok, loca.lt, 000webhost, Google Sites, glitch.me, replit.app, etc. |
| 18 | `brand_in_path` | ⭐ Detects brand impersonation in path/subdomain (e.g. "facebook" on a 3rd-party domain) |

> ⭐ Features 17 & 18 were added specifically to detect **modern phishing toolkits** like [zphisher](https://github.com/htr-tech/zphisher) that bypass traditional URL analysis by using HTTPS on free hosting services.

### ClassLabel
- `0` = Phishing
- `1` = Legitimate

---

## Deep Learning Model

**Architecture:** Pure-Numpy Feed-Forward Neural Network (MLP)

```
Input(18) → Dense(128, ReLU) → Dense(64, ReLU) → Dense(1, Sigmoid)
```

| Property | Value |
|---|---|
| Implementation | Pure NumPy (no TensorFlow/PyTorch) |
| Initialization | He initialization |
| Loss | Binary Cross-Entropy |
| Optimizer | Gradient Descent |
| Epochs | 3000 |
| Learning Rate | 0.05 |
| Test Accuracy | 100% |
| Phishing Recall | 100% |

---

## Backend API

Base URL: `http://127.0.0.1:8000`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API status |
| GET | `/health` | Health check (model loaded) |
| GET | `/model-info` | Model metadata and metrics |
| POST | `/predict` | Analyze URL for phishing |

### POST /predict

**Request:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "url": "https://example.com",
  "verdict": "Legitimate",
  "phishing_probability": 0.02,
  "legitimate_probability": 0.98,
  "risk_level": "Low",
  "recommendation": "The URL appears relatively low risk...",
  "features": { "url_length": 23, "https_flag": 1, "uses_free_hosting": 0, ... }
}
```

Interactive API docs: `http://127.0.0.1:8000/docs`

---

## Full Installation (Backend + Frontend + Extension)

### Prerequisites
- Python 3.10+
- Node.js 18+ with npm
- Google Chrome

### Setup

```bash
# Clone
git clone https://github.com/FineFur/PhishShieldAIDL.git
cd PhishShieldAIDL

# Python dependencies
pip install -r requirements.txt

# Frontend dependencies
cd frontend && npm install && cd ..
```

### Running

```bash
# Terminal 1 — Backend
cd backend
uvicorn main:app --reload --host 127.0.0.1 --port 8000

# Terminal 2 — Frontend dashboard
cd frontend
npm run dev
```

Frontend dashboard: `http://localhost:5173`

---

## Retraining the Model (Optional)

Only needed if you want to retrain with fresh data.

```bash
# Step 1: Regenerate dataset
python dataset/generate_dataset.py

# Step 2: Retrain model
python model/train_numpy_mlp.py
```

> The repo already includes pre-trained weights (`model/numpy_mlp_weights.json`) and scaler (`model/scaler.pkl`) — retraining is **not required** to use the extension.

---

## Project Structure

```
PhishShieldAIDL/
├── backend/
│   ├── main.py                 # FastAPI application
│   ├── feature_extractor.py    # URL feature extraction (18 features)
│   ├── schemas.py              # Pydantic models
│   └── requirements.txt
├── dataset/
│   └── generate_dataset.py     # Dataset generator (includes zphisher URLs)
├── extension/                  # ← Chrome Extension (load this folder)
│   ├── manifest.json
│   ├── background.js           # Service worker + API calls
│   ├── content.js              # Auto-scan on page load
│   ├── popup.html              # Extension popup UI
│   ├── popup.js
│   └── content.css
├── frontend/
│   └── src/
│       ├── App.jsx
│       ├── components/
│       └── pages/
├── model/
│   ├── train_numpy_mlp.py      # Training script (NumpyMLP)
│   ├── preprocess.py           # Data preprocessing
│   ├── evaluate_model.py       # Evaluation
│   ├── numpy_mlp_weights.json  # ✅ Pre-trained model weights
│   ├── scaler.pkl              # ✅ Pre-fitted scaler
│   ├── feature_columns.pkl     # ✅ Feature column order
│   └── training_metrics.json   # Training results
├── README.md
├── .gitignore
└── requirements.txt
```

---

## Limitations

1. Analyzes URL-level features only — does not inspect page HTML or content
2. Does not perform DNS/WHOIS reputation checks
3. Does not use Google Safe Browsing or VirusTotal
4. Requires the backend to be running locally on port 8000
5. Model probability is an estimate, not proof of malicious intent

---

## Academic Disclaimer

This project is developed as an academic mini-project for MCA (LP III) coursework. The phishing detection model performs **static URL feature analysis** using a deep-learning classifier. It should not be used as the sole basis for determining website safety in production environments.

---

## License

Developed for educational purposes.

---

*PhishShield AI — Intelligent Phishing Website Detection Using Deep Learning*
