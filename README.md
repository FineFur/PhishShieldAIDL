# PhishShield AI

## Intelligent Phishing Website Detection Using Deep Learning

PhishShield AI is a full-stack machine learning application that detects phishing websites by analyzing URL characteristics using a deep-learning model. The system extracts 16 engineered features from a URL string and classifies it as **Phishing** or **Legitimate** with a confidence probability.

> **Core Philosophy:** SCAN → DETECT → EXPLAIN → RECORD

---

## Features

- 🔍 **URL Scanning** — Analyze any URL for phishing indicators
- 🧠 **Deep Learning Model** — Feed-forward neural network (MLP) trained on URL features
- 📊 **Risk Assessment** — Low / Medium / High risk classification with probabilities
- 💡 **Explainable Results** — Feature-level explanations for each analysis
- 📋 **Scan History** — Persistent scan records stored in browser localStorage
- 🔒 **Security Tips** — Educational content about phishing awareness
- 🌙 **Dark/Light Mode** — Theme preference persisted across sessions
- 📱 **Responsive Design** — Works on desktop, tablet, and mobile
- 🛡️ **Safe Analysis** — Static URL feature extraction only; never visits target websites

---

## Technology Stack

| Layer        | Technologies                            |
| ------------ | --------------------------------------- |
| **Frontend** | React.js, Vite, JavaScript, Axios, CSS  |
| **Backend**  | Python, FastAPI, Uvicorn, Pydantic      |
| **ML/DL**    | TensorFlow, Keras, Scikit-learn, Pandas |
| **Data**     | CSV dataset with engineered features    |
| **Storage**  | Browser localStorage                    |

---

## System Architecture

```
User enters a URL
        ↓
React frontend (Vite)
        ↓
FastAPI backend (POST /predict)
        ↓
URL feature extraction (16 features)
        ↓
StandardScaler preprocessing
        ↓
TensorFlow/Keras MLP model
        ↓
Phishing probability (sigmoid output)
        ↓
Risk assessment + explanation
        ↓
Stored in localStorage
        ↓
Displayed in React dashboard
```

---

## Dataset

The project uses a CSV dataset (`dataset/url_features_extracted1.csv`) with URL-based engineered features.

### Feature Engineering

| # | Feature                  | Description                          |
|---|--------------------------|--------------------------------------|
| 1 | `url_length`             | Total length of the URL string       |
| 2 | `has_ip_address`         | URL contains IP address (1/0)        |
| 3 | `dot_count`              | Number of dots in URL                |
| 4 | `https_flag`             | Uses HTTPS protocol (1/0)            |
| 5 | `url_entropy`            | Shannon entropy of URL string        |
| 6 | `token_count`            | Number of URL tokens                 |
| 7 | `subdomain_count`        | Number of subdomains                 |
| 8 | `query_param_count`      | Number of query parameters           |
| 9 | `tld_length`             | Length of top-level domain           |
| 10| `path_length`            | Length of URL path                   |
| 11| `has_hyphen_in_domain`   | Domain contains hyphen (1/0)         |
| 12| `number_of_digits`       | Count of digit characters            |
| 13| `tld_popularity`         | TLD popularity score (1/0)           |
| 14| `suspicious_file_extension` | Suspicious file extension (1/0)   |
| 15| `domain_name_length`     | Length of domain name                |
| 16| `percentage_numeric_chars` | Percentage of numeric characters   |

### ClassLabel

- `0` = Phishing
- `1` = Legitimate

The target is converted internally: `y_phishing = 1` if `ClassLabel == 0`, so the sigmoid output directly represents **phishing probability**.

---

## Preprocessing

1. Load CSV dataset
2. Remove missing labels and duplicates
3. Handle invalid `subdomain_count` values (`-1` → NaN → median from training data)
4. 80/20 stratified train/test split (`random_state=42`)
5. StandardScaler fit on **training data only** (no data leakage)
6. Save `scaler.pkl` and `feature_columns.pkl`

---

## Deep Learning Model

**Architecture:** Feed-Forward Neural Network (MLP)

```
Input(16) → Dense(128, ReLU) → BatchNorm → Dropout(0.30)
          → Dense(64, ReLU)  → Dropout(0.20)
          → Dense(32, ReLU)
          → Dense(1, Sigmoid)
```

**Training Configuration:**
- Optimizer: Adam
- Loss: Binary Crossentropy
- Metrics: Accuracy, Precision, Recall, AUC
- Batch Size: 256
- Max Epochs: 30
- Callbacks: EarlyStopping, ReduceLROnPlateau

**Evaluation Metrics** are saved to `model/training_metrics.json` and include accuracy, precision, recall, F1-score, ROC-AUC, and confusion matrix — all computed from the actual trained model.

---

## Backend API

| Method | Endpoint      | Description                     |
|--------|---------------|---------------------------------|
| GET    | `/`           | API status                      |
| GET    | `/health`     | Health check (model loaded)     |
| GET    | `/model-info` | Model metadata and metrics      |
| POST   | `/predict`    | Analyze URL for phishing        |

### POST /predict

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "verdict": "Legitimate",
  "phishing_probability": 0.08,
  "legitimate_probability": 0.92,
  "risk_level": "Low",
  "recommendation": "The URL appears relatively low risk...",
  "features": { ... }
}
```

Interactive API docs available at: `http://127.0.0.1:8000/docs`

---

## Installation

### Prerequisites

- Python 3.10+ with pip
- Node.js 18+ with npm
- Git

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd PhishShieldAIDL

# Install Python dependencies
pip install -r requirements.txt

# Install frontend dependencies
cd frontend
npm install
cd ..
```

---

## Running the Project

### Step 1: Generate Dataset (if not present)

```bash
python dataset/generate_dataset.py
```

### Step 2: Train the Model

```bash
python model/train_model.py
```

### Step 3: Evaluate the Model

```bash
python model/evaluate_model.py
```

### Step 4: Start the Backend

```bash
cd backend
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### Step 5: Start the Frontend

```bash
cd frontend
npm run dev
```

The application will be available at `http://localhost:5173`

---

## Testing

### Test URLs

| URL | Type |
|-----|------|
| `https://www.google.com` | Testing example |
| `https://www.github.com` | Testing example |
| `http://192.168.1.10/login.php` | Testing example |
| `https://secure-login-example.com/account/verify` | Testing example |

> **Note:** These are testing examples only. Do not assume their real-world security status based solely on this application.

---

## Limitations

1. The model only analyzes URL-level features
2. It does not inspect webpage HTML or content
3. It does not execute JavaScript
4. It does not perform DNS reputation checks
5. It does not guarantee website safety
6. Newly emerging attack patterns may not be represented in the training dataset
7. Dataset distribution can affect model performance
8. Model probability is an estimate, not proof of malicious intent

---

## Future Scope

1. HTML-based phishing detection
2. Screenshot-based webpage analysis
3. QR-code URL scanning
4. Browser extension
5. Real-time threat intelligence integration
6. WHOIS/DNS features
7. Ensemble models
8. Transformer-based URL models
9. Explainable AI (SHAP, LIME)
10. Cloud deployment
11. Continuous model retraining

---

## Project Structure

```
PhishShieldAIDL/
├── backend/
│   ├── main.py                    # FastAPI application
│   ├── feature_extractor.py       # URL feature extraction
│   ├── schemas.py                 # Pydantic models
│   ├── requirements.txt           # Backend dependencies
│   └── utils/                     # Utility modules
├── dataset/
│   ├── url_features_extracted1.csv # Training dataset
│   └── generate_dataset.py        # Dataset generator (fallback)
├── model/
│   ├── train_model.py             # Model training script
│   ├── preprocess.py              # Data preprocessing
│   ├── evaluate_model.py          # Model evaluation
│   ├── phishshield_model.keras    # Trained model
│   ├── scaler.pkl                 # Feature scaler
│   ├── feature_columns.pkl        # Feature column order
│   └── training_metrics.json      # Evaluation metrics
├── frontend/
│   ├── package.json
│   ├── index.html
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── App.css
│       ├── components/
│       │   ├── Sidebar.jsx
│       │   ├── TopBar.jsx
│       │   ├── StatCard.jsx
│       │   ├── UrlScanner.jsx
│       │   ├── ScanResult.jsx
│       │   ├── FeatureCard.jsx
│       │   ├── RecentScans.jsx
│       │   └── EmptyState.jsx
│       └── pages/
│           ├── Dashboard.jsx
│           ├── ScanHistory.jsx
│           ├── SecurityTips.jsx
│           └── Settings.jsx
├── README.md
├── .gitignore
└── requirements.txt
```

---

## Academic Disclaimer

This project is developed as an academic mini-project for MCA coursework. The phishing detection model performs **static URL feature analysis** using a deep-learning classifier. It does not:

- Crawl or visit target websites
- Perform browser sandboxing
- Use WHOIS intelligence or DNS reputation
- Access Google Safe Browsing or VirusTotal
- Provide live threat intelligence

The system analyzes URL string characteristics and provides a probability-based assessment. It should not be used as the sole basis for determining website safety in production environments.

---

## License

This project is developed for educational purposes.

---

*PhishShield AI — Intelligent Phishing Website Detection Using Deep Learning*
