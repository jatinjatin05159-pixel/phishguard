"""
Phishing URL Detector using Random Forest
-----------------------------------------
This module extracts structural and lexical features from a given URL
and predicts its phishing risk score (0 to 100) using a trained
Random Forest machine learning model.
"""

import os
import re
import csv
from urllib.parse import urlparse
import joblib
from sklearn.ensemble import RandomForestClassifier

# Paths to data and saved model (located in the same directory as this script)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(BASE_DIR, "phishing_rf_model.joblib")
DATA_FILE = os.path.join(BASE_DIR, "url_data.csv")

# Set of unusual or frequently abused top-level domains (TLDs)
UNUSUAL_TLDS = {
    ".xyz", ".top", ".buzz", ".club", ".work", ".click",
    ".loan", ".icu", ".gq", ".cf", ".tk", ".ml", ".ga",
    ".fit", ".rest", ".live"
}

# Common keywords heavily found in phishing and credential harvesting links
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "kyc", "signin",
    "banking", "secure", "account", "confirm", "wallet",
    "alert", "recovery", "password", "security", "unauthorized"
]


def extract_features(link: str) -> list:
    """
    Extracts numerical and boolean features from a URL text.
    
    Features extracted:
    1. Total URL length
    2. Number of dots (.)
    3. Number of hyphens (-)
    4. Whether URL contains '@'
    5. Number of digits
    6. Whether URL uses HTTPS
    7. Whether its ending/TLD is unusual (e.g. .xyz, .top)
    8. Count of suspicious phishing keywords (e.g. login, kyc, verify)
    9. Whether the URL contains an IP address
    """
    link = str(link).strip()
    link_lower = link.lower()

    # 1. Total URL length
    url_length = len(link)

    # 2. Number of dots and hyphens
    num_dots = link.count(".")
    num_hyphens = link.count("-")

    # 3. Whether the URL contains '@'
    has_at_symbol = 1 if "@" in link else 0

    # 4. Number of digits
    num_digits = sum(c.isdigit() for c in link)

    # 5. Whether it uses HTTPS
    is_https = 1 if link_lower.startswith("https://") else 0

    # 6. Whether its ending is unusual, such as .xyz
    try:
        # urlparse requires a scheme to properly parse hostname
        parsed = urlparse(link if "://" in link else "http://" + link)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        hostname = ""

    has_unusual_ending = 1 if any(hostname.endswith(tld) for tld in UNUSUAL_TLDS) else 0

    # 7. Additional clues: Count of suspicious phishing keywords
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in link_lower)

    # 8. Additional clues: Whether an IP address is used instead of a domain name
    has_ip = 1 if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", link_lower) else 0

    return [
        url_length,
        num_dots,
        num_hyphens,
        has_at_symbol,
        num_digits,
        is_https,
        has_unusual_ending,
        keyword_count,
        has_ip,
    ]


def _train_and_save_model() -> RandomForestClassifier:
    """
    Trains a Random Forest classifier from url_data.csv and saves it to disk.
    """
    if not os.path.exists(DATA_FILE):
        raise FileNotFoundError(
            f"Training data file not found at: {DATA_FILE}. "
            "Please ensure url_data.csv is present in the project directory."
        )

    X, y = [], []
    with open(DATA_FILE, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)  # Skip CSV header
        for row in reader:
            if len(row) >= 2:
                url_text, label_val = row[0], int(row[1])
                X.append(extract_features(url_text))
                y.append(label_val)

    # Create and train Random Forest Classifier
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42
    )
    model.fit(X, y)

    # Save trained model to disk so subsequent runs load instantly
    joblib.dump(model, MODEL_FILE)
    return model


def _load_or_train_model() -> RandomForestClassifier:
    """
    Loads pre-trained model from disk if available; otherwise trains it once.
    """
    if os.path.exists(MODEL_FILE):
        try:
            return joblib.load(MODEL_FILE)
        except Exception:
            # If saved model is corrupted or incompatible, retrain once
            return _train_and_save_model()
    else:
        return _train_and_save_model()


# Load or train the model ONCE upon module loading.
# This ensures check_url() does not retrain the model on each call.
_model = _load_or_train_model()


def check_url(link: str) -> int:
    """
    Accepts a URL as text and returns an integer score from 0 to 100:
      - 0 means likely safe.
      - 100 means likely phishing.

    Does NOT retrain the model; uses the preloaded Random Forest model.
    """
    if not link or not isinstance(link, str) or not link.strip():
        return 0

    # Extract feature vector for the given link
    features = extract_features(link)

    # Predict probabilities for [class_0 (safe), class_1 (phishing)]
    probabilities = _model.predict_proba([features])[0]
    phishing_probability = probabilities[1]

    # Convert probability (0.0 to 1.0) into an integer score from 0 to 100
    score = int(round(phishing_probability * 100))

    # Clamp score within [0, 100]
    return max(0, min(100, score))


if __name__ == "__main__":
    print("=" * 60)
    print("       Phishing URL Detector - Random Forest Model       ")
    print("=" * 60)
    print("Scoring Scale: 0 = Likely Safe, 100 = Likely Phishing\n")

    # Example test URLs
    test_urls = [
        "http://sbi-kyc-update.xyz/login",  # should score high
        "https://www.google.com",           # should score low
        "https://www.hdfcbank.com",         # should score low
    ]

    for url in test_urls:
        score = check_url(url)
        risk = "HIGH RISK (Phishing)" if score >= 60 else "LOW RISK (Safe)"
        print(f"URL   : {url}")
        print(f"Score : {score}/100 [{risk}]")
        print("-" * 60)
