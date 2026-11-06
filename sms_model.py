"""
================================================================================
Cybersecurity & Digital Safety Hackathon
Person 1: SMS Spam Detection Model
Module: sms_model.py

Description:
    Production inference module for SMS spam detection.
    Loads a pre-trained Scikit-learn Pipeline (TF-IDF Vectorizer + Logistic Regression)
    once upon import and exposes the standard `check_sms(text)` function.
================================================================================
"""

import os
import sys
import joblib

# Determine the absolute path to the directory containing this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE_NAME = "sms_spam_model.pkl"
MODEL_PATH = os.path.join(BASE_DIR, MODEL_FILE_NAME)

# ------------------------------------------------------------------------------
# 1. MODEL LOADING (Loaded ONCE at module import)
# ------------------------------------------------------------------------------
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"\n[ERROR] Model file not found at: '{MODEL_PATH}'\n"
        f"Please run 'python train_model.py' to train and generate '{MODEL_FILE_NAME}' first,\n"
        f"or ensure the .pkl file is placed in the same directory as 'sms_model.py'."
    )

try:
    _model = joblib.load(MODEL_PATH)
except Exception as e:
    raise RuntimeError(f"[ERROR] Failed to load model file '{MODEL_PATH}': {e}")

# ------------------------------------------------------------------------------
# 2. DYNAMIC SPAM CLASS INDEX IDENTIFICATION
# ------------------------------------------------------------------------------
# Identify the spam class index dynamically from classes_ rather than assuming 0 or 1
if hasattr(_model, "classes_"):
    _classes = list(_model.classes_)
elif hasattr(_model, "named_steps") and "classifier" in _model.named_steps:
    _classes = list(_model.named_steps["classifier"].classes_)
else:
    _classes = ["ham", "spam"]

# Match 'spam' label (case-insensitive) or fallback to positive binary class (1)
_spam_index = None
for idx, label in enumerate(_classes):
    if str(label).strip().lower() == "spam":
        _spam_index = idx
        break

if _spam_index is None:
    if 1 in _classes:
        _spam_index = _classes.index(1)
    else:
        # Default to the second class if binary classification
        _spam_index = 1 if len(_classes) > 1 else 0


# ------------------------------------------------------------------------------
# 3. CORE PREDICTION FUNCTION
# ------------------------------------------------------------------------------
def check_sms(text):
    """
    Evaluates an SMS text message and predicts its spam probability.

    Parameters:
        text (str): The raw SMS message content.

    Returns:
        int: An integer score from 0 to 100.
             - 0   : Completely safe (ham)
             - 100 : Extremely high spam probability
    """
    # Defensive input handling for None, empty strings, non-string types, or whitespace
    if text is None or not isinstance(text, str) or not text.strip():
        return 0

    # Model was pre-loaded into memory at import time; no retraining occurs
    probabilities = _model.predict_proba([text])[0]
    
    # Calculate spam probability scaled to 0-100
    spam_probability = probabilities[_spam_index]
    spam_score = int(round(spam_probability * 100))

    # Clamp the value strictly within [0, 100]
    return max(0, min(100, spam_score))


# ------------------------------------------------------------------------------
# 4. VERIFICATION / SELF-TEST
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print(" CYBERSECURITY & DIGITAL SAFETY - SMS SPAM DETECTION MODEL TEST")
    print("=" * 70)
    print(f"Loaded Model : {MODEL_PATH}")
    print(f"Detected Classes: {_classes} | Spam Class Index: {_spam_index}\n")

    # Mandatory test cases from Hackathon specifications
    test_cases = [
        ("Test 1", "URGENT your account will be blocked, click here"),
        ("Test 2", "are we meeting at 5?")
    ]

    for label, message in test_cases:
        score = check_sms(message)
        status = "SPAM / PHISHING" if score >= 50 else "SAFE / HAM"
        print(f"[{label}]")
        print(f"  SMS Message : \"{message}\"")
        print(f"  Spam Score  : {score}/100 -> {status}\n")

    print("=" * 70)
