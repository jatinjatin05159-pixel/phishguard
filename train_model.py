"""
================================================================================
Cybersecurity & Digital Safety Hackathon
Person 1: SMS Spam Detection Model
Training Script: train_model.py (Enhanced with Indian Scam Patterns)

Description:
    Trains the SMS Spam Detection Model using:
        1. Official UCI SMS Spam Collection dataset (~5,572 records)
        2. Specialized Indian-style Scam & Cyber Fraud dataset (80+ records)
    Builds a unified Scikit-learn Pipeline:
        - TF-IDF Vectorizer (ngram_range=(1, 2), stop_words='english')
        - Logistic Regression (class_weight='balanced', solver='liblinear')
    Saves the final fitted pipeline to 'sms_spam_model.pkl' via Joblib.
================================================================================
"""

import os
import sys
import urllib.request
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# Directory Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_OUTPUT_PATH = os.path.join(BASE_DIR, "sms_spam_model.pkl")
LOCAL_DATA_FILE = os.path.join(BASE_DIR, "sms_spam_collection.tsv")
INDIAN_DATA_FILE = os.path.join(BASE_DIR, "indian_scam_dataset.tsv")
SCAM_TYPES_FILE = os.path.join(BASE_DIR, "scam_types_dataset.tsv")

DATA_URLS = [
    "https://raw.githubusercontent.com/justmarkham/DAT8/master/data/sms.tsv",
    "https://raw.githubusercontent.com/stedy/Machine-Learning-with-R-datasets/master/sms_spam.csv"
]


def load_dataset():
    """
    Loads both UCI SMS Spam Collection and Indian-style scam additions.
    Merges them into a comprehensive training DataFrame.
    """
    dfs = []

    # 1. Load or download standard UCI SMS Spam Collection
    uci_loaded = False
    if os.path.exists(LOCAL_DATA_FILE):
        print(f"[*] Found local UCI dataset at: {LOCAL_DATA_FILE}")
        uci_df = pd.read_csv(LOCAL_DATA_FILE, sep="\t", names=["label", "message"], header=None, encoding="utf-8")
        dfs.append(uci_df)
        uci_loaded = True
    else:
        for url in DATA_URLS:
            try:
                print(f"[*] Downloading UCI SMS Spam Collection from:\n    {url} ...")
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as response:
                    content = response.read().decode("utf-8", errors="ignore")

                with open(LOCAL_DATA_FILE, "w", encoding="utf-8") as f:
                    f.write(content)

                sep = "\t" if "sms.tsv" in url or "\t" in content[:200] else ","
                if sep == "\t":
                    uci_df = pd.read_csv(LOCAL_DATA_FILE, sep="\t", names=["label", "message"], header=None, encoding="utf-8")
                else:
                    uci_df = pd.read_csv(LOCAL_DATA_FILE, encoding="utf-8")
                    uci_df.columns = [c.lower() for c in uci_df.columns]
                    if "type" in uci_df.columns and "text" in uci_df.columns:
                        uci_df = uci_df.rename(columns={"type": "label", "text": "message"})

                dfs.append(uci_df)
                uci_loaded = True
                print(f"[+] UCI Dataset loaded ({len(uci_df)} samples).")
                break
            except Exception as e:
                print(f"[-] Could not fetch from {url}: {e}")

    # Fallback seed if UCI download failed
    if not uci_loaded:
        print("[!] Using fallback seed dataset...")
        seed_data = [
            ("spam", "URGENT your account will be blocked, click here to verify immediately!"),
            ("spam", "Congratulations! You won a 1000 Walmart gift card. Click here now to claim."),
            ("spam", "FreeMsg: Claim your free 500 cash bonus by texting WIN to 88088."),
            ("spam", "Your bank account has been compromised. Log in now to unlock."),
            ("ham", "are we meeting at 5?"),
            ("ham", "Hey, what are you doing tonight? Let's grab dinner."),
            ("ham", "I will be home by 7 pm, see you soon.")
        ]
        dfs.append(pd.DataFrame(seed_data * 50, columns=["label", "message"]))

    # 2. Load Indian-style scam dataset if available
    if os.path.exists(INDIAN_DATA_FILE):
        print(f"[*] Loading Indian-style scam dataset from: {INDIAN_DATA_FILE}")
        try:
            indian_df = pd.read_csv(INDIAN_DATA_FILE, sep="\t", encoding="utf-8")
            print(f"[+] Loaded {len(indian_df)} Indian-style scam & ham samples.")
            # Give slightly higher weight to domain-specific Indian threats during training
            dfs.append(indian_df)
            dfs.append(indian_df[indian_df['label'] == 'spam']) # Boost Indian scam representation
        except Exception as e:
            print(f"[-] Could not load Indian dataset: {e}")

    # 3. Digital-arrest, malicious-app (APK / remote access) and other scam examples,
    #    plus hard 'safe' messages (real bank alerts, official links, scam-awareness warnings)
    if os.path.exists(SCAM_TYPES_FILE):
        try:
            types_df = pd.read_csv(SCAM_TYPES_FILE, sep="\t", encoding="utf-8")
            print(f"[+] Loaded {len(types_df)} digital-arrest / malicious-app / hard-safe samples.")
            dfs.append(types_df)
            dfs.append(types_df[types_df['label'] == 'spam'])   # boost these new scam types
        except Exception as e:
            print(f"[-] Could not load scam-types dataset: {e}")

    # Merge all data sources
    combined_df = pd.concat(dfs, ignore_index=True)
    return combined_df


def train():
    print("=" * 70)
    print(" TRAINING SMS SPAM MODEL (UCI + INDIAN CYBERSECURITY SCAMS)")
    print("=" * 70)

    # 1. Preprocess & Clean
    df = load_dataset()
    df = df.dropna(subset=["label", "message"])
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df["message"] = df["message"].astype(str).str.strip()
    df = df[df["label"].isin(["ham", "spam"])].copy()

    total_records = len(df)
    ham_count = (df['label'] == 'ham').sum()
    spam_count = (df['label'] == 'spam').sum()

    print(f"\n[*] Combined Dataset Summary:")
    print(f"    Total samples : {total_records}")
    print(f"    Ham (Safe)    : {ham_count} ({ham_count/total_records*100:.1f}%)")
    print(f"    Spam          : {spam_count} ({spam_count/total_records*100:.1f}%)")

    # 2. Train / Test Split
    X = df["message"]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 3. Scikit-learn Pipeline (TF-IDF + Logistic Regression)
    # Using lowercase=True, ngram_range=(1, 2) to capture phrases like 'bijli bill' and 'account blocked'
    print("\n[*] Constructing Pipeline: TfidfVectorizer -> LogisticRegression ...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            stop_words='english',
            lowercase=True,
            ngram_range=(1, 2),
            max_df=0.95,
            min_df=2
        )),
        ('classifier', LogisticRegression(
            C=5.0,
            solver='liblinear',
            random_state=42,
            class_weight='balanced'
        ))
    ])

    # 4. Train
    print("[*] Training pipeline on dataset...")
    pipeline.fit(X_train, y_train)

    # 5. Evaluate
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[+] Test Set Accuracy: {acc * 100:.2f}%\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["ham", "spam"]))

    # 6. Save Pipeline
    print(f"[*] Exporting trained model to:\n    {MODEL_OUTPUT_PATH}")
    joblib.dump(pipeline, MODEL_OUTPUT_PATH)
    print("[+] Model saved successfully as 'sms_spam_model.pkl'!")

    # 7. Verification Test Suite (Hackathon + Indian Scams)
    print("\n" + "=" * 70)
    print(" EVALUATION TEST SUITE (HACKATHON & INDIAN SCAM BENCHMARKS)")
    print("=" * 70)
    classes = list(pipeline.classes_)
    spam_idx = classes.index("spam")

    eval_messages = [
        # Standard Hackathon tests
        ("Standard Hackathon 1", "URGENT your account will be blocked, click here"),
        ("Standard Hackathon 2", "are we meeting at 5?"),
        # Indian-style Scam additions
        ("Indian Banking KYC",   "Your SBI account will be blocked today. Complete KYC now: link"),
        ("Indian Parcel / Fee",  "Pay Rs 49 customs fee for your parcel: link"),
        ("Indian Electricity",   "Your electricity bill is pending, power will be cut tonight. Pay now"),
        ("Hinglish Bijli Scam",  "Aapka bijli bill pending hai, abhi pay karein"),
        ("Indian FASTag Scam",   "Your FASTag is blocked, recharge now"),
        ("Normal Hinglish Ham",  "bhai kab tak pahunchega?"),
        ("Normal Work Ham",      "did you finish the PPT for the presentation?")
    ]

    for category, msg in eval_messages:
        prob = pipeline.predict_proba([msg])[0][spam_idx]
        score = int(round(prob * 100))
        status = "SPAM / FRAUD" if score >= 50 else "SAFE / HAM"
        print(f"[{category}]")
        print(f"  SMS   : \"{msg}\"")
        print(f"  Score : {score}/100 -> {status}\n")

    print("=" * 70)
    print("Training finished successfully!")


if __name__ == "__main__":
    train()
