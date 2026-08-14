"""
Model training script for CyberShield.
Generates synthetic labelled training data, trains Random Forest classifiers
for URL, IP, and text threat detection, then persists them to disk.

Run once:  python -m cyber_shield.core.train_model
"""

import os
import random
import math
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from cyber_shield.core.feature_extractor import (
    extract_url_features,
    extract_ip_features,
    extract_text_features,
)

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
LABELS = ["safe", "suspicious", "malicious"]

random.seed(42)
np.random.seed(42)


# ---------------------------------------------------------------------------
# Synthetic dataset generators
# ---------------------------------------------------------------------------

def _make_url_samples():
    safe_urls = [
        "https://www.google.com/search?q=weather",
        "https://github.com/openai/openai-python",
        "https://stackoverflow.com/questions/12345",
        "https://en.wikipedia.org/wiki/Python_(programming_language)",
        "https://www.bbc.com/news/world",
        "https://docs.python.org/3/library/os.html",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://mail.google.com/mail/u/0/",
        "https://www.reddit.com/r/programming/",
        "https://www.linkedin.com/in/someone",
        "https://microsoft.com/en-us/windows",
        "https://apple.com/iphone",
        "https://www.nytimes.com/2024/01/01/tech/ai.html",
        "https://www.cloudflare.com/learning/ddos/",
    ]

    suspicious_urls = [
        "http://bit.ly/3xFreeGift",
        "http://tinyurl.com/verify-account",
        "http://192.168.1.105/admin/login",
        "http://paypal-secure-login.xyz/confirm",
        "http://amazon-prize-winner.top/claim",
        "https://secure-bankofamerica.ml/signin",
        "http://login-verify.click/account/reset",
        "http://update-your-account.xyz/login",
        "http://free-iphone-giveaway.win/enter",
        "https://www.g00gle.com/search",
        "http://microsoft-support-alert.xyz",
        "http://download.free-antivirus.top/setup.exe",
    ]

    malicious_urls = [
        "http://paypal.account-verify.tk/signin?user=victim",
        "http://secure-login.amazon.cf/update-payment",
        "http://192.0.2.45/phish/steal_creds.php?redirect=1",
        "http://appleid.apple.support-locked.ga/unlock",
        "http://www.irs-tax-refund.gq/claim?ssn=123456789",
        "http://faceb00k-login.ml/credential-harvest",
        "http://bit.ly/3AbCdEf-banklogin",
        "http://chase-online.secure-verify.top/banking/signin",
        "http://netflix-account%2Fsuspended.cyou/login",
        "http://update-password-alert.monster/reset@victim.com",
        "http://fedex-delivery-failed.cfd/pay?parcel=XYZ",
        "http://dhl-package-held.icu/customs-fee",
    ]

    samples, labels = [], []
    for url in safe_urls:
        f = extract_url_features(url)
        samples.append(list(f.values()))
        labels.append(0)

    for url in suspicious_urls:
        f = extract_url_features(url)
        samples.append(list(f.values()))
        labels.append(1)

    for url in malicious_urls:
        f = extract_url_features(url)
        samples.append(list(f.values()))
        labels.append(2)

    # Augment with noise
    augmented_s, augmented_l = [], []
    for feat, label in zip(samples, labels):
        for _ in range(18):
            noisy = [v + random.gauss(0, 0.05 * (abs(v) + 0.1)) if isinstance(v, float)
                     else max(0, v + random.randint(-1, 1)) for v in feat]
            augmented_s.append(noisy)
            augmented_l.append(label)

    return samples + augmented_s, labels + augmented_l


def _make_ip_samples():
    safe_ips = [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "208.67.222.222", "9.9.9.9", "149.112.112.112",
        "2606:4700:4700::1111",
    ]
    suspicious_ips = [
        "192.168.0.1", "10.0.0.1", "172.16.0.1",
        "100.64.0.1", "169.254.0.1",
    ]
    malicious_ips = [
        "192.0.2.1", "198.51.100.1", "203.0.113.1",
        "192.0.2.200", "198.51.100.99", "203.0.113.50",
    ]

    samples, labels = [], []
    for ip in safe_ips:
        f = extract_ip_features(ip)
        samples.append(list(f.values()))
        labels.append(0)
    for ip in suspicious_ips:
        f = extract_ip_features(ip)
        samples.append(list(f.values()))
        labels.append(1)
    for ip in malicious_ips:
        f = extract_ip_features(ip)
        samples.append(list(f.values()))
        labels.append(2)

    # Augment
    augmented_s, augmented_l = [], []
    for feat, label in zip(samples, labels):
        for _ in range(25):
            noisy = [max(0.0, v + random.gauss(0, 0.05)) if isinstance(v, float)
                     else v for v in feat]
            augmented_s.append(noisy)
            augmented_l.append(label)

    return samples + augmented_s, labels + augmented_l


def _make_text_samples():
    safe_texts = [
        "Please find the meeting notes attached for your review.",
        "The quarterly report has been updated on the shared drive.",
        "Hi team, the sprint planning is scheduled for Monday at 10 AM.",
        "Your order #12345 has shipped and will arrive by Thursday.",
        "Thank you for subscribing to our newsletter.",
        "Let me know if you need any help with the documentation.",
        "The server maintenance window is this Sunday from 2-4 AM UTC.",
        "Reminder: submit your timesheets by end of Friday.",
        "Your password was successfully changed.",
        "We have received your support ticket and will respond within 24 hours.",
    ]

    suspicious_texts = [
        "Click here to verify your account immediately.",
        "Your account has been suspended. Update your payment info.",
        "Unusual sign-in activity detected. Confirm your identity.",
        "Limited time offer: act now to claim your free gift!",
        "You have been selected for a special prize. Respond ASAP.",
        "Invoice attached. Please review and approve urgent payment.",
        "Reset your password — it expires in 24 hours.",
        "We detected suspicious activity. Verify your account here.",
    ]

    malicious_texts = [
        "URGENT: Your PayPal account has been SUSPENDED! Click http://paypal-verify.tk/login to restore access NOW!!!",
        "Congratulations! You have WON an iPhone 15. Click the link to claim: http://bit.ly/FreePhone",
        "Your IRS tax refund of $4,521 is pending. Provide your SSN 123-45-6789 to claim. Act NOW!",
        "Wire transfer of $10,000 required urgently. Open the attachment to confirm. Password: 1234",
        "Your Netflix account is LOCKED. Confirm your credit card at http://netflix-billing.monster/update",
        "Dear customer, unusual sign-in from Russia. Verify your credentials: http://amazon.security-alert.cfd",
        "FREE BITCOIN WALLET — You have been selected! Confirm your crypto wallet address NOW to receive $500.",
        "FINAL WARNING: Your computer is infected with 5 viruses! Call 1-800-555-0199 immediately!",
    ]

    samples, labels = [], []
    for text in safe_texts:
        f = extract_text_features(text)
        samples.append(list(f.values()))
        labels.append(0)
    for text in suspicious_texts:
        f = extract_text_features(text)
        samples.append(list(f.values()))
        labels.append(1)
    for text in malicious_texts:
        f = extract_text_features(text)
        samples.append(list(f.values()))
        labels.append(2)

    augmented_s, augmented_l = [], []
    for feat, label in zip(samples, labels):
        for _ in range(20):
            noisy = [max(0.0, v + random.gauss(0, 0.05 * (abs(v) + 0.1))) if isinstance(v, float)
                     else max(0, v + random.randint(-1, 1)) for v in feat]
            augmented_s.append(noisy)
            augmented_l.append(label)

    return samples + augmented_s, labels + augmented_l


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def _train_and_save(name: str, X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=3,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"\n{'='*50}")
    print(f"Model: {name}")
    print(classification_report(y_test, y_pred, target_names=LABELS, zero_division=0))

    path = os.path.join(MODELS_DIR, f"{name}_model.pkl")
    with open(path, "wb") as f:
        pickle.dump(model, f)
    print(f"Saved -> {path}")
    return model


def train_all():
    os.makedirs(MODELS_DIR, exist_ok=True)

    print("Generating URL training data...")
    X_url, y_url = _make_url_samples()
    _train_and_save("url", X_url, y_url)

    print("Generating IP training data...")
    X_ip, y_ip = _make_ip_samples()
    _train_and_save("ip", X_ip, y_ip)

    print("Generating text training data...")
    X_text, y_text = _make_text_samples()
    _train_and_save("text", X_text, y_text)

    print("\n[OK] All models trained and saved successfully.")


if __name__ == "__main__":
    train_all()
