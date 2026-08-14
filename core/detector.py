"""
Detector module for CyberShield.
Loads trained models and provides a unified predict() interface.
"""

import os
import re
import pickle
import ipaddress
from cyber_shield.core.feature_extractor import (
    extract_url_features,
    extract_ip_features,
    extract_text_features,
)

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
LABELS = ["safe", "suspicious", "malicious"]

_CACHE: dict = {}


def _load(name: str):
    if name not in _CACHE:
        path = os.path.join(MODELS_DIR, f"{name}_model.pkl")
        with open(path, "rb") as f:
            _CACHE[name] = pickle.load(f)
    return _CACHE[name]


# ---------------------------------------------------------------------------
# Input type auto-detection
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(
    r"^(https?://|www\.)[^\s]{4,}", re.IGNORECASE
)
_IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$|"
    r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
)


def detect_input_type(raw: str) -> str:
    """Return 'url', 'ip', or 'text'."""
    raw = raw.strip()
    if _IP_PATTERN.match(raw):
        try:
            ipaddress.ip_address(raw)
            return "ip"
        except ValueError:
            pass
    if _URL_PATTERN.match(raw):
        return "url"
    # Bare hostname without scheme that has a suspicious TLD is still a URL
    if re.match(r"^[a-zA-Z0-9\-\.]+\.(tk|ml|ga|cf|gq|xyz|top|click|download|loan|win|bid)$", raw):
        return "url"
    return "text"


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def _explain_url(features: dict, label: str, proba: list) -> list:
    tips = []
    if features["has_ip_in_host"]:
        tips.append("URL uses a raw IP address instead of a domain name.")
    if not features["has_https"]:
        tips.append("Connection is unencrypted (HTTP, not HTTPS).")
    if features["suspicious_tld"]:
        tips.append("Domain uses a free/abused TLD commonly found in phishing.")
    if features["brand_in_subdomain"]:
        tips.append("A trusted brand name appears in a subdomain — possible impersonation.")
    if features["is_shortener"]:
        tips.append("URL shortener detected — the true destination is hidden.")
    if features["has_at_symbol"]:
        tips.append("'@' symbol in URL can be used to trick users about the real host.")
    if features["phishing_kw_count"] >= 2:
        tips.append(f"{features['phishing_kw_count']} phishing-related keywords found in the URL.")
    if features["host_entropy"] > 3.5:
        tips.append("Domain name has high character entropy — possible algorithmically generated domain.")
    if features["url_length"] > 100:
        tips.append("Unusually long URL — may be hiding the true destination.")
    if features["has_double_slash_redirect"]:
        tips.append("Double-slash redirect detected in path.")
    if not tips and label == "safe":
        tips.append("URL structure looks clean. Domain appears legitimate.")
    return tips


def _explain_ip(features: dict, label: str) -> list:
    tips = []
    if not features["valid_ip"]:
        tips.append("Input is not a valid IP address format.")
        return tips
    if features["in_known_bad_range"]:
        tips.append("IP falls within a documented reserved/test range (RFC 5737) — not routable on internet.")
    if features["is_loopback"]:
        tips.append("Loopback address — only accessible on the local machine.")
    if features["is_multicast"]:
        tips.append("Multicast address — used for group communication, not individual servers.")
    if features["is_private"]:
        tips.append("Private/internal IP address — not accessible from the public internet.")
    if label == "safe" and not tips:
        tips.append("IP appears to be a legitimate public address (e.g., DNS resolver or CDN).")
    return tips


def _explain_text(features: dict, label: str) -> list:
    tips = []
    if features["social_eng_hits"] >= 3:
        tips.append(f"Message contains {features['social_eng_hits']} social engineering patterns (urgency, threats, prizes).")
    elif features["social_eng_hits"] > 0:
        tips.append(f"Message contains {features['social_eng_hits']} social engineering phrase(s).")
    if features["url_count"] >= 2:
        tips.append(f"{features['url_count']} URLs embedded in the message.")
    elif features["url_count"] == 1:
        tips.append("Message contains an embedded URL — verify before clicking.")
    if features["exclamation_count"] >= 3:
        tips.append(f"{features['exclamation_count']} exclamation marks detected — common in scam messages.")
    if features["caps_ratio"] > 0.15:
        tips.append("High proportion of uppercase letters — often used to create urgency.")
    if features["has_ssn_pattern"]:
        tips.append("Possible Social Security Number pattern detected in message.")
    if features["has_phone_number"]:
        tips.append("Phone number detected — verify legitimacy before calling.")
    if not tips and label == "safe":
        tips.append("Message content appears normal with no threat indicators.")
    return tips


def predict(raw_input: str, input_type: str = "auto") -> dict:
    """
    Analyse input and return a detection result dict:
      {
        "input_type": str,
        "label": str,           # "safe" | "suspicious" | "malicious"
        "confidence": float,    # 0-100
        "probabilities": dict,  # per-class probabilities
        "explanations": list,   # human-readable reasons
        "features": dict,       # extracted feature values
      }
    """
    raw = raw_input.strip()
    if not raw:
        return {"error": "Empty input provided."}

    if input_type == "auto":
        input_type = detect_input_type(raw)

    try:
        if input_type == "url":
            model = _load("url")
            features = extract_url_features(raw)
        elif input_type == "ip":
            model = _load("ip")
            features = extract_ip_features(raw)
        else:
            model = _load("text")
            features = extract_text_features(raw)
    except FileNotFoundError:
        return {"error": "Models not found. Run: python -m cyber_shield.core.train_model"}

    feat_vector = [list(features.values())]
    pred_idx = int(model.predict(feat_vector)[0])
    probas = model.predict_proba(feat_vector)[0]
    label = LABELS[pred_idx]
    confidence = round(float(probas[pred_idx]) * 100, 1)

    proba_dict = {LABELS[i]: round(float(p) * 100, 1) for i, p in enumerate(probas)}

    if input_type == "url":
        explanations = _explain_url(features, label, probas)
    elif input_type == "ip":
        explanations = _explain_ip(features, label)
    else:
        explanations = _explain_text(features, label)

    return {
        "input_type": input_type,
        "label": label,
        "confidence": confidence,
        "probabilities": proba_dict,
        "explanations": explanations,
        "features": features,
    }
