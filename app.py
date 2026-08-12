"""
CyberShield — Flask web application
Run:  python app.py
"""

import os
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from .core.detector import predict

app: Flask = Flask(
    import_name=__name__,
    template_folder="templates",
    static_folder="static",
)
app.secret_key = os.urandom(24)

# In-memory scan history (last 50 entries)
_history: list = []
MAX_HISTORY = 50


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True, silent=True) or {}
    raw_input = (data.get("input") or "").strip()
    input_type = (data.get("type") or "auto").strip().lower()

    if not raw_input:
        return jsonify({"error": "No input provided."}), 400

    if input_type not in ("auto", "url", "ip", "text"):
        input_type = "auto"

    result = predict(raw_input, input_type)

    if "error" not in result:
        entry = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "input": raw_input[:80] + ("…" if len(raw_input) > 80 else ""),
            "type": result["input_type"],
            "label": result["label"],
            "confidence": result["confidence"],
        }
        _history.insert(0, entry)
        if len(_history) > MAX_HISTORY:
            _history.pop()

    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def history():
    return jsonify(_history[:20])


@app.route("/api/examples", methods=["GET"])
def examples():
    return jsonify([
        {"label": "Safe URL",        "value": "https://www.google.com/search?q=python", "type": "url"},
        {"label": "Phishing URL",    "value": "http://paypal-account-verify.tk/signin?user=test", "type": "url"},
        {"label": "Shortener URL",   "value": "http://bit.ly/3xFreeGift",  "type": "url"},
        {"label": "Public IP",       "value": "8.8.8.8",                   "type": "ip"},
        {"label": "Private IP",      "value": "192.168.1.1",               "type": "ip"},
        {"label": "Reserved IP",     "value": "192.0.2.1",                 "type": "ip"},
        {"label": "Safe email",      "value": "Please find the meeting notes attached for Monday's review.", "type": "text"},
        {"label": "Phishing email",  "value": "URGENT: Your account has been SUSPENDED! Click here to verify now!!!", "type": "text"},
        {"label": "Scam message",    "value": "Congratulations! You won a FREE iPhone. Confirm your wallet address to receive $500 in Bitcoin NOW!", "type": "text"},
    ])


if __name__ == "__main__":
    # Auto-train models if not present
    import glob as _glob
    model_files = _glob.glob(os.path.join("cyber_shield", "models", "*.pkl"))
    if len(model_files) < 3:
        print("Models not found — training now (one-time setup)...")
        from cyber_shield.core.train_model import train_all
        train_all()

    print("\n" + "="*55)
    print("  [SHIELD]  CyberShield -- AI Cybersecurity Threat Detector")
    print("="*55)
    print("  Running at:  http://127.0.0.1:5000")
    print("="*55 + "\n")
    app.run(debug=False, host="127.0.0.1", port=5000)
