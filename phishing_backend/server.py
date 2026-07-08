from flask import Flask, request, jsonify
from flask_cors import CORS
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)


def extract_url_features(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        features = {
            "having_ip": 1
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain)
            else 0,
            "long_url": 1 if len(url) > 54 else 0,
            "short_url": 1 if len(url) < 30 else 0,
            "symbol_at": 1 if "@" in url else 0,
            "redirecting": 1 if url.count("//") > 2 else 0,
            "prefix_suffix": 1 if "-" in domain else 0,
            "sub_domain": 1 if domain.count(".") >= 3 else 0,
            "https": 1 if "https" in url else 0,
            "domain_age": 1 if is_suspicious_tld(domain) else 0,
            "port": 1 if ":" in domain else 0,
        }
        return features
    except:
        return None


def is_suspicious_tld(domain):
    suspicious_tlds = [
        "tk",
        "ml",
        "ga",
        "cf",
        "xyz",
        "top",
        "men",
        "download",
        "stream",
    ]
    tld = domain.split(".")[-1].lower()
    return tld in suspicious_tlds


def predict_phishing(features):
    if not features:
        return {
            "isPhishing": False,
            "confidence": 0,
            "riskLevel": "UNKNOWN",
            "indicators": [],
        }

    score = 0
    indicators = []

    if features["having_ip"]:
        score += 0.25
        indicators.append("❌ IP address")
    if features["symbol_at"]:
        score += 0.20
        indicators.append("❌ @ symbol")
    if features["redirecting"]:
        score += 0.15
        indicators.append("⚠️ Redirects")
    if features["prefix_suffix"]:
        score += 0.12
        indicators.append("⚠️ Hyphens")
    if features["sub_domain"]:
        score += 0.12
        indicators.append("⚠️ Subdomains")
    if features["domain_age"]:
        score += 0.15
        indicators.append("⚠️ Suspicious TLD")
    if features["long_url"]:
        score += 0.08
        indicators.append("⚠️ Long URL")
    if not features["https"]:
        score += 0.08
        indicators.append("⚠️ No HTTPS")

    score = min(score, 1.0)

    if score >= 0.65:
        risk = "CRITICAL"
    elif score >= 0.45:
        risk = "HIGH"
    elif score >= 0.25:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "isPhishing": score >= 0.45,
        "confidence": int(score * 100),
        "riskLevel": risk,
        "indicators": indicators if indicators else ["✓ Safe"],
    }


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Phishing Detector API"})


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        url = data.get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400

        features = extract_url_features(url)
        result = predict_phishing(features)

        return jsonify(
            {
                "url": url,
                "isPhishing": result["isPhishing"],
                "confidence": result["confidence"],
                "riskLevel": result["riskLevel"],
                "indicators": result["indicators"],
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("🛡️ Starting Phishing Detector API...")
    print("👉 http://127.0.0.1:5000/health")
    app.run(debug=True, port=5000, host="127.0.0.1")
