from flask import Flask, request, jsonify
from flask_cors import CORS
import re
from urllib.parse import urlparse
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)


def has_suspicious_keywords(url):
    """Check for suspicious keywords in URL"""
    suspicious_keywords = [
        "verify",
        "confirm",
        "update",
        "secure",
        "account",
        "login",
        "signin",
        "password",
        "urgent",
        "confirm-identity",
        "validate",
        "activate",
        "reactivate",
        "suspended",
        "limited",
        "unusual",
        "suspicious",
        "alert",
        "action",
        "required",
        "immediately",
    ]
    url_low = url.lower()
    for keyword in suspicious_keywords:
        if keyword in url_low:
            return 1
    return 0


def has_brand_mimicking(domain, path):
    """Check if URL is mimicking famous brands"""
    brands = [
        "amazon",
        "paypal",
        "apple",
        "google",
        "microsoft",
        "facebook",
        "instagram",
        "twitter",
        "linkedin",
        "stripe",
        "visa",
        "mastercard",
        "bank",
        "chase",
        "wells",
        "amex",
        "americanexpress",
        "ebay",
        "alibaba",
        "netflix",
        "uber",
        "airbnb",
        "spotify",
        "dropbox",
    ]
    domain_low = domain.lower()
    path_low = path.lower()
    full_url = f"{domain}{path}".lower()

    brand_count = sum(1 for b in brands if b in full_url)
    if brand_count >= 2:
        return 1

    for b in brands:
        if b in path_low and b not in domain_low:
            return 1

    return 0


def is_suspicious_tld(domain):
    """Check if domain has suspicious TLD"""
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
        "gq",
        "work",
        "click",
        "loan",
    ]
    tld = domain.split(".")[-1].lower()
    return tld in suspicious_tlds


def has_suspicious_path_structure(path, domain):
    """Check if path contains domain-like structures (very suspicious)"""
    if not path or path == "/":
        return 0

    path_lower = path.lower()

    if re.search(r"/www\.|/mail\.|/secure\.|/online\.", path_lower):
        return 1

    if re.search(r"/[a-z0-9\-]+\.[a-z]{2,}/", path_lower):
        return 1

    if path.count(".") >= 2:
        return 1

    return 0


def extract_url_features(url):
    """Extract features from URL for phishing detection"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        full_url = url.lower()

        free_host_providers = [
            "servebbs.org",
            "no-ip",
            "duckdns.org",
            "hopto.org",
            "changeip",
            "ddns",
        ]

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
            "port": 1
            if ":" in domain and not re.match(r":\d+$", domain.split(":")[-1])
            else 0,
            "domain_mimicking": has_brand_mimicking(domain, path),
            "suspicious_keywords": has_suspicious_keywords(full_url),
            "suspicious_path": has_suspicious_path_structure(path, domain),
            "suspicious_extension": 1
            if path.endswith(".php") or path.endswith(".asp") or path.endswith(".aspx")
            else 0,
            "free_host": 1
            if any(h in domain.lower() for h in free_host_providers)
            else 0,
        }

        logger.debug(f"Features for {url}: {features}")
        return features
    except Exception as e:
        logger.error(f"Feature extraction error: {e}")
        return None


def predict_phishing(features):
    """Predict if URL is phishing based on features"""
    if not features:
        return {
            "isPhishing": False,
            "confidence": 0,
            "riskLevel": "UNKNOWN",
            "indicators": [],
        }

    score = 0.0
    indicators = []

    if features["having_ip"]:
        score += 0.25
        indicators.append("❌ IP address instead of domain name")

    if features["symbol_at"]:
        score += 0.20
        indicators.append("❌ Contains @ symbol (credential hiding)")

    if features["redirecting"]:
        score += 0.15
        indicators.append("⚠️ Multiple redirects detected")

    if features["domain_mimicking"]:
        score += 0.30
        indicators.append("❌ Domain mimicking famous brands")

    if features["suspicious_keywords"]:
        score += 0.20
        indicators.append("❌ Suspicious phishing-related keywords in URL")

    if features["suspicious_path"]:
        score += 0.25
        indicators.append("❌ Suspicious path structure (domain-like patterns in path)")

    if features["suspicious_extension"]:
        score += 0.15
        indicators.append("⚠️ Suspicious script extension (.php/.asp/.aspx)")

    if features["free_host"]:
        score += 0.25
        indicators.append(
            "❌ Uses free/dynamic DNS hosting (commonly abused in phishing kits)"
        )

    if features["domain_age"]:
        score += 0.15
        indicators.append("⚠️ Suspicious TLD detected")

    if features["prefix_suffix"]:
        score += 0.12
        indicators.append("⚠️ Hyphens in domain (mimics trusted sites)")

    if features["sub_domain"]:
        score += 0.12
        indicators.append("⚠️ Too many subdomains (unusual)")

    if features["long_url"]:
        score += 0.08
        indicators.append("⚠️ Unusually long URL")

    if not features["https"]:
        score += 0.08
        indicators.append("⚠️ Not using HTTPS (unencrypted)")

    if features["short_url"]:
        score += 0.05
        indicators.append("⚠️ Shortened/suspicious URL length")

    if features["port"]:
        score += 0.10
        indicators.append("⚠️ Non-standard port detected")

    score = min(score, 1.0)

    if score >= 0.80:
        risk_level = "CRITICAL"
    elif score >= 0.55:
        risk_level = "HIGH"
    elif score >= 0.35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "isPhishing": score >= 0.55,
        "confidence": int(score * 100),
        "riskLevel": risk_level,
        "indicators": indicators if indicators else ["✓ No threats detected"],
    }


@app.route("/predict", methods=["POST"])
def predict():
    """Main prediction endpoint"""
    try:
        data = request.json
        url = data.get("url", "")

        if not url:
            return jsonify({"error": "URL required"}), 400

        logger.info(f"Analyzing URL: {url}")

        features = extract_url_features(url)
        if not features:
            return jsonify({"error": "Feature extraction failed"}), 500

        result = predict_phishing(features)

        return jsonify(
            {
                "url": url,
                "isPhishing": result["isPhishing"],
                "confidence": result["confidence"],
                "riskLevel": result["riskLevel"],
                "indicators": result["indicators"],
                "source": "Rule-Based Detection with XAI",
            }
        )

    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Phishing Detector API"})


if __name__ == "__main__":
    logger.info("🛡️ Phishing Detector API Starting...")
    logger.info("Server running at http://127.0.0.1:5000")
    app.run(debug=True, port=5000, host="127.0.0.1")
