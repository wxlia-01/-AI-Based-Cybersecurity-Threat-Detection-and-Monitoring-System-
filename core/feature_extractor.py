"""
Feature extraction module for CyberShield.
Extracts numerical/boolean features from URLs, IPs, and text messages.
"""

import re
import math
import ipaddress
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# URL Features
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".download", ".loan", ".win", ".bid", ".stream", ".gdn", ".icu",
    ".buzz", ".monster", ".cyou", ".cfd",
}

TRUSTED_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "ebay",
    "bank", "chase", "wellsfargo", "citibank", "irs", "fedex", "dhl",
]

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "update", "confirm", "account",
    "secure", "banking", "password", "credential", "wallet", "reset",
    "alert", "suspended", "unlock", "validate", "authenticate",
]

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
}


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def extract_url_features(url: str) -> dict:
    """Return a feature dict for a URL string."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()

    # Basic length signals
    url_length = len(url)
    host_length = len(host)
    path_length = len(path)
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_at = url.count("@")
    num_digits_in_host = sum(c.isdigit() for c in host)
    num_subdomains = max(0, host.count(".") - 1)

    # Entropy (high = random/DGA domain)
    domain_parts = host.split(".")
    domain_name = domain_parts[-2] if len(domain_parts) >= 2 else host
    host_entropy = _entropy(domain_name)

    # Structural flags
    has_ip_in_host = 0
    try:
        ipaddress.ip_address(host)
        has_ip_in_host = 1
    except ValueError:
        pass

    has_https = int(parsed.scheme == "https")
    has_at_symbol = int("@" in url)
    has_double_slash_redirect = int("//" in path)
    is_shortener = int(host in SHORTENER_HOSTS)

    # TLD suspicion
    tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
    suspicious_tld = int(tld.lower() in SUSPICIOUS_TLDS)

    # Brand impersonation: brand word in subdomain but not as the real domain
    brand_in_subdomain = 0
    if num_subdomains > 0:
        subdomain_part = ".".join(domain_parts[:-2]).lower()
        brand_in_subdomain = int(any(b in subdomain_part for b in TRUSTED_BRANDS))

    # Phishing keyword count
    phishing_kw_count = sum(kw in full for kw in PHISHING_KEYWORDS)

    # Query string length
    query_length = len(parsed.query)
    has_encoded_chars = int("%" in url)

    return {
        "url_length": url_length,
        "host_length": host_length,
        "path_length": path_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_at": num_at,
        "num_digits_in_host": num_digits_in_host,
        "num_subdomains": num_subdomains,
        "host_entropy": round(host_entropy, 4),
        "has_ip_in_host": has_ip_in_host,
        "has_https": has_https,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_redirect": has_double_slash_redirect,
        "is_shortener": is_shortener,
        "suspicious_tld": suspicious_tld,
        "brand_in_subdomain": brand_in_subdomain,
        "phishing_kw_count": phishing_kw_count,
        "query_length": query_length,
        "has_encoded_chars": has_encoded_chars,
    }


# ---------------------------------------------------------------------------
# IP Address Features
# ---------------------------------------------------------------------------

KNOWN_MALICIOUS_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("100.64.0.0/10"),   # Shared address space
]


def extract_ip_features(ip_str: str) -> dict:
    """Return feature dict for an IP address string."""
    ip_str = ip_str.strip()
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"valid_ip": 0, "is_private": 0, "is_loopback": 0,
                "is_multicast": 0, "is_reserved": 0, "in_known_bad_range": 0,
                "ip_version": 0, "octet_entropy": 0.0}

    in_known_bad = int(any(addr in net for net in KNOWN_MALICIOUS_RANGES))

    return {
        "valid_ip": 1,
        "is_private": int(addr.is_private),
        "is_loopback": int(addr.is_loopback),
        "is_multicast": int(addr.is_multicast),
        "is_reserved": int(addr.is_reserved),
        "in_known_bad_range": in_known_bad,
        "ip_version": addr.version,
        "octet_entropy": round(_entropy(ip_str.replace(".", "").replace(":", "")), 4),
    }


# ---------------------------------------------------------------------------
# Text / Message Features
# ---------------------------------------------------------------------------

SOCIAL_ENG_PATTERNS = [
    r"urgent",
    r"act\s+now",
    r"limited\s+time",
    r"your\s+account\s+(has\s+been|is|was)\s+(suspended|locked|compromised)",
    r"click\s+(here|below|the\s+link)",
    r"verify\s+your",
    r"confirm\s+your",
    r"unusual\s+sign[- ]in",
    r"we\s+detected",
    r"congratulations.{0,30}(won|winner|prize)",
    r"free\s+(gift|money|iphone|ipad)",
    r"you\s+have\s+been\s+selected",
    r"update\s+your\s+payment",
    r"invoice\s+(attached|enclosed)",
    r"open\s+the\s+attachment",
    r"wire\s+transfer",
    r"bitcoin|crypto.*wallet",
    r"password\s+(expired|reset\s+required)",
    r"tax\s+(refund|return)",
    r"irs|revenue\s+service",
]

URL_PATTERN = re.compile(
    r"https?://[^\s]+|www\.[^\s]+", re.IGNORECASE
)


def extract_text_features(text: str) -> dict:
    """Return feature dict for a free-text message."""
    text_lower = text.lower()
    words = re.findall(r"\b\w+\b", text_lower)
    word_count = len(words)

    social_eng_hits = sum(
        1 for p in SOCIAL_ENG_PATTERNS if re.search(p, text_lower)
    )
    url_count = len(URL_PATTERN.findall(text))
    exclamation_count = text.count("!")
    question_count = text.count("?")
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    has_phone_number = int(bool(re.search(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", text)))
    has_ssn_pattern = int(bool(re.search(r"\b\d{3}-\d{2}-\d{4}\b", text)))
    avg_word_length = (sum(len(w) for w in words) / word_count) if word_count else 0

    return {
        "word_count": word_count,
        "social_eng_hits": social_eng_hits,
        "url_count": url_count,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "caps_ratio": round(caps_ratio, 4),
        "has_phone_number": has_phone_number,
        "has_ssn_pattern": has_ssn_pattern,
        "avg_word_length": round(avg_word_length, 4),
    }
