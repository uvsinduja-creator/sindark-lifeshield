"""
URL Feature Extraction for LifeShield Phishing URL ML Model.
Extracts lexical, structural, and statistical features from URLs (CPU-efficient).
"""
import math
import re
from urllib.parse import urlparse
from typing import Dict, List, Any

# Common keywords associated with credential harvesting and phishing attacks
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "account", "update", "banking",
    "secure", "security", "webscr", "signin", "sign-in", "ebayisapi",
    "auth", "authentication", "confirm", "confirmation", "paypal",
    "wallet", "recover", "recovery", "password", "credential", "suspend",
    "suspended", "alert", "billing", "invoice", "token", "support"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work", "icu",
    "cam", "fit", "rest", "party", "click", "live", "country", "link"
}

IPV4_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$")


def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_url_features(url: str) -> Dict[str, float]:
    """
    Extracts a numeric feature vector from a given URL string.
    Returns a dictionary of feature names to float values.
    """
    if not url:
        url = ""

    parsed = urlparse(url)
    hostname = parsed.netloc.split(":")[0].lower() if parsed.netloc else ""
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()

    # Domain parts
    domain_parts = hostname.split(".")
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""

    # Digits
    digits_url = sum(c.isdigit() for c in full_url)
    digits_host = sum(c.isdigit() for c in hostname)

    # Keywords matching in path/query/hostname
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url)

    # Check for IP address in hostname
    is_ip = 1.0 if IPV4_PATTERN.match(parsed.netloc) else 0.0

    # Subdomain count
    subdomain_count = max(0, len(domain_parts) - 2) if not is_ip else 0

    features: Dict[str, float] = {
        "url_length": float(len(full_url)),
        "host_length": float(len(hostname)),
        "path_length": float(len(path)),
        "count_dots": float(full_url.count(".")),
        "count_hyphens": float(full_url.count("-")),
        "count_at": float(full_url.count("@")),
        "count_question": float(full_url.count("?")),
        "count_percent": float(full_url.count("%")),
        "count_equal": float(full_url.count("=")),
        "count_slash": float(full_url.count("/")),
        "subdomain_count": float(subdomain_count),
        "digits_url": float(digits_url),
        "ratio_digits_url": round(digits_url / len(full_url), 4) if full_url else 0.0,
        "ratio_digits_host": round(digits_host / len(hostname), 4) if hostname else 0.0,
        "is_ip": is_ip,
        "is_https": 1.0 if parsed.scheme == "https" else 0.0,
        "has_port": 1.0 if parsed.port is not None else 0.0,
        "entropy": calculate_entropy(full_url),
        "keyword_hits": float(keyword_hits),
        "suspicious_tld": 1.0 if tld in SUSPICIOUS_TLDS else 0.0,
    }

    return features


FEATURE_NAMES = list(extract_url_features("http://example.com").keys())


def features_to_vector(features: Dict[str, float]) -> List[float]:
    """Converts a feature dictionary to an ordered feature list."""
    return [features.get(name, 0.0) for name in FEATURE_NAMES]


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=lifeshield",
        "http://192.168.1.15/paypal/login.php?cmd=verify&account=update",
        "https://secure-apple-id-verify.account-update.xyz/login.html"
    ]
    for u in test_urls:
        feats = extract_url_features(u)
        print(f"URL: {u}")
        print(f"  Entropy: {feats['entropy']} | Keywords: {feats['keyword_hits']} | Is IP: {feats['is_ip']} | Length: {feats['url_length']}")
