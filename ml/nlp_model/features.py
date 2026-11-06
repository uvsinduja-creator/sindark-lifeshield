"""
Linguistic and Behavioral Feature Extraction for Scam/Phishing Message NLP Model.
Extracts explainable indicator tags (urgency, credential lures, financial demands, links).
"""
import re
from typing import List, Dict, Any

URGENCY_KEYWORDS = [
    r"\burgent\b", r"\bimmediately\b", r"\baction required\b", r"\bsuspended\b",
    r"\bdeactivated\b", r"\block(?:ed)?\b", r"\bfinal notice\b", r"\b24 hours?\b",
    r"\b48 hours?\b", r"\bexpire[ds]?\b", r"\bwarning\b", r"\balert\b",
    r"\bunauthorized\b", r"\btermination\b"
]

FINANCIAL_KEYWORDS = [
    r"\b\$[0-9]+(?:\.[0-9]{2})?\b", r"\btransfer\b", r"\brefund\b", r"\blottery\b",
    r"\bwon\b", r"\bprize\b", r"\bwire\b", r"\bbitcoin\b", r"\bbtc\b", r"\bcrypto\b",
    r"\bgift card\b", r"\bsettle(?:ment)?\b", r"\bcustoms fee\b", r"\bpayment\b",
    r"\bbilling\b", r"\binvoice\b", r"\bzelle\b"
]

CREDENTIAL_KEYWORDS = [
    r"\bpassword\b", r"\bpasscode\b", r"\bpin\b", r"\botp\b", r"\bverify\b",
    r"\bverification\b", r"\bseed phrase\b", r"\bsecurity code\b", r"\bssn\b",
    r"\bcredit card\b", r"\blogin\b", r"\bsign-?in\b", r"\bcredentials?\b"
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
PHONE_PATTERN = re.compile(r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}")


def extract_message_indicators(text: str) -> List[str]:
    """
    Scans a message for explainable threat signals and indicators.
    Returns a human-readable list of detected triggers.
    """
    if not text:
        return []

    text_lower = text.lower()
    indicators: List[str] = []

    # 1. Links
    found_urls = URL_PATTERN.findall(text)
    if found_urls:
        indicators.append(f"Embedded link detected ({found_urls[0][:40]}...)")

    # 2. Urgency triggers
    matched_urgency = [k for k in URGENCY_KEYWORDS if re.search(k, text_lower)]
    if matched_urgency:
        indicators.append("High-urgency language attempting to compel immediate action")

    # 3. Credential lures
    matched_creds = [k for k in CREDENTIAL_KEYWORDS if re.search(k, text_lower)]
    if matched_creds:
        indicators.append("Credential or identity verification solicitation")

    # 4. Financial / payment / prize cues
    matched_finance = [k for k in FINANCIAL_KEYWORDS if re.search(k, text_lower)]
    if matched_finance:
        indicators.append("Financial, prize reward, or unexpected payment demand")

    # 5. Suspicious callback phone numbers
    found_phones = PHONE_PATTERN.findall(text)
    if found_phones and (matched_urgency or matched_creds):
        indicators.append("Urgent callback phone number prompt")

    # 6. Excessive capitalization
    letters = [c for c in text if c.isalpha()]
    if len(letters) >= 20:
        cap_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        if cap_ratio >= 0.45:
            indicators.append("Aggressive all-caps typography pattern")

    return indicators


if __name__ == "__main__":
    sample_scam = "URGENT: Your Bank of America account is locked. Verify password now: http://bofa-verify.xyz"
    print("Sample Scam Indicators:", extract_message_indicators(sample_scam))
    sample_ham = "Hey, are you free for lunch tomorrow at noon?"
    print("Sample Ham Indicators:", extract_message_indicators(sample_ham))
