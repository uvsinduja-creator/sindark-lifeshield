"""
Dataset collection script for LifeShield Scam Message NLP Model (Week 5).
Downloads real-world SMS Spam/Phishing and Fraud/Phishing email datasets:
  1. UCI SMS Spam Collection benchmark (5,574 real SMS messages)
  2. Fraud Email Phishing dataset (11,929 real email samples)
Combines, cleans, deduplicates, and saves balanced ~10,000-sample dataset to ml/nlp_model/data/dataset.csv.
"""
import csv
import io
import random
import re
import sys
import urllib.request
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DATASET_CSV = DATA_DIR / "dataset.csv"

# Diverse modern scam/phishing message patterns (SMS, WhatsApp, Email, Telegram)
MODERN_SCAM_PATTERNS = [
    ("URGENT: Your Chase checking account has been temporarily locked due to suspicious activity. Verify identity now at https://chase-security-auth.top/verify or your card will be deactivated.", 1),
    ("USPS Alert: Your shipment #9400111899562537612984 is held at our distribution center due to unpaid customs fee ($2.95). Update address and pay here: http://usps-redelivery-portal.xyz", 1),
    ("SECURITY WARNING: A new sign-in from an unknown Windows device was detected on your Microsoft account. If this was not you, reset password immediately: https://msft-account-protection.xyz/signin", 1),
    ("Wells Fargo Security: Did you attempt a Zelle transfer of $750.00 to JOHN? Reply YES or NO. If NO, call our fraud department immediately at 1-800-555-0199.", 1),
    ("Amazon Security: Unusual login attempt from IP 192.168.1.1. Your order has been placed on hold. Confirm your billing details at http://amazon-billing-check.top/confirm", 1),
    ("Congratulations! You have been selected as the 2nd place winner in the Walmart Customer Appreciation Raffle. Claim your $1,000 gift card here: http://walmart-rewards-gift.xyz", 1),
    ("Internal Revenue Service Notice: You have an unpaid tax balance of $1,420. Failure to respond within 24 hours will result in legal enforcement. Settle now: http://irs-tax-settlement.xyz", 1),
    ("Binance Security Alert: An unauthorized withdrawal request of 0.85 BTC was initiated. Cancel withdrawal immediately by verifying your 2FA at https://binance-security-cancel.top", 1),
    ("MetaMask Notification: Your wallet requires mandatory software migration to prevent permanent asset loss. Enter your 12-word seed phrase here to backup: http://metamask-migrate.icu", 1),
    ("Netflix Payment Failed: We were unable to process your monthly subscription renewal. Update your payment method within 48 hours to avoid service interruption: http://netflix-billing-update.top", 1),
    ("PayPal Alert: You sent a payment of $499.00 to CryptoExchange Inc. If you did not make this transaction, dispute the charge now: http://paypal-resolution-center.top/dispute", 1),
    ("Bank of America Fraud Alert: Immediate action required. Your online banking access has been suspended due to multiple failed login attempts. Reactivate at http://bofa-reactivate.xyz", 1),
    ("Apple ID Verification: Your iCloud account is scheduled for deletion due to inactivity and security flags. Verify credentials now: http://appleid-manage-security.xyz", 1),
    ("DHL Express: Delivery attempt failed for package tracking #DHL-83921. Schedule re-delivery and settle delivery surcharge ($1.50) here: http://dhl-delivery-confirm.top", 1),
    ("HR Payroll Update: Please verify your direct deposit banking information for the upcoming pay cycle before 5:00 PM today: http://payroll-portal-verification.xyz/login", 1),
]

MODERN_BENIGN_PATTERNS = [
    ("Hey, are we still meeting for lunch tomorrow at 12:30?", 0),
    ("Can you send me the slide deck from today's architecture review meeting?", 0),
    ("Your appointment with Dr. Smith is confirmed for Thursday at 3:00 PM. Reply 1 to confirm, 2 to reschedule.", 0),
    ("Don't forget to review the pull request on GitHub when you have a moment.", 0),
    ("The package was delivered on your front porch at 2:15 PM.", 0),
    ("Happy birthday! Wishing you a wonderful day and year ahead!", 0),
    ("I just pushed the latest commit with the unit test fixes. Please pull and check.", 0),
    ("Your verification code is 482910. It expires in 10 minutes. Do not share this code with anyone.", 0),
    ("Hey mom, I arrived safely at the train station. Heading home now.", 0),
    ("Thanks for sending the document over. I'll read through it this afternoon.", 0),
    ("Meeting link for our 4pm standup: https://meet.google.com/abc-defg-hij", 0),
    ("Can you pick up milk and bread on your way back from work?", 0),
    ("Your table at Luigi's Italian Bistro is ready for party of 4.", 0),
    ("Flight AA 1492 to Chicago is on time. Gate departure at B14.", 0),
    ("Sounds great! Let's touch base on Monday after the sprint planning.", 0),
]


def clean_text(text: str) -> str:
    """Normalizes whitespace and removes null characters."""
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def fetch_sms_spam_dataset() -> list[tuple[str, int]]:
    """Downloads and parses the UCI SMS Spam Collection benchmark dataset."""
    print("[+] Fetching UCI SMS Spam Collection dataset...")
    url = "https://raw.githubusercontent.com/ShresthaSudip/SMS_Spam_Detection_DNN_LSTM_BiLSTM/master/SMSSpamCollection"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    samples = []
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            for line in content.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    raw_label = parts[0].strip().lower()
                    raw_text = clean_text(parts[1])
                    if raw_text:
                        label = 1 if raw_label == "spam" else 0
                        samples.append((raw_text, label))
        print(f"    Loaded {len(samples)} samples from SMS Spam Collection.")
    except Exception as e:
        print(f"    [!] Warning: Failed to fetch SMS Spam Collection ({e})")
    return samples


def fetch_fraud_email_dataset(limit: int = 10000) -> list[tuple[str, int]]:
    """Downloads and parses samples from the Fraud Email dataset."""
    print("[+] Fetching samples from Fraud Email Phishing dataset...")
    url = "https://raw.githubusercontent.com/mo-messidi/Email-Phishing-Attempts-Detection-using-NLP/master/fraud_email_.csv"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    samples = []
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            reader = csv.reader(io.StringIO(content))
            next(reader, None)  # skip header
            count = 0
            for row in reader:
                if len(row) >= 2:
                    text = clean_text(row[0])
                    try:
                        label = int(row[1].strip())
                    except ValueError:
                        continue
                    if 20 <= len(text) <= 2500:
                        samples.append((text, label))
                        count += 1
                        if count >= limit:
                            break
        print(f"    Loaded {len(samples)} samples from Fraud Email dataset.")
    except Exception as e:
        print(f"    [!] Warning: Failed to fetch Fraud Email dataset ({e})")
    return samples


def build_and_save_dataset(target_per_class: int = 5000) -> None:
    """Assembles all data sources, balances, deduplicates, and saves to CSV."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Fetch datasets
    sms_samples = fetch_sms_spam_dataset()
    email_samples = fetch_fraud_email_dataset(limit=10000)

    # 2. Add modern patterns
    all_raw = sms_samples + email_samples + MODERN_SCAM_PATTERNS + MODERN_BENIGN_PATTERNS

    # Deduplicate by normalized text
    seen = set()
    cleaned_samples = []
    for text, label in all_raw:
        norm = text.lower().strip()
        if norm not in seen and len(text) >= 10:
            seen.add(norm)
            cleaned_samples.append((text, label))

    ham_list = [s for s in cleaned_samples if s[1] == 0]
    spam_list = [s for s in cleaned_samples if s[1] == 1]

    random.seed(42)
    random.shuffle(ham_list)
    random.shuffle(spam_list)

    selected_count = min(len(ham_list), len(spam_list), target_per_class)
    selected_ham = ham_list[:selected_count]
    selected_spam = spam_list[:selected_count]

    final_dataset = selected_ham + selected_spam
    random.shuffle(final_dataset)

    print(f"\n[+] Scaled NLP Dataset Summary:")
    print(f"    Total Benign (Ham) : {len(selected_ham)}")
    print(f"    Total Scam (Spam)  : {len(selected_spam)}")
    print(f"    Total Samples      : {len(final_dataset)}")

    with open(DATASET_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        for text, label in final_dataset:
            writer.writerow([text, label])

    print(f"[+] Successfully wrote {len(final_dataset)} samples to {DATASET_CSV}")


if __name__ == "__main__":
    build_and_save_dataset()
