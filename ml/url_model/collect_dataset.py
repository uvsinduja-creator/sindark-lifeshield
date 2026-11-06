"""
Dataset collection script for LifeShield URL Phishing Model.
Downloads real-world threat feeds and legitimate domain rankings:
  1. Phishing: JPCERT/CC verified phishing archive (Jan-Jun 2024) + OpenPhish community feed
  2. Benign: Tranco Top 1M list (standard scientific research benchmark) + diverse real-world paths
Saves large curated, deduplicated dataset to ml/url_model/data/dataset.csv.
"""
import csv
import io
import os
import random
import sys
import urllib.request
import zipfile
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DATASET_CSV = DATA_DIR / "dataset.csv"

# Diverse realistic web paths representing modern websites
COMMON_BENIGN_PATHS = [
    "",
    "/",
    "/about",
    "/about-us",
    "/contact",
    "/contact-us",
    "/privacy-policy",
    "/terms-of-service",
    "/docs",
    "/docs/v2/getting-started",
    "/documentation/overview",
    "/blog",
    "/blog/2024/03/modern-cloud-infrastructure",
    "/news",
    "/news/technology/quantum-computing-breakthrough",
    "/help",
    "/help-center/faq",
    "/support",
    "/search?q=open+source+software",
    "/search?q=python+programming+guide",
    "/search?q=machine+learning+tutorial",
    "/products/item?id=1024",
    "/products/laptops/macbook-pro",
    "/category/electronics",
    "/articles/view?id=492",
    "/wiki/Computer_science",
    "/wiki/Information_security",
    "/wiki/Machine_learning",
    "/wiki/Artificial_intelligence",
    "/questions/tagged/python",
    "/questions/4829104/how-to-optimize-code",
    "/en-US/docs/Web/JavaScript/Reference",
    "/en-US/docs/Web/HTTP/Overview",
    "/watch?v=dQw4w9WgXcQ",
    "/channel/UC_x5XG1OV2P6uZZ5FSM9Ttw",
    "/releases/tag/v1.2.0",
    "/tree/main/src/components",
    "/blob/main/README.md",
    "/download/latest",
    "/features/collaboration",
    "/pricing/plans",
    "/dashboard/analytics",
    "/community/forum/topic/4921",
    "/explore/trending",
]

# High-reputation reference benign URLs to ensure standard sites are represented
SEED_BENIGN_URLS = [
    "https://www.google.com/search?q=python+programming",
    "https://github.com/torvalds/linux",
    "https://github.com/python/cpython",
    "https://en.wikipedia.org/wiki/Computer_science",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Software_engineering",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://stackoverflow.com/questions/tagged/python",
    "https://docs.python.org/3/library/functions.html",
    "https://pypi.org/project/scikit-learn/",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://portal.azure.com",
    "https://news.ycombinator.com",
    "https://www.nytimes.com/section/technology",
    "https://cve.mitre.org",
    "https://nist.gov/cyberframework",
    "https://cloudflare.com/learning/access-management/what-is-zero-trust/",
]


def fetch_openphish_urls(limit: int = 500) -> list[str]:
    """Fetches active phishing URLs from OpenPhish feed."""
    print("[+] Fetching live phishing URLs from OpenPhish...")
    url = "https://openphish.com/feed.txt"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    urls = []
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            lines = resp.read().decode("utf-8", errors="ignore").splitlines()
            for line in lines:
                l = line.strip()
                if l.startswith("http://") or l.startswith("https://"):
                    urls.append(l)
        print(f"    Downloaded {len(urls)} URLs from OpenPhish.")
    except Exception as e:
        print(f"    [!] Warning: Failed to fetch OpenPhish ({e})")
    return urls[:limit]


def fetch_jpcert_phishing_urls(months: list[str] = ["202401", "202402", "202403", "202404", "202405", "202406"]) -> list[str]:
    """Fetches verified phishing URLs from JPCERT/CC archive."""
    print(f"[+] Fetching verified phishing archives from JPCERT/CC ({len(months)} months)...")
    all_urls = []
    for month in months:
        url = f"https://raw.githubusercontent.com/JPCERTCC/phishurl-list/main/2024/{month}.csv"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                reader = csv.reader(io.StringIO(content))
                next(reader, None)  # skip header
                for row in reader:
                    if len(row) > 1:
                        target_url = row[1].strip()
                        if target_url.startswith("http://") or target_url.startswith("https://"):
                            all_urls.append(target_url)
            print(f"    Downloaded {len(all_urls)} URLs so far after {month} archive.")
        except Exception as e:
            print(f"    [!] Warning: Failed to fetch JPCERT {month} ({e})")
    return all_urls


def fetch_tranco_benign_urls(sample_size: int = 25000) -> list[str]:
    """Downloads top domains from Tranco list and synthesizes realistic paths."""
    print(f"[+] Fetching {sample_size} top legitimate domains from Tranco list...")
    url = "https://tranco-list.eu/top-1m.csv.zip"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    benign_urls = list(SEED_BENIGN_URLS)
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = resp.read()
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                first_file = z.namelist()[0]
                with z.open(first_file) as f:
                    lines = [f.readline().decode("utf-8", errors="ignore").strip() for _ in range(sample_size)]
                    for line in lines:
                        parts = line.split(",")
                        if len(parts) == 2:
                            domain = parts[1].strip()
                            # 85% HTTPS, 15% HTTP (standard modern web distribution)
                            scheme = "https" if random.random() < 0.85 else "http"
                            subpath = random.choice(COMMON_BENIGN_PATHS)
                            benign_urls.append(f"{scheme}://{domain}{subpath}")
        print(f"    Synthesized {len(benign_urls)} benign URLs from Tranco top domains.")
    except Exception as e:
        print(f"    [!] Warning: Failed to fetch Tranco ({e})")
    return benign_urls


def build_and_save_dataset(target_samples_per_class: int = 20000) -> None:
    """Builds large balanced dataset of benign and phishing URLs and writes to CSV."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Phishing URLs
    phish_openphish = fetch_openphish_urls()
    phish_jpcert = fetch_jpcert_phishing_urls()
    all_phishing = list(dict.fromkeys(phish_openphish + phish_jpcert))
    random.seed(42)
    random.shuffle(all_phishing)
    selected_phishing = all_phishing[:target_samples_per_class]

    # 2. Benign URLs
    benign_urls = fetch_tranco_benign_urls(sample_size=len(selected_phishing) + 1000)
    selected_benign = benign_urls[:len(selected_phishing)]

    print(f"\n[+] Scaled dataset summary:")
    print(f"    Phishing URLs: {len(selected_phishing)}")
    print(f"    Benign URLs:   {len(selected_benign)}")
    print(f"    Total samples: {len(selected_phishing) + len(selected_benign)}")

    # 3. Write to CSV
    with open(DATASET_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for u in selected_benign:
            writer.writerow([u, 0])
        for u in selected_phishing:
            writer.writerow([u, 1])

    print(f"[+] Successfully wrote {len(selected_phishing) + len(selected_benign)} samples to {DATASET_CSV}")


if __name__ == "__main__":
    build_and_save_dataset()
