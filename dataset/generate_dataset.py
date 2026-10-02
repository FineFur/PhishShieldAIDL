"""
PhishShield AI - Dataset Generator

Generates a realistic URL features dataset for model training.
This creates synthetic but statistically representative data
based on known phishing URL characteristics from research literature,
INCLUDING modern phishing toolkit patterns (zphisher, ngrok, 000webhost, etc.)

Output: dataset/url_features_extracted1.csv

This script is used ONLY if the real dataset is not available.
If url_features_extracted1.csv already exists, this script should NOT be run.
"""

import os
import sys
import math
import random
import csv
import re
import string
from collections import Counter
from urllib.parse import urlparse, parse_qs

random.seed(42)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(PROJECT_ROOT, "dataset")
OUTPUT_PATH = os.path.join(DATASET_DIR, "url_features_extracted1.csv")

# ── Feature columns (now 18 features) ─────────────────────────────────
COLUMNS = [
    "URL",
    "url_length",
    "has_ip_address",
    "dot_count",
    "https_flag",
    "url_entropy",
    "token_count",
    "subdomain_count",
    "query_param_count",
    "tld_length",
    "path_length",
    "has_hyphen_in_domain",
    "number_of_digits",
    "tld_popularity",
    "suspicious_file_extension",
    "domain_name_length",
    "percentage_numeric_chars",
    "uses_free_hosting",   # NEW
    "brand_in_path",       # NEW
    "ClassLabel",
]

POPULAR_TLDS = ["com", "org", "net", "edu", "gov", "io", "co", "dev", "app", "ai"]
UNCOMMON_TLDS = ["xyz", "top", "club", "buzz", "tk", "ml", "ga", "cf", "gq", "info", "biz", "win", "racing"]

LEGIT_DOMAINS = [
    "google", "facebook", "amazon", "microsoft", "apple", "github",
    "stackoverflow", "wikipedia", "linkedin", "twitter", "youtube",
    "netflix", "spotify", "reddit", "dropbox", "adobe", "oracle",
    "salesforce", "shopify", "zoom", "slack", "notion", "figma",
    "stripe", "paypal", "ebay", "walmart", "target", "bestbuy",
    "medium", "quora", "pinterest", "tumblr", "instagram",
]

SUSPICIOUS_WORDS = [
    "secure", "login", "verify", "account", "update", "confirm",
    "banking", "wallet", "signin", "password", "credential",
    "suspended", "locked", "urgent", "alert", "warning",
    "free", "prize", "winner", "claim", "offer",
]

SUSPICIOUS_EXTS = [".exe", ".zip", ".php", ".cgi", ".asp", ".jsp"]

# Zphisher / modern phishing toolkit hosting services
FREE_HOSTING_SERVICES = [
    "000webhostapp.com",
    "000webhost.com",
    "infinityfreeapp.com",
    "epizy.com",
    "byethost.com",
    "atwebpages.com",
    "glitch.me",
    "replit.app",
    "repl.co",
]
TUNNEL_SERVICES = [
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "loca.lt",
    "localxpose.io",
    "serveo.net",
    "trycloudflare.com",
    "pagekite.me",
]
KNOWN_BRANDS = [
    "facebook", "fb", "instagram", "whatsapp", "messenger",
    "google", "gmail", "youtube",
    "apple", "icloud",
    "microsoft", "outlook", "hotmail",
    "paypal", "ebay", "amazon", "netflix",
    "twitter", "linkedin", "snapchat",
    "hdfc", "icici", "sbi", "paytm",
]

POPULAR_TLD_SET = {"com", "org", "net", "edu", "gov", "io", "co", "dev", "app", "ai",
                    "me", "us", "uk", "in"}


# ── Utility functions ──────────────────────────────────────────────────

def calc_entropy(text):
    """Shannon entropy."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features_from_url(url):
    """Extract all 18 features from a generated URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    url_length = len(url)
    has_ip = 1 if re.search(r'(?:\d{1,3}\.){3}\d{1,3}', url) else 0
    dot_count = url.count(".")
    https_flag = 1 if parsed.scheme == "https" else 0
    url_entropy = calc_entropy(url)

    tokens = re.split(r'[/.\-_?=&@:]+', url)
    token_count = len([t for t in tokens if t])

    parts = hostname.split(".")
    if len(parts) > 2:
        subdomain_count = len(parts) - 2
    else:
        subdomain_count = 0
    if random.random() < 0.05:
        subdomain_count = -1

    query_param_count = len(parse_qs(parsed.query))
    tld = parts[-1] if parts else ""
    tld_length = len(tld)
    path_length = len(path)

    domain_part = parts[-2] if len(parts) >= 2 else hostname
    has_hyphen = 1 if "-" in domain_part else 0

    num_digits = sum(1 for c in url if c.isdigit())
    tld_popularity = 1 if tld.lower() in POPULAR_TLD_SET else 0

    suspicious_ext = 0
    for ext in [".exe", ".zip", ".php", ".cgi", ".asp", ".jsp", ".bat", ".scr"]:
        if path.lower().endswith(ext):
            suspicious_ext = 1
            break

    domain_name = parts[-2] if len(parts) >= 2 else hostname
    domain_name_length = len(domain_name)
    pct_numeric = round((num_digits / url_length * 100) if url_length > 0 else 0.0, 4)

    # NEW Feature 17: uses_free_hosting
    uses_free_hosting = 0
    hostname_lower = hostname.lower()
    for service in FREE_HOSTING_SERVICES + TUNNEL_SERVICES:
        if hostname_lower == service or hostname_lower.endswith("." + service):
            uses_free_hosting = 1
            break
    if "sites.google.com/view" in url.lower():
        uses_free_hosting = 1

    # NEW Feature 18: brand_in_path
    brand_in_path = 0
    registered_domain = parts[-2].lower() if len(parts) >= 2 else hostname_lower
    subdomains = ".".join(parts[:-2]).lower() if len(parts) > 2 else ""
    search_space = subdomains + " " + path.lower()
    for brand in KNOWN_BRANDS:
        if brand in search_space and brand not in registered_domain:
            brand_in_path = 1
            break

    return {
        "url_length": url_length,
        "has_ip_address": has_ip,
        "dot_count": dot_count,
        "https_flag": https_flag,
        "url_entropy": url_entropy,
        "token_count": token_count,
        "subdomain_count": subdomain_count,
        "query_param_count": query_param_count,
        "tld_length": tld_length,
        "path_length": path_length,
        "has_hyphen_in_domain": has_hyphen,
        "number_of_digits": num_digits,
        "tld_popularity": tld_popularity,
        "suspicious_file_extension": suspicious_ext,
        "domain_name_length": domain_name_length,
        "percentage_numeric_chars": pct_numeric,
        "uses_free_hosting": uses_free_hosting,
        "brand_in_path": brand_in_path,
    }


# ── URL Generators ─────────────────────────────────────────────────────

def generate_legitimate_url():
    """Generate a legitimate-looking URL with realistic features."""
    domain = random.choice(LEGIT_DOMAINS)
    tld = random.choice(POPULAR_TLDS)

    sub_count = random.choices([0, 1], weights=[0.6, 0.4])[0]
    subs = "www." if sub_count == 1 else ""

    scheme = random.choices(["https://", "http://"], weights=[0.9, 0.1])[0]

    path_words = random.choices(
        ["about", "contact", "products", "services", "blog", "help", "docs",
         "pricing", "features", "team", "careers", "privacy", "terms"],
        k=random.randint(0, 3)
    )
    path = "/" + "/".join(path_words) if path_words else ""

    qp_count = random.choices([0, 1], weights=[0.7, 0.3])[0]
    query = ""
    if qp_count > 0:
        query = "?ref=" + "".join(random.choices(string.ascii_lowercase, k=4))

    url = f"{scheme}{subs}{domain}.{tld}{path}{query}"
    return url


def generate_traditional_phishing_url():
    """Generate traditional phishing URL (typosquat, IP-based, suspicious path)."""
    strategy = random.choices(
        ["typosquat", "ip_based", "long_subdomain", "suspicious_path", "mixed"],
        weights=[0.25, 0.15, 0.2, 0.2, 0.2]
    )[0]

    scheme = random.choices(["https://", "http://"], weights=[0.4, 0.6])[0]

    if strategy == "ip_based":
        ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        path_parts = random.choices(SUSPICIOUS_WORDS, k=random.randint(1, 3))
        ext = random.choice(SUSPICIOUS_EXTS + ["", "", ""])
        path = "/" + "/".join(path_parts) + ext
        qp = ""
        if random.random() > 0.5:
            qp = "?id=" + "".join(random.choices(string.digits, k=random.randint(4, 12)))
        return f"{scheme}{ip}{path}{qp}"

    if strategy == "typosquat":
        base = random.choice(LEGIT_DOMAINS)
        typo_methods = [
            lambda s: s + random.choice(["s", "1", "l", "0", "-secure"]),
            lambda s: s[:len(s)//2] + random.choice(["0", "1"]) + s[len(s)//2+1:],
            lambda s: s + "-" + random.choice(SUSPICIOUS_WORDS),
        ]
        domain = random.choice(typo_methods)(base)
        tld = random.choice(UNCOMMON_TLDS + POPULAR_TLDS[:3])
    elif strategy == "long_subdomain":
        words = random.choices(SUSPICIOUS_WORDS, k=random.randint(2, 4))
        domain = random.choice(LEGIT_DOMAINS)
        subs = ".".join(words)
        tld = random.choice(POPULAR_TLDS[:5] + UNCOMMON_TLDS[:5])
        path_words = random.choices(SUSPICIOUS_WORDS, k=random.randint(1, 2))
        ext = random.choice(SUSPICIOUS_EXTS + ["", ""])
        path = "/" + "/".join(path_words) + ext
        qp = ""
        if random.random() > 0.4:
            qp = "?token=" + "".join(random.choices(string.hexdigits, k=random.randint(8, 24)))
        return f"{scheme}{subs}.{domain}.{tld}{path}{qp}"
    elif strategy == "suspicious_path":
        domain = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 16)))
        tld = random.choice(UNCOMMON_TLDS)
    else:  # mixed
        words = random.choices(SUSPICIOUS_WORDS, k=random.randint(1, 3))
        domain = "-".join(words) + str(random.randint(1, 999))
        tld = random.choice(UNCOMMON_TLDS)

    path_words = random.choices(SUSPICIOUS_WORDS + ["download", "reset", "recovery"], k=random.randint(1, 4))
    ext = random.choice(SUSPICIOUS_EXTS + ["", "", "", ""])
    path = "/" + "/".join(path_words) + ext

    qp_count = random.randint(0, 3)
    qp_parts = []
    for _ in range(qp_count):
        key = random.choice(["id", "token", "user", "session", "ref", "redirect", "code"])
        val = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(4, 20)))
        qp_parts.append(f"{key}={val}")
    query = "?" + "&".join(qp_parts) if qp_parts else ""

    sub_count = random.choices([0, 1, 2], weights=[0.4, 0.3, 0.3])[0]
    subs = ""
    if sub_count > 0:
        sub_words = random.choices(SUSPICIOUS_WORDS[:8] + ["www", "secure", "mail"], k=sub_count)
        subs = ".".join(sub_words) + "."

    return f"{scheme}{subs}{domain}.{tld}{path}{query}"


def generate_zphisher_url():
    """
    Generate a realistic zphisher/modern-toolkit phishing URL.

    These URLs are HTTPS, use popular TLDs, and look structurally clean
    but host phishing pages on free/tunnel services — bypassing traditional
    URL feature checks. This is the primary gap in the old training data.

    Patterns covered:
        - ngrok tunnel: https://<random>.ngrok-free.app/facebook/login
        - loca.lt tunnel: https://<random>.loca.lt/
        - 000webhost: https://facebook-login.<random>.000webhostapp.com/
        - Google Sites: https://sites.google.com/view/faceb00k-secure/
        - Glitch/Replit: https://<project>.glitch.me/instagram/verify
        - Brand in subdomain: https://facebook.<random>.000webhostapp.com/
    """
    brand = random.choice(KNOWN_BRANDS)
    strategy = random.choices(
        ["ngrok", "loca_lt", "000webhost_sub", "google_sites", "glitch", "free_host_path"],
        weights=[0.20, 0.15, 0.20, 0.15, 0.15, 0.15]
    )[0]

    path_parts = random.choices(
        [brand, "login", "verify", "account", "secure", "signin", "update", "confirm"],
        k=random.randint(1, 3)
    )
    path = "/" + "/".join(path_parts)
    qp = ""
    if random.random() > 0.5:
        key = random.choice(["token", "ref", "id", "session"])
        val = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 20)))
        qp = f"?{key}={val}"

    rand_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 14)))

    if strategy == "ngrok":
        service = random.choice(["ngrok-free.app", "ngrok.app", "ngrok.io"])
        url = f"https://{rand_id}.{service}{path}{qp}"

    elif strategy == "loca_lt":
        url = f"https://{rand_id}.loca.lt{path}{qp}"

    elif strategy == "000webhost_sub":
        # e.g. https://facebook-login.000webhostapp.com/
        subdomain = brand + "-" + random.choice(["login", "secure", "verify", "account"])
        url = f"https://{subdomain}.000webhostapp.com{path}{qp}"

    elif strategy == "google_sites":
        # Misspelled brand in path
        misspelled = brand.replace("a", "4").replace("o", "0").replace("e", "3") if len(brand) > 3 else brand + "-login"
        url = f"https://sites.google.com/view/{misspelled}-{rand_id}{path}{qp}"

    elif strategy == "glitch":
        service = random.choice(["glitch.me", "replit.app", "repl.co"])
        project = rand_id + "-" + random.choice(["app", "page", "site", "web"])
        url = f"https://{project}.{service}{path}{qp}"

    else:  # free_host_path
        service = random.choice(FREE_HOSTING_SERVICES)
        # Brand in path, random domain
        url = f"https://{rand_id}.{service}/{brand}/login{qp}"

    return url


def generate_phishing_url():
    """Generate a phishing URL — either traditional or zphisher-style."""
    # 40% of phishing URLs are modern zphisher-style
    if random.random() < 0.40:
        return generate_zphisher_url()
    return generate_traditional_phishing_url()


# ── Dataset generation ─────────────────────────────────────────────────

def generate_dataset(n_total=6000, phishing_ratio=0.45):
    """Generate the full dataset with 18 features."""
    n_phishing = int(n_total * phishing_ratio)
    n_legit = n_total - n_phishing

    rows = []

    print(f"Generating {n_legit} legitimate URLs...")
    for _ in range(n_legit):
        url = generate_legitimate_url()
        features = extract_features_from_url(url)
        rows.append({"URL": url, **features, "ClassLabel": 1})  # 1 = legitimate

    print(f"Generating {n_phishing} phishing URLs ({int(n_phishing*0.4)} zphisher-style)...")
    for _ in range(n_phishing):
        url = generate_phishing_url()
        features = extract_features_from_url(url)
        rows.append({"URL": url, **features, "ClassLabel": 0})  # 0 = phishing

    random.shuffle(rows)
    return rows


def save_dataset(rows, path=OUTPUT_PATH):
    """Save to CSV."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Dataset saved: {path} ({len(rows)} rows)")


if __name__ == "__main__":
    if os.path.exists(OUTPUT_PATH):
        print(f"Removing old dataset: {OUTPUT_PATH}")
        os.remove(OUTPUT_PATH)

    rows = generate_dataset(n_total=6000, phishing_ratio=0.45)
    save_dataset(rows)
    print("Done!")
