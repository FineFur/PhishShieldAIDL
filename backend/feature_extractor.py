"""
PhishShield AI - URL Feature Extractor

Extracts exactly 18 engineered features from a URL string for model inference.
These features match the training dataset columns exactly.

IMPORTANT: This module performs STATIC URL string analysis only.
It does NOT visit, crawl, or request the target website.

Features extracted:
    1.  url_length              - Total length of the URL string
    2.  has_ip_address          - Whether URL contains an IP address (1/0)
    3.  dot_count               - Number of dots in the URL
    4.  https_flag              - Whether URL uses HTTPS (1/0)
    5.  url_entropy             - Shannon entropy of the URL string
    6.  token_count             - Number of tokens (split by delimiters)
    7.  subdomain_count         - Number of subdomains
    8.  query_param_count       - Number of query parameters
    9.  tld_length              - Length of the top-level domain
    10. path_length             - Length of the URL path
    11. has_hyphen_in_domain    - Whether domain contains a hyphen (1/0)
    12. number_of_digits        - Count of digit characters in URL
    13. tld_popularity          - Popularity score of the TLD (1=popular, 0=uncommon)
    14. suspicious_file_extension - Whether URL ends with suspicious extension (1/0)
    15. domain_name_length      - Length of the domain name (without TLD)
    16. percentage_numeric_chars - Percentage of numeric characters in URL
    17. uses_free_hosting       - Whether URL uses a known free/tunnel hosting service (1/0)
    18. brand_in_path           - Whether a well-known brand name appears in path/subdomain (1/0)
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter


# ── Popular TLDs (commonly used by legitimate websites) ────────────────
POPULAR_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int",
    "co", "io", "ai", "dev", "app", "me", "info",
    "us", "uk", "ca", "au", "de", "fr", "jp", "in",
    "br", "ru", "cn", "it", "es", "nl", "se", "no",
    "fi", "dk", "pl", "cz", "at", "ch", "be", "pt",
    "ie", "nz", "za", "mx", "ar", "cl", "co.uk",
    "co.in", "com.au", "com.br", "co.jp",
}

# ── Suspicious file extensions ─────────────────────────────────────────
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".zip", ".rar", ".bat", ".cmd", ".scr", ".msi",
    ".js", ".vbs", ".ps1", ".jar", ".apk", ".php", ".cgi",
    ".asp", ".aspx", ".jsp", ".action",
}

# ── Free / Tunneling hosting services abused by phishing tools (e.g. zphisher) ──
FREE_HOSTING_DOMAINS = {
    # Tunneling / ngrok-style
    "ngrok.io", "ngrok-free.app", "ngrok.app",
    "loca.lt", "localxpose.io", "serveo.net",
    "cloudflared.com", "trycloudflare.com",
    "pagekite.me", "bore.pub",
    # Free web hosts
    "000webhostapp.com", "000webhost.com",
    "infinityfreeapp.com", "epizy.com",
    "byethost.com", "freewebhostingarea.com",
    "atwebpages.com", "wix.com", "weebly.com",
    # Google / GitHub pages (commonly abused)
    "sites.google.com", "pages.github.io",
    "glitch.me", "replit.app", "repl.co",
    # Shortened / redirectors used with phishing
    "bit.ly", "tinyurl.com", "t.co", "ow.ly",
    "rebrand.ly", "cutt.ly", "is.gd", "v.gd",
}

# ── Well-known brands whose names should NOT appear in path/subdomain ──
KNOWN_BRANDS = {
    "facebook", "fb", "instagram", "whatsapp", "messenger",
    "google", "gmail", "youtube", "googlemail",
    "apple", "icloud", "itunes", "appstore",
    "microsoft", "outlook", "hotmail", "office365", "onedrive",
    "paypal", "ebay", "amazon", "netflix",
    "twitter", "linkedin", "snapchat", "tiktok",
    "bank", "banking", "wellsfargo", "chase", "citibank",
    "hdfc", "icici", "sbi", "paytm",
}


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher entropy suggests more randomness (common in phishing URLs).
    """
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def check_ip_address(url: str) -> int:
    """
    Check if the URL contains an IP address instead of a domain name.
    Detects both IPv4 and hexadecimal IP representations.
    Returns 1 if IP found, 0 otherwise.
    """
    # IPv4 pattern
    ipv4_pattern = r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    # Hexadecimal IP pattern (e.g., 0x41.0x42.0x43.0x44)
    hex_pattern = r'(?:0[xX][0-9a-fA-F]+\.){3}0[xX][0-9a-fA-F]+'

    if re.search(ipv4_pattern, url) or re.search(hex_pattern, url):
        return 1
    return 0


def count_tokens(url: str) -> int:
    """
    Count the number of tokens in the URL.
    Tokens are separated by common URL delimiters: / . - _ ? = & @
    """
    tokens = re.split(r'[/.\-_?=&@:]+', url)
    return len([t for t in tokens if t])


def count_subdomains(url: str) -> int:
    """
    Count the number of subdomains in the URL.
    e.g., 'sub1.sub2.example.com' has 2 subdomains (sub1, sub2).
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        parts = hostname.split(".")

        # Need at least domain.tld (2 parts)
        if len(parts) <= 2:
            return 0

        # Handle common two-part TLDs like co.uk, com.au
        two_part_tlds = {"co.uk", "com.au", "co.in", "com.br", "co.jp",
                         "co.nz", "co.za", "com.mx", "com.ar", "org.uk",
                         "net.au", "ac.uk", "gov.uk"}
        tld_check = ".".join(parts[-2:])
        if tld_check in two_part_tlds:
            return max(0, len(parts) - 3)

        return len(parts) - 2
    except Exception:
        return 0


def count_query_params(url: str) -> int:
    """Count the number of query parameters in the URL."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return len(params)
    except Exception:
        return 0


def get_tld(url: str) -> str:
    """Extract the top-level domain from the URL."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        parts = hostname.split(".")
        if len(parts) >= 2:
            return parts[-1]
        return ""
    except Exception:
        return ""


def get_tld_popularity(tld: str) -> int:
    """
    Return 1 if the TLD is popular/common, 0 otherwise.
    Based on a curated list of well-known TLDs.
    """
    return 1 if tld.lower() in POPULAR_TLDS else 0


def check_suspicious_extension(url: str) -> int:
    """
    Check if the URL path ends with a suspicious file extension.
    Returns 1 if suspicious, 0 otherwise.
    """
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        for ext in SUSPICIOUS_EXTENSIONS:
            if path.endswith(ext):
                return 1
        return 0
    except Exception:
        return 0


def get_domain_name_length(url: str) -> int:
    """
    Get the length of the domain name (excluding TLD and subdomains).
    For 'www.example.com', this returns len('example') = 7.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        parts = hostname.split(".")

        if len(parts) >= 2:
            # Handle two-part TLDs
            two_part_tlds = {"co.uk", "com.au", "co.in", "com.br", "co.jp",
                             "co.nz", "co.za", "com.mx", "com.ar"}
            tld_check = ".".join(parts[-2:])
            if tld_check in two_part_tlds and len(parts) >= 3:
                return len(parts[-3])
            return len(parts[-2])
        elif len(parts) == 1:
            return len(parts[0])
        return 0
    except Exception:
        return 0


def check_hyphen_in_domain(url: str) -> int:
    """
    Check if the domain name contains a hyphen.
    Phishing URLs sometimes use hyphens to mimic legitimate domains.
    Returns 1 if hyphen found, 0 otherwise.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        # Get the main domain part
        parts = hostname.split(".")
        if len(parts) >= 2:
            domain = parts[-2]
        else:
            domain = hostname
        return 1 if "-" in domain else 0
    except Exception:
        return 0


def check_free_hosting(url: str) -> int:
    """
    Check if the URL uses a known free or tunneling hosting service
    that is commonly abused by phishing toolkits like zphisher.
    Returns 1 if detected, 0 otherwise.
    """
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        full_url_lower = url.lower()

        # Direct hostname match or suffix match
        for domain in FREE_HOSTING_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                return 1

        # Special case: sites.google.com/view/* is the Google Sites phishing pattern
        if "sites.google.com/view" in full_url_lower:
            return 1

        return 0
    except Exception:
        return 0


def check_brand_in_path(url: str) -> int:
    """
    Check if a well-known brand name appears in the URL path or subdomain
    when that brand is NOT the actual domain owner.

    e.g.  https://facebook-login.000webhostapp.com/  -> brand 'facebook' in subdomain
          https://abc.ngrok.io/facebook/login        -> brand 'facebook' in path

    Returns 1 if a brand name is found in a suspicious position, 0 otherwise.
    """
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        parts = hostname.split(".")

        # The actual registered domain (second-to-last part)
        registered_domain = parts[-2] if len(parts) >= 2 else hostname

        # Check subdomains (everything before the registered domain)
        subdomains = ".".join(parts[:-2]) if len(parts) > 2 else ""

        # Check path
        search_space = subdomains + " " + path

        for brand in KNOWN_BRANDS:
            # Brand in subdomain or path, but not the registered domain itself
            if brand in search_space and brand not in registered_domain:
                return 1
        return 0
    except Exception:
        return 0


def extract_url_features(url: str) -> dict:
    """
    Extract all 18 features from a URL string.

    Returns a dictionary with feature names as keys matching
    the exact column names used during model training.

    IMPORTANT: Feature names and definitions must match the training dataset.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    tld = get_tld(url)

    # Count digits in full URL
    digit_count = sum(1 for c in url if c.isdigit())
    url_len = len(url)

    features = {
        "url_length": url_len,
        "has_ip_address": check_ip_address(url),
        "dot_count": url.count("."),
        "https_flag": 1 if parsed.scheme.lower() == "https" else 0,
        "url_entropy": calculate_entropy(url),
        "token_count": count_tokens(url),
        "subdomain_count": count_subdomains(url),
        "query_param_count": count_query_params(url),
        "tld_length": len(tld),
        "path_length": len(path),
        "has_hyphen_in_domain": check_hyphen_in_domain(url),
        "number_of_digits": digit_count,
        "tld_popularity": get_tld_popularity(tld),
        "suspicious_file_extension": check_suspicious_extension(url),
        "domain_name_length": get_domain_name_length(url),
        "percentage_numeric_chars": round(
            (digit_count / url_len * 100) if url_len > 0 else 0.0, 4
        ),
        "uses_free_hosting": check_free_hosting(url),
        "brand_in_path": check_brand_in_path(url),
    }

    return features


if __name__ == "__main__":
    # Quick test
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.10/login.php",
        "https://secure-login-example.com/account/verify",
        "http://1234567890.suspicious-site.xyz/free-iphone.exe?user=test&ref=abc",
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        features = extract_url_features(url)
        for k, v in features.items():
            print(f"  {k}: {v}")
