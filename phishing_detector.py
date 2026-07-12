"""
Phishing URL & Email Indicator Detector
-----------------------------------------
Analyzes a URL or raw email text for common phishing red flags and
produces a weighted risk score with an explanation of each flag.

This is a heuristic/educational tool, not a production-grade
detector. Real-world phishing detection uses ML models, threat
intel feeds, and sender reputation databases in addition to these
kinds of static checks.

Usage:
    python phishing_detector.py --url "http://paypa1-secure-login.tk/verify"
    python phishing_detector.py --email sample_email.txt
"""

import argparse
import re
import sys
from urllib.parse import urlparse

# Common URL shortener domains, often abused to hide the real destination
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"}

# TLDs frequently abused in phishing campaigns (cheap/free registration)
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"}

# Words commonly used to create urgency/pressure in phishing content
URGENCY_WORDS = [
    "verify your account", "urgent", "act now", "suspended", "immediately",
    "click here", "confirm your identity", "limited time", "unusual activity",
    "your account will be", "security alert", "reset your password",
]

# Brands commonly impersonated - used to detect lookalike/typosquat domains
COMMONLY_SPOOFED_BRANDS = [
    "paypal", "apple", "microsoft", "amazon", "netflix", "google",
    "bankofamerica", "wellsfargo", "chase", "facebook", "instagram",
]


def analyze_url(url):
    """Return a list of (flag_description, weight) tuples for a single URL."""
    flags = []
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.lower()
    full = url.lower()

    # 1. IP address used instead of a domain name
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(":")[0]):
        flags.append(("URL uses a raw IP address instead of a domain name", 25))

    # 2. Uses a known URL shortener
    if any(shortener in domain for shortener in URL_SHORTENERS):
        flags.append(("URL uses a link-shortening service (hides real destination)", 15))

    # 3. Suspicious/cheap TLD
    if any(full.endswith(tld) or tld + "/" in full for tld in SUSPICIOUS_TLDS):
        flags.append(("Domain uses a TLD commonly abused in phishing (.tk, .xyz, etc.)", 15))

    # 4. Excessive subdomains (e.g. paypal.com.security-check.ru)
    subdomain_count = domain.count(".")
    if subdomain_count >= 3:
        flags.append((f"Unusually high number of subdomains ({subdomain_count})", 15))

    # 5. '@' symbol in URL (browsers ignore everything before @ when connecting)
    if "@" in url:
        flags.append(("URL contains '@' symbol (can hide the real destination)", 25))

    # 6. Brand name present but NOT as the actual registered domain (typosquat pattern)
    for brand in COMMONLY_SPOOFED_BRANDS:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            flags.append((f"Contains brand name '{brand}' but domain doesn't match official site", 30))
            break

    # 7. No HTTPS
    if parsed.scheme == "http":
        flags.append(("URL does not use HTTPS", 10))

    # 8. Hyphens in domain (common in lookalike domains)
    if domain.count("-") >= 2:
        flags.append(("Domain contains multiple hyphens (common in spoofed domains)", 10))

    return flags


def analyze_email_text(text):
    """Scan raw email text for urgency language and embedded suspicious URLs."""
    flags = []
    lower_text = text.lower()

    matched_phrases = [phrase for phrase in URGENCY_WORDS if phrase in lower_text]
    if matched_phrases:
        flags.append((f"Contains urgency/pressure language: {matched_phrases}", 10 * len(matched_phrases)))

    urls_found = re.findall(r"https?://[^\s\"'<>]+|www\.[^\s\"'<>]+", text)
    for url in urls_found:
        flags.extend(analyze_url(url))

    # Check for mismatched display name vs actual sender domain (simple heuristic)
    from_match = re.search(r"From:\s*(.+)", text, re.IGNORECASE)
    if from_match:
        from_line = from_match.group(1)
        for brand in COMMONLY_SPOOFED_BRANDS:
            if brand in from_line.lower() and f"{brand}.com" not in from_line.lower():
                flags.append((f"'From' header mentions '{brand}' but sending domain looks different", 25))
                break

    return flags, urls_found


def score_to_verdict(score):
    if score >= 60:
        return "HIGH RISK — likely phishing"
    elif score >= 30:
        return "MEDIUM RISK — treat with caution"
    elif score > 0:
        return "LOW RISK — minor flags found"
    return "NO FLAGS DETECTED"


def print_report(subject, flags):
    print("=" * 65)
    print(f" Phishing Indicator Report: {subject}")
    print("=" * 65)

    if not flags:
        print(" No suspicious indicators found.")
    else:
        total_score = 0
        for description, weight in flags:
            print(f"[+{weight:3d}] {description}")
            total_score += weight
        total_score = min(total_score, 100)
        print("-" * 65)
        print(f" Risk Score: {total_score}/100")
        print(f" Verdict:    {score_to_verdict(total_score)}")
    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(description="Detect phishing indicators in a URL or email")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="A single URL to analyze")
    group.add_argument("--email", help="Path to a text file containing raw email content")
    args = parser.parse_args()

    if args.url:
        flags = analyze_url(args.url)
        print_report(args.url, flags)
    else:
        try:
            with open(args.email, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except FileNotFoundError:
            print(f"[!] File not found: {args.email}")
            sys.exit(1)

        flags, urls_found = analyze_email_text(content)
        print_report(args.email, flags)
        if urls_found:
            print(f"\n URLs found in email: {urls_found}")


if __name__ == "__main__":
    main()
