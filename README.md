# Phishing URL & Email Indicator Detector

A Python tool that analyzes URLs or raw email content for common phishing red flags and produces a weighted risk score with a clear explanation of each flag found.

## Why I Built This

Phishing remains the #1 initial attack vector in most breaches. This project shows practical understanding of the technical indicators analysts look for — typosquatting, suspicious TLDs, link shorteners, urgency language, and sender/domain mismatches — rather than just knowing phishing exists in theory.

## Features

- Analyzes standalone URLs **or** full raw email text
- Detects IP-based URLs, URL shorteners, suspicious TLDs, excessive subdomains, `@` symbol tricks, and missing HTTPS
- Flags brand impersonation / typosquatting (e.g. `paypa1-secure-login.tk`)
- Scans email body for urgency/pressure language commonly used in social engineering
- Detects "From" header mismatches (claims to be a brand but domain doesn't match)
- Produces a weighted 0–100 risk score with a clear verdict

## Technologies Used

- Python 3
- `re` (regex) for pattern matching
- `urllib.parse` for URL parsing
- `argparse` for CLI arguments

## How to Run

```bash
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector

# Analyze a single URL
python phishing_detector.py --url "http://paypa1-secure-login.tk/verify"

# Analyze a full email (raw text/headers)
python phishing_detector.py --email sample_phishing_email.txt
```

A sample phishing email (`sample_phishing_email.txt`) is included so you can test it right away.

## Sample Output

```
=================================================================
 Phishing Indicator Report: sample_phishing_email.txt
=================================================================
[+100] Contains urgency/pressure language: ['verify your account', 'urgent', ...]
[+ 15] Domain uses a TLD commonly abused in phishing (.tk, .xyz, etc.)
[+ 10] URL does not use HTTPS
[+ 10] Domain contains multiple hyphens (common in spoofed domains)
[+ 25] 'From' header mentions 'paypal' but sending domain looks different
-----------------------------------------------------------------
 Risk Score: 100/100
 Verdict:    HIGH RISK — likely phishing
=================================================================
```

## How the Scoring Works

Each red flag adds weighted points (10–30) based on how strong an indicator it typically is. For example, a domain containing a brand name that doesn't match the real brand's domain (typosquatting) is weighted heavily (30 points), while a missing HTTPS alone is a weaker signal (10 points). Scores are capped at 100.

| Score Range | Verdict |
|---|---|
| 60–100 | HIGH RISK — likely phishing |
| 30–59 | MEDIUM RISK — treat with caution |
| 1–29 | LOW RISK — minor flags found |
| 0 | No flags detected |

## What I Learned

- The specific technical patterns behind typosquatting and lookalike domains
- How phishing emails combine multiple weak signals (urgency + suspicious link + spoofed sender) into a strong overall signal
- How to design a transparent, explainable scoring system rather than a black-box "yes/no" classifier
- Why real-world phishing detection also needs sender reputation and ML — this tool covers the static/heuristic layer

## Future Improvements

- Add domain age lookup (via WHOIS) — brand-new domains are a strong phishing signal
- Cross-check URLs against a live threat intelligence feed (e.g. Google Safe Browsing API)
- Parse actual `.eml` files instead of plain text
- Add a similarity check (Levenshtein distance) between domains and known brand names to catch subtler typosquats
