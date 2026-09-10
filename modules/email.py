"""
Email Phishing Detection Module
Preprocesses email content, runs BiLSTM DL model, scans URLs via existing ML pipeline.
"""

import re
from html import unescape
from bs4 import BeautifulSoup

from modules.email_model import predict_email_text
from modules.url_service import predict_url
from modules.phishing_checks import check_ssl, dns_check, reputation_check

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "password", "account suspended", "click here", "immediately",
    "wire transfer", "invoice", "payment overdue", "confirm identity", "security alert",
    "unusual activity", "login now", "update billing", "claim reward", "gift card",
    "crypto", "bitcoin", "refund", "tax", "locked", "expire", "credentials",
    "social security", "bank account", "wire payment", "limited time", "act now",
]

FREE_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.ru", "protonmail.com", "yandex.com", "icloud.com",
]

TRUSTED_SENDER_DOMAINS = [
    "google.com", "microsoft.com", "amazon.com", "apple.com", "paypal.com",
    "github.com", "linkedin.com", "facebook.com", "netflix.com",
]


def preprocess_email_text(text):
    """Lowercase, remove HTML, remove stopwords, tokenize-ready string."""
    text = unescape(str(text))
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.lower()
    text = re.sub(r"[^\w\s@.-]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    try:
        import nltk
        try:
            stops = set(nltk.corpus.stopwords.words("english"))
        except LookupError:
            nltk.download("stopwords", quiet=True)
            stops = set(nltk.corpus.stopwords.words("english"))
        words = [w for w in text.split() if w not in stops and len(w) > 1]
        text = " ".join(words)
    except Exception:
        pass
    return text


def extract_urls(text):
    """Extract all HTTP/HTTPS URLs from email body, subject, and HTML."""
    patterns = [
        r'https?://[^\s<>"\'\)\]]+',
        r'www\.[^\s<>"\'\)\]]+',
    ]
    urls = []
    for pattern in patterns:
        found = re.findall(pattern, str(text), re.IGNORECASE)
        for u in found:
            u = u.rstrip(".,;:!?)'\"")
            if not u.startswith("http"):
                u = "https://" + u
            if u not in urls:
                urls.append(u)
    return urls


def _extract_email_domain(email_address):
    """Return the domain part of an email address, or empty if invalid."""
    match = re.search(r"<?([^<>\s]+@[^<>\s]+)>?", str(email_address or "").strip())
    email_addr = match.group(1) if match else str(email_address or "").strip()
    if "@" not in email_addr:
        return ""
    return email_addr.rsplit("@", 1)[-1].lower()


def analyze_sender(sender_email, reply_to=None):
    """Analyze sender email for spoofing and reputation signals."""
    sender = sender_email.strip().lower()
    reply_to = (reply_to or "").strip().lower()
    sender_domain = _extract_email_domain(sender)
    reply_to_domain = _extract_email_domain(reply_to)
    analysis = {
        "sender": sender,
        "reply_to": reply_to,
        "domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "reply_to_mismatch": bool(sender_domain and reply_to_domain and sender_domain != reply_to_domain),
        "sender_missing": not bool(sender_domain),
        "reply_to_missing": bool(reply_to and not reply_to_domain),
        "is_free_provider": False,
        "is_trusted_domain": False,
        "display_name_mismatch": False,
        "risks": [],
        "score": 0,
    }
    if not sender_domain:
        analysis["risks"].append("From address is missing or invalid")
        analysis["score"] += 30
        return analysis

    if sender_domain in FREE_EMAIL_DOMAINS:
        analysis["is_free_provider"] = True
        analysis["risks"].append(f"Sender uses free email provider ({sender_domain})")
        analysis["score"] += 10

    trusted = any(t in sender_domain for t in TRUSTED_SENDER_DOMAINS)
    analysis["is_trusted_domain"] = trusted

    if re.search(r"paypal|amazon|microsoft|apple|google|bank|netflix", sender.split("@", 1)[0]) and not trusted:
        analysis["risks"].append("Sender is impersonating a trusted brand on a non-official domain")
        analysis["score"] += 25

    if re.search(r"\d{3,}", sender.split("@", 1)[0]):
        analysis["risks"].append("Sender address contains suspicious numeric patterns")
        analysis["score"] += 10

    if len(sender.split("@", 1)[0]) > 30:
        analysis["risks"].append("Unusually long sender local-part")
        analysis["score"] += 5

    if analysis["reply_to_mismatch"]:
        analysis["risks"].append("Reply-To domain mismatch")
        analysis["score"] += 25

    if reply_to and not reply_to_domain:
        analysis["risks"].append("Reply-To address is invalid")
        analysis["score"] += 15

    return analysis


def find_suspicious_keywords(text):
    text_lower = text.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
    return found


def analyze_email(sender, subject, body, attachments=None, embedded_urls=None, reply_to=None):
    """
    Full email phishing analysis pipeline.
    Combines BiLSTM, URL ML, reputation, SSL, domain checks.
    """
    attachments = attachments or []
    raw_combined = f"{subject} {body}".strip()
    preprocessed = preprocess_email_text(raw_combined)

    if not preprocessed:
        return {
            "verdict": "safe",
            "display": " Safe Email",
            "confidence": 100.0,
            "risk_score": 0.0,
            "dl_result": {
                "prediction": 0,
                "phishing_probability": 0.0,
                "safe_probability": 1.0,
                "confidence": 100.0,
            },
            "suspicious_keywords": [],
            "suspicious_urls": [],
            "extracted_urls": [],
            "url_results": [],
            "sender_analysis": analyze_sender(sender),
            "risks": [],
            "heuristic_score": 0,
            "preprocessed_preview": "",
            "ssl_failures": [],
            "dns_failures": [],
            "low_reputation": [],
        }

    # BiLSTM Deep Learning prediction
    dl_result = predict_email_text(preprocessed)
    dl_phishing_conf = dl_result["phishing_probability"] * 100

    # Extract URLs automatically
    all_urls = extract_urls(raw_combined)
    if embedded_urls:
        for u in embedded_urls:
            u = u.strip()
            if u and u not in all_urls:
                all_urls.append(u if u.startswith("http") else "https://" + u)

    # Scan each URL with existing Flask ML model + SSL/DNS/Reputation checks
    url_results = []
    suspicious_urls = []
    max_url_risk = 0
    ssl_failures = []
    dns_failures = []
    low_reputation = []
    
    for url in all_urls[:5]:
        try:
            res = predict_url(url)
            url_results.append(res)
            
            # Additional SSL/DNS/Reputation checks
            ssl_valid = check_ssl(url)
            dns_valid = dns_check(url)
            reputation = reputation_check(url)
            
            if not ssl_valid:
                ssl_failures.append(url)
            if not dns_valid:
                dns_failures.append(url)
            if reputation == "Unknown":
                low_reputation.append(url)
            
            if res["verdict"] == "phishing":
                suspicious_urls.append({
                    "url": url, 
                    "confidence": res["confidence"], 
                    "risks": res["risks"][:3],
                    "ssl_valid": ssl_valid,
                    "dns_valid": dns_valid,
                    "reputation": reputation
                })
            max_url_risk = max(max_url_risk, res["risk_score"])
        except Exception as e:
            print(f"URL scan error for {url}: {e}")

    # Sender analysis
    sender_analysis = analyze_sender(sender)

    # Suspicious keywords
    suspicious_kws = find_suspicious_keywords(raw_combined)

    # Heuristic scoring
    risks = list(sender_analysis["risks"])
    heuristic_score = sender_analysis["score"]

    if suspicious_kws:
        risks.append(f"Suspicious keywords detected: {', '.join(suspicious_kws[:5])}")
        heuristic_score += min(len(suspicious_kws) * 5, 30)

    if attachments:
        risky_ext = [a for a in attachments if re.search(r"\.(exe|scr|bat|cmd|js|vbs|zip|rar|iso)$", a, re.I)]
        if risky_ext:
            risks.append(f"Risky attachments: {', '.join(risky_ext)}")
            heuristic_score += 25

    if suspicious_urls:
        risks.append(f"{len(suspicious_urls)} phishing URL(s) found in email")
        heuristic_score += min(len(suspicious_urls) * 15, 45)

    if max_url_risk >= 50:
        heuristic_score += 20

    # SSL/DNS/Reputation integration
    if ssl_failures:
        risks.append(f"{len(ssl_failures)} URL(s) with invalid SSL certificates")
        heuristic_score += min(len(ssl_failures) * 10, 30)
    
    if dns_failures:
        risks.append(f"{len(dns_failures)} URL(s) with DNS resolution failures")
        heuristic_score += min(len(dns_failures) * 15, 40)
    
    if low_reputation:
        risks.append(f"{len(low_reputation)} URL(s) with low domain reputation")
        heuristic_score += min(len(low_reputation) * 8, 25)

    # Combined scoring: BiLSTM (40%) + URL ML (35%) + Heuristics (25%)
    combined_score = (
        dl_phishing_conf * 0.40 +
        max(max_url_risk, max((r["confidence"] for r in suspicious_urls), default=0)) * 0.35 +
        min(heuristic_score, 100) * 0.25
    )
    combined_score = min(round(combined_score, 2), 100.0)

    verdict = "phishing" if combined_score >= 50 else "safe"
    if suspicious_urls and max_url_risk >= 50:
        verdict = "phishing"

    confidence = combined_score if verdict == "phishing" else round(dl_result["safe_probability"] * 100, 2)
    confidence = min(max(confidence, combined_score), 100.0)

    display = "Phishing Email Detected!" if verdict == "phishing" else " Safe Email"

    scanned = {r["url"]: r for r in url_results}
    extracted_urls = []
    for url in all_urls:
        res = scanned.get(url)
        if res:
            extracted_urls.append({
                "url": res.get("url", url),
                "status": res.get("verdict", "unknown"),
                "risks": res.get("risks", []),
                "risk_score": res.get("risk_score", 0),
                "confidence": res.get("confidence", 0),
            })
        else:
            extracted_urls.append({
                "url": url,
                "status": "unknown",
                "risks": ["URL was not scanned"],
                "risk_score": 0,
                "confidence": 0,
            })

    return {
        "verdict": verdict,
        "display": display,
        "confidence": round(confidence, 2),
        "risk_score": round(combined_score, 2),
        "dl_result": dl_result,
        "suspicious_keywords": suspicious_kws,
        "suspicious_urls": suspicious_urls,
        "extracted_urls": extracted_urls,
        "url_results": url_results,
        "sender_analysis": sender_analysis,
        "risks": risks,
        "heuristic_score": min(heuristic_score, 100),
        "preprocessed_preview": preprocessed[:200] + ("..." if len(preprocessed) > 200 else ""),
        "ssl_failures": ssl_failures,
        "dns_failures": dns_failures,
        "low_reputation": low_reputation,
    }
