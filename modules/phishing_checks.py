import requests
import ssl
import socket
import difflib
import dns.resolver
import re
import time
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime, timezone

TRUSTED_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "openai.com", "amazon.com",
    "facebook.com", "youtube.com", "wikipedia.org", "instagram.com",
    "apple.com", "paypal.com", "netflix.com"
]

LEET_TRANS = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '@': 'a', '$': 's'})

_blacklist_cache = {"data": set(), "last_updated": 0}


def get_cached_blacklist():
    now = time.time()
    if now - _blacklist_cache["last_updated"] > 3600 or not _blacklist_cache["data"]:
        urls = set()
        for source in ["https://openphish.com/feed.txt", "https://urlhaus.abuse.ch/downloads/text/"]:
            try:
                response = requests.get(source, timeout=5)
                if response.status_code == 200:
                    for line in response.text.splitlines():
                        bad_url = line.strip().lower()
                        if bad_url and not bad_url.startswith("#"):
                            urls.add(bad_url)
            except Exception as e:
                print("BLACKLIST FETCH ERROR:", e)
        _blacklist_cache["data"] = urls
        _blacklist_cache["last_updated"] = now
    return _blacklist_cache["data"]


def check_blacklist(url):
    try:
        return url.strip().lower() in get_cached_blacklist()
    except Exception:
        return False


def check_phishtank(url):
    return False


def check_ssl(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False


def dns_check(url):
    try:
        domain = urlparse(url).netloc or tldextract.extract(url).registered_domain
        if not domain:
            return False
        dns.resolver.resolve(domain, "A")
        return True
    except Exception:
        return False


def get_domain_age_years(domain):
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=2)
        data = response.json()
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                creation_date = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                return round((datetime.now(timezone.utc) - creation_date).days / 365, 1)
    except Exception as e:
        print("RDAP ERROR:", e)
    return None


def get_domain_age(domain):
    age_years = get_domain_age_years(domain)
    return f"{age_years} years" if age_years is not None else "Not Available"


def extract_features(url):
    features = []
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix if ext.suffix else ext.domain
    response, soup, html, redirect_history = None, None, "", []
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        html = response.text.lower()
        soup = BeautifulSoup(response.text, "html.parser")
        redirect_history = response.history
    except Exception:
        pass
    age_years = get_domain_age_years(domain)
    ssl_valid = check_ssl(url)
    has_ip = bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))
    features.append(-1 if has_ip else 1)
    features.append(1 if len(url) < 54 else (0 if len(url) <= 75 else -1))
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly"]
    features.append(-1 if any(s in url.lower() for s in shorteners) else 1)
    features.append(-1 if "@" in url else 1)
    features.append(-1 if url[8:].find("//") != -1 else 1)
    features.append(-1 if "-" in ext.domain else 1)
    subdomains = [s for s in ext.subdomain.split(".") if s and s.lower() != "www"]
    features.append(1 if len(subdomains) == 0 else (0 if len(subdomains) == 1 else -1))
    if parsed.scheme == "https" and ssl_valid:
        features.append(1 if age_years is not None and age_years >= 1.0 else 0)
    else:
        features.append(-1)
    features.append(1 if age_years is not None and age_years >= 1.0 else -1)
    if soup:
        fav = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        features.append(-1 if fav and fav.get("href") and fav.get("href").startswith("http") and domain not in fav.get("href") else 1)
    else:
        features.append(0)
    features.append(1 if parsed.port is None or parsed.port in [80, 443] else -1)
    features.append(-1 if "https" in ext.domain.lower() else 1)
    if soup:
        total = external = 0
        for tag in soup.find_all(["img", "audio", "embed", "iframe"]):
            src = tag.get("src")
            if src:
                total += 1
                if src.startswith("http") and domain not in src:
                    external += 1
        features.append(1 if total == 0 else (1 if external / total < 0.22 else (0 if external / total <= 0.61 else -1)))
    else:
        features.append(0)
    if soup:
        anchors = soup.find_all("a")
        total, unsafe = len(anchors), 0
        for a in anchors:
            href = a.get("href")
            if href and (href.startswith("#") or href.lower().startswith("javascript") or (href.startswith("http") and domain not in href)):
                unsafe += 1
        features.append(1 if total == 0 else (1 if unsafe / total < 0.31 else (0 if unsafe / total <= 0.67 else -1)))
    else:
        features.append(0)
    if soup:
        tags = soup.find_all(["meta", "script", "link"])
        total = len(tags)
        external = sum(1 for tag in tags if (tag.get("src") or tag.get("href")) and (tag.get("src") or tag.get("href")).startswith("http") and domain not in (tag.get("src") or tag.get("href")))
        features.append(1 if total == 0 else (1 if external / total < 0.17 else (0 if external / total <= 0.81 else -1)))
    else:
        features.append(0)
    if soup:
        forms = soup.find_all("form")
        if not forms:
            features.append(1)
        else:
            action = forms[0].get("action")
            features.append(-1 if not action or action == "" or action == "about:blank" else (0 if action.startswith("http") and domain not in action else 1))
    else:
        features.append(0)
    if soup:
        found = any("mailto:" in str(form.get("action")).lower() or "mail(" in str(form.get("action")).lower() for form in soup.find_all("form"))
        features.append(-1 if found else 1)
    else:
        features.append(1)
    hostname = parsed.hostname or ""
    features.append(1 if domain in hostname else -1)
    features.append(1 if response is not None and len(redirect_history) <= 1 else (0 if response is not None and len(redirect_history) <= 3 else (-1 if response is not None else 0)))
    features.append(-1 if response is not None and "onmouseover" in html and "status" in html else (1 if response is not None else 0))
    features.append(-1 if response is not None and ("event.button==2" in html or "event.button == 2" in html) else (1 if response is not None else 0))
    features.append(-1 if response is not None and "prompt(" in html and "form" in html else (1 if response is not None else 0))
    if soup:
        hidden = any(i.get("style") and ("display:none" in i.get("style").lower() or "visibility:hidden" in i.get("style").lower()) for i in soup.find_all("iframe"))
        features.append(-1 if hidden else 1)
    else:
        features.append(1)
    features.append(1 if age_years is not None and age_years >= 0.5 else (0 if age_years is None else -1))
    dns_ok = dns_check(url)
    features.append(1 if dns_ok else -1)
    features.extend([1 if domain in TRUSTED_DOMAINS else 0, 1 if domain in TRUSTED_DOMAINS else 0, 1 if dns_ok else -1, 1 if domain in TRUSTED_DOMAINS else 0])
    features.append(-1 if check_blacklist(url) or has_ip else 1)
    return features


def reputation_check(url):
    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix if ext.suffix else ext.domain
    for trusted in TRUSTED_DOMAINS:
        if trusted in domain:
            return "Trusted"
    suspicious_score = sum(1 for word in ["login", "verify", "secure", "bank", "update", "reward", "gift"] if word in url.lower())
    return "Suspicious" if suspicious_score >= 2 else "Unknown"


def check_brand_impersonation(url):
    trusted_brands = ["google", "paypal", "amazon", "microsoft", "facebook", "github", "apple", "instagram", "netflix"]
    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix if ext.suffix else ext.domain
    if domain in TRUSTED_DOMAINS:
        return False
    norm_domain = ext.domain.lower().translate(LEET_TRANS).replace("-", "")
    for brand in trusted_brands:
        if brand in norm_domain or difflib.SequenceMatcher(None, norm_domain, brand).ratio() >= 0.70:
            return True
    return False


def content_analysis(url, html=None, soup=None):
    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix if ext.suffix else ext.domain
    if domain in TRUSTED_DOMAINS:
        return [], 0
    risks, score = [], 0
    try:
        if html is None or soup is None:
            response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            html = response.text.lower()
            soup = BeautifulSoup(html, "html.parser")
        for word in ["verify your account", "update payment", "confirm identity", "login now", "urgent action", "claim reward", "password expired"]:
            if word in html:
                risks.append(f"Suspicious content: {word}")
                score += 10
        for form in soup.find_all("form"):
            action = form.get("action")
            if action and action.startswith("http") and domain not in action:
                risks.append("External Form Submission")
                score += 15
                break
    except Exception as e:
        print("CONTENT ANALYSIS ERROR:", e)
    return risks, score


def analyze_risk(url):
    risks, score = [], 0
    if "https" not in url:
        risks.append("No HTTPS encryption")
        score += 10
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly"]
    if any(s in url.lower() for s in shorteners):
        risks.append("URL Shortener Detected")
        score += 15
    if "@" in url:
        risks.append("Contains @ symbol")
        score += 20
    if url.count("-") >= 3:
        risks.append("Excessive hyphens in domain")
        score += 15
    for word in ["verify", "bank", "secure", "update", "payment", "confirm"]:
        if word in url.lower():
            risks.append(f"Suspicious keyword: {word}")
            score += 10
    if sum(c.isdigit() for c in url) >= 8:
        risks.append("Excessive numbers in URL")
        score += 15
    for tld in [".tk", ".xyz", ".top", ".gq", ".ml", ".cf"]:
        if tld in url.lower():
            risks.append(f"Suspicious extension: {tld}")
            score += 20
    return risks, score
