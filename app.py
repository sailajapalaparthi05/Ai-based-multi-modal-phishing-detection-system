print("APP.PY LOADED")
import sys
import io
import os
import tempfile
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
from flask import Flask, render_template, request, jsonify
import numpy as np
import joblib
import requests
import ssl
import socket
import whois
import difflib
import dns.resolver
import re
import time
import tldextract
import pandas as pd
import traceback
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime, timezone

# QR Code & Image Imports
try:
    import cv2
    cv2_available = True
except ImportError:
    cv2_available = False
    print("[!] OpenCV not available - QR scanning disabled")

try:
    import numpy as np
    np_available = True
except ImportError:
    np_available = False
    print("[!] NumPy not available - QR scanning disabled")

try:
    from pyzbar.pyzbar import decode, ZBarSymbol
    pyzbar_available = True
except (ImportError, FileNotFoundError, OSError) as e:
    pyzbar_available = False
    print(f"[!] pyzbar not available - using fallback QR detection: {e}")

try:
    import zxingcpp
    zxing_available = True
except ImportError:
    zxing_available = False
    print("[!] zxingcpp not available - using fallback QR detection")

from database import db_helper
import sys
print(sys.stdout.encoding)

# Initialize Database
try:
    db_helper.create_table()
except Exception as e:
    print("Database table initialization error:", e)

from flask import Flask, request, jsonify, render_template
app = Flask(__name__)
latest_browser_scan = {}

# -------------------------------
# LOAD MODEL
# -------------------------------
model = joblib.load("model/phishing_model.pkl")

# Initialize QR detector
qr_detector = None
qr_available = False
if cv2_available:
    try:
        qr_detector = cv2.QRCodeDetector()
        qr_available = True
        print("[+] OpenCV QR detector initialized")
    except Exception as e:
        print(f"[!] OpenCV QR detector initialization failed: {e}")

FEATURE_NAMES = [
    'having_IPhaving_IP_Address', 'URLURL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
    'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]

# -------------------------------
# QR ANALYSIS HELPER
# -------------------------------
def analyze_qr_url(extracted_url):
    """
    Common QR URL analysis function.
    Uses the same URL phishing analysis service as the Website platform.
    """
    from modules.url_service import predict_url
    from urllib.parse import urlparse

    if not extracted_url:
        return {
            "success": False,
            "error": "No URL extracted from QR code"
        }

    # Clean extracted QR data
    url = extracted_url.strip()
    url = ''.join(ch for ch in url if ch.isprintable())

    # Add HTTPS when the QR payload has no scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Validate if it's actually a URL (has a valid domain)
    try:
        parsed = urlparse(url)
        if not parsed.netloc or '.' not in parsed.netloc:
            return {
                "success": False,
                "error": "QR code does not contain a valid URL",
                "url": url,
                "extracted_url": url
            }
    except Exception:
        return {
            "success": False,
            "error": "QR code does not contain a valid URL",
            "url": url,
            "extracted_url": url
        }

    print("=" * 70)
    print("[QR] ANALYSIS STARTED")
    print(f"[QR] Extracted URL : {url}")

    try:
        result = predict_url(url)

        print(f"[QR] Status        : {result.get('verdict')}")
        print(f"[QR] Confidence    : {result.get('confidence')}%")
        print(f"[QR] Risk Score    : {result.get('risk_score')}/100")
        print(f"[QR] SSL           : {result.get('ssl_valid')}")
        print(f"[QR] DNS           : {result.get('dns_valid')}")
        print(f"[QR] Domain Age    : {result.get('domain_age')}")
        print(f"[QR] Reputation    : {result.get('reputation')}")
        print(f"[QR] Brand Spoof   : {result.get('brand_spoof')}")
        print("=" * 70)

        # Convert numpy types to Python native types for JSON serialization
        def convert_value(val):
            if hasattr(val, 'item'):  # numpy scalar
                return val.item()
            elif isinstance(val, dict):
                return {k: convert_value(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [convert_value(v) for v in val]
            return val

        converted_result = {k: convert_value(v) for k, v in result.items()}

        return {
            "success": True,
            "url": converted_result.get("url", url),
            "extracted_url": converted_result.get("url", url),
            "prediction": converted_result.get("verdict", "unknown"),
            "status": converted_result.get("verdict", "unknown"),
            "confidence": converted_result.get("confidence", 0),
            "risk_score": converted_result.get("risk_score", 0),
            "risks": converted_result.get("risks", []),
            "ssl_valid": converted_result.get("ssl_valid", False),
            "dns_valid": converted_result.get("dns_valid", False),
            "domain_age": converted_result.get("domain_age", "Not Available"),
            "reputation": converted_result.get("reputation", "Unknown"),
            "brand_spoof": converted_result.get("brand_spoof", False),
            "blacklisted": converted_result.get("blacklisted", False),
            "ml_prediction": converted_result.get("ml_prediction"),
            "ml_probabilities": converted_result.get("ml_probabilities", {})
        }

    except Exception as e:
        print(f"[QR] ANALYSIS ERROR: {e}")
        import traceback
        traceback.print_exc()

        return {
            "success": False,
            "error": str(e),
            "url": url,
            "extracted_url": url
        }

# -------------------------------
# QR SCANNING HELPERS
# -------------------------------
def scan_qr_from_camera():
    if not qr_available:
        print("[!] QR scanning not available - OpenCV not installed")
        return None
    
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("Error: Could not open camera.")
            return None

        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

        print("Scanning... Look at the preview window.")
        start_time = time.time()
        
        while time.time() - start_time < 60:
            ret, frame = cap.read()
            if not ret:
                continue

            cv2.imshow("Aim at QR Code (Press ESC to stop)", frame)
            
            # Try pyzbar first if available
            if pyzbar_available:
                try:
                    from pyzbar.pyzbar import decode, ZBarSymbol
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    codes = decode(gray, symbols=[ZBarSymbol.QRCODE])
                    for code in codes:
                        data = code.data.decode("utf-8")
                        if data:
                            cv2.destroyAllWindows()
                            cap.release()
                            return data.strip()
                except Exception as e:
                    print(f"[!] pyzbar scan failed: {e}")
            
            # Fallback to OpenCV QR detector
            url, _, _ = qr_detector.detectAndDecode(frame)
            if url:
                cv2.destroyAllWindows()
                cap.release()
                return url.strip()

            if cv2.waitKey(1) == 27:
                break

        cv2.destroyAllWindows()
        cap.release()
        return None
    except Exception as e:
        print(f"Camera scan error: {e}")
        try:
            if 'cap' in locals():
                cap.release()
            cv2.destroyAllWindows()
        except:
            pass
        return None


def scan_qr_code(image_file):
    if not qr_available or not np_available:
        print("[!] QR scanning not available - required libraries not installed")
        return None
    
    try:
        # Reset file pointer
        image_file.seek(0)
        file_bytes = np.frombuffer(image_file.read(), np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

        if img is None:
            print("Error: Could not decode image")
            return None

        extracted_data = None

        # Try zxingcpp first if available
        if zxing_available:
            try:
                results = zxingcpp.read_barcodes(img)
                if results:
                    extracted_data = results[0].text.strip()
                    print(f"[DEBUG] zxingcpp extracted: {extracted_data}")
            except Exception as e:
                print(f"[!] zxingcpp scan failed: {e}")

        # Try pyzbar if available
        if not extracted_data and pyzbar_available:
            try:
                from pyzbar.pyzbar import decode, ZBarSymbol
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                codes = decode(gray, symbols=[ZBarSymbol.QRCODE])
                for code in codes:
                    data = code.data.decode("utf-8")
                    if data:
                        extracted_data = data.strip()
                        print(f"[DEBUG] pyzbar extracted: {extracted_data}")
                        break
            except Exception as e:
                print(f"[!] pyzbar scan failed: {e}")

        # Fallback to OpenCV QR detector
        if not extracted_data:
            try:
                url, _, _ = qr_detector.detectAndDecode(img)
                if url:
                    extracted_data = url.strip()
                    print(f"[DEBUG] OpenCV extracted: {extracted_data}")
            except Exception as e:
                print(f"[!] OpenCV scan failed: {e}")

        # Validate extracted data
        if extracted_data:
            # Clean up the extracted data
            extracted_data = extracted_data.strip()
            # Remove any whitespace or special characters
            extracted_data = ''.join(char for char in extracted_data if char.isprintable())
            print(f"[DEBUG] Final extracted URL: {extracted_data}")
            return extracted_data

        return None
    except Exception as e:
        print(f"QR scan error: {e}")
        import traceback
        traceback.print_exc()
        return None

TRUSTED_DOMAINS = [
    "google.com",
    "github.com",
    "microsoft.com",
    "openai.com",
    "amazon.com",
    "facebook.com",
    "youtube.com",
    "wikipedia.org",
    "instagram.com",
    "apple.com",
    "paypal.com",
    "netflix.com"
]

LEET_TRANS = str.maketrans({
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '@': 'a',
    '$': 's'
})

# -------------------------------
# BLACKLIST IN-MEMORY CACHE
# -------------------------------
_blacklist_cache = {
    "data": set(),
    "last_updated": 0
}

def get_cached_blacklist():
    now = time.time()
    if now - _blacklist_cache["last_updated"] > 3600 or not _blacklist_cache["data"]:
        urls = set()
        sources = [
            "https://openphish.com/feed.txt",
            "https://urlhaus.abuse.ch/downloads/text/"
        ]
        for source in sources:
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
        bad_urls = get_cached_blacklist()
        clean_url = url.strip().lower()
        return clean_url in bad_urls
    except Exception as e:
        print("BLACKLIST CHECK ERROR:", e)
        return False

def check_phishtank(url):
    return False

# -------------------------------
# SSL & DNS CHECKS
# -------------------------------
def check_ssl(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificate = ssock.getpeercert()
                return True
    except Exception as e:
        print(f"SSL check failed for {url}: {e}")
        return False

def dns_check(url):
    try:
        domain = urlparse(url).netloc or tldextract.extract(url).registered_domain
        if not domain:
            return False
        dns.resolver.resolve(domain, "A", timeout=3)
        return True
    except Exception as e:
        print(f"DNS check failed for {url}: {e}")
        return False

# -------------------------------
# DOMAIN AGE CHECK
# -------------------------------
def get_domain_age_years(domain):
    try:
        url = f"https://rdap.org/domain/{domain}"
        response = requests.get(url, timeout=5)
        data = response.json()
        events = data.get("events", [])
        creation_date = None
        for event in events:
            if event.get("eventAction") == "registration":
                creation_date = event.get("eventDate")
                break
        if creation_date is None:
            print(f"[DEBUG] No creation date found for {domain}")
            return None

        creation_date = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - creation_date).days
        age_years = round(age_days / 365, 1)
        print(f"[DEBUG] Domain {domain} age: {age_years} years ({age_days} days)")
        return age_years
    except Exception as e:
        print(f"[DEBUG] RDAP ERROR for {domain}: {e}")
        return None

def get_domain_age(domain):
    age_years = get_domain_age_years(domain)
    if age_years is not None:
        return f"{age_years} years"
    return "Not Available"

# -------------------------------
# FEATURE EXTRACTION
# -------------------------------
def extract_features(url):
    features = []
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix if ext.suffix else ext.domain

    response = None
    soup = None
    html = ""
    redirect_history = []

    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        html = response.text.lower()
        soup = BeautifulSoup(response.text, "html.parser")
        redirect_history = response.history
    except Exception:
        pass

    age_years = get_domain_age_years(domain)
    ssl_valid = check_ssl(url)

    # 1. Having IP Address
    has_ip = bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))
    features.append(-1 if has_ip else 1)

    # 2. URL Length
    if len(url) < 54:
        features.append(1)
    elif len(url) <= 75:
        features.append(0)
    else:
        features.append(-1)

    # 3. URL Shortening
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly"]
    features.append(-1 if any(s in url.lower() for s in shorteners) else 1)

    # 4. @ Symbol
    features.append(-1 if "@" in url else 1)

    # 5. Double Slash Redirect
    features.append(-1 if url[8:].find("//") != -1 else 1)

    # 6. Prefix-Suffix
    features.append(-1 if "-" in ext.domain else 1)

    # 7. Subdomain Count
    subdomains = [s for s in ext.subdomain.split(".") if s and s.lower() != "www"]
    if len(subdomains) == 0:
        features.append(1)
    elif len(subdomains) == 1:
        features.append(0)
    else:
        features.append(-1)

    # 8. SSLfinal_State
    if parsed.scheme == "https" and ssl_valid:
        if age_years is not None and age_years >= 1.0:
            features.append(1)
        else:
            features.append(0)
    else:
        features.append(-1)

    # 9. Domain Registration Length
    if age_years is not None and age_years >= 1.0:
        features.append(1)
    else:
        features.append(-1)

    # 10. Favicon
    if soup:
        fav = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if fav and fav.get("href") and fav.get("href").startswith("http") and domain not in fav.get("href"):
            features.append(-1)
        else:
            features.append(1)
    else:
        features.append(0)

    # 11. Port
    if parsed.port is None or parsed.port in [80, 443]:
        features.append(1)
    else:
        features.append(-1)

    # 12. HTTPS Token
    features.append(-1 if "https" in ext.domain.lower() else 1)

    # 13. Request URL
    if soup:
        total = 0
        external = 0
        for tag in soup.find_all(["img", "audio", "embed", "iframe"]):
            src = tag.get("src")
            if src:
                total += 1
                if src.startswith("http") and domain not in src:
                    external += 1
        if total == 0:
            features.append(1)
        else:
            ratio = external / total
            features.append(1 if ratio < 0.22 else (0 if ratio <= 0.61 else -1))
    else:
        features.append(0)

    # 14. URL of Anchor
    if soup:
        anchors = soup.find_all("a")
        total = len(anchors)
        unsafe = 0
        for a in anchors:
            href = a.get("href")
            if href:
                if href.startswith("#") or href.lower().startswith("javascript") or (href.startswith("http") and domain not in href):
                    unsafe += 1
        if total == 0:
            features.append(1)
        else:
            ratio = unsafe / total
            features.append(1 if ratio < 0.31 else (0 if ratio <= 0.67 else -1))
    else:
        features.append(0)

    # 15. Links in Tags
    if soup:
        tags = soup.find_all(["meta", "script", "link"])
        total = len(tags)
        external = 0
        for tag in tags:
            value = tag.get("src") or tag.get("href")
            if value and value.startswith("http") and domain not in value:
                external += 1
        if total == 0:
            features.append(1)
        else:
            ratio = external / total
            features.append(1 if ratio < 0.17 else (0 if ratio <= 0.81 else -1))
    else:
        features.append(0)

    # 16. SFH
    if soup:
        forms = soup.find_all("form")
        if len(forms) == 0:
            features.append(1)
        else:
            action = forms[0].get("action")
            if not action or action == "" or action == "about:blank":
                features.append(-1)
            elif action.startswith("http") and domain not in action:
                features.append(0)
            else:
                features.append(1)
    else:
        features.append(0)

    # 17. Submitting to Email
    if soup:
        forms = soup.find_all("form")
        found = False
        for form in forms:
            action = str(form.get("action")).lower()
            if "mailto:" in action or "mail(" in action:
                found = True
                break
        features.append(-1 if found else 1)
    else:
        features.append(1)

    # 18. Abnormal URL
    hostname = parsed.hostname if parsed.hostname else ""
    features.append(1 if domain in hostname else -1)

    # 19. Redirect
    if response is not None:
        h = len(redirect_history)
        features.append(1 if h <= 1 else (0 if h <= 3 else -1))
    else:
        features.append(0)

    # 20. onMouseOver
    if response is not None:
        features.append(-1 if "onmouseover" in html and "status" in html else 1)
    else:
        features.append(0)

    # 21. Right Click
    if response is not None:
        features.append(-1 if "event.button==2" in html or "event.button == 2" in html else 1)
    else:
        features.append(0)

    # 22. Popup Window
    if response is not None:
        features.append(-1 if "prompt(" in html and "form" in html else 1)
    else:
        features.append(0)

    # 23. Hidden Iframe
    if soup:
        hidden_iframe = any(
            i.get("style") and ("display:none" in i.get("style").lower() or "visibility:hidden" in i.get("style").lower())
            for i in soup.find_all("iframe")
        )
        features.append(-1 if hidden_iframe else 1)
    else:
        features.append(1)

    # 24. Age of Domain
    if age_years is not None:
        features.append(1 if age_years >= 0.5 else -1)
    else:
        features.append(0)

    # 25. DNS Record
    dns_ok = dns_check(url)
    features.append(1 if dns_ok else -1)

    # 26. web_traffic
    features.append(1 if domain in TRUSTED_DOMAINS else 0)

    # 27. Page_Rank
    features.append(1 if domain in TRUSTED_DOMAINS else 0)

    # 28. Google_Index
    features.append(1 if dns_ok else -1)

    # 29. Links_pointing_to_page
    features.append(1 if domain in TRUSTED_DOMAINS else 0)

    # 30. Statistical_report
    features.append(-1 if check_blacklist(url) or has_ip else 1)

    return features

# -------------------------------
# REPUTATION & BRAND CHECKS
# -------------------------------
def reputation_check(url):
    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix if ext.suffix else ext.domain

    for trusted in TRUSTED_DOMAINS:
        if trusted in domain:
            return "Trusted"

    suspicious_words = ["login", "verify", "secure", "bank", "update", "reward", "gift"]
    suspicious_score = sum(1 for word in suspicious_words if word in url.lower())

    if suspicious_score >= 2:
        return "Suspicious"

    return "Unknown"

def check_brand_impersonation(url):
    trusted_brands = ["google", "paypal", "amazon", "microsoft", "facebook", "github", "apple", "instagram", "netflix"]
    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix if ext.suffix else ext.domain

    if domain in TRUSTED_DOMAINS:
        return False

    norm_domain = ext.domain.lower().translate(LEET_TRANS).replace("-", "")

    for brand in trusted_brands:
        if brand in norm_domain:
            return True
        similarity = difflib.SequenceMatcher(None, norm_domain, brand).ratio()
        if similarity >= 0.70:
            return True

    return False

# -------------------------------
# CONTENT & RISK ANALYSIS
# -------------------------------
def content_analysis(url, html=None, soup=None):
    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix if ext.suffix else ext.domain
    if domain in TRUSTED_DOMAINS:
        return [], 0

    risks = []
    score = 0

    try:
        if html is None or soup is None:
            response = requests.get(url, timeout=3, headers={"User-Agent": "Mozilla/5.0"})
            html = response.text.lower()
            soup = BeautifulSoup(response.text, "html.parser")

        suspicious_keywords = [
            "verify your account",
            "update payment",
            "confirm identity",
            "login now",
            "urgent action",
            "claim reward",
            "password expired"
        ]

        for word in suspicious_keywords:
            if word in html:
                risks.append(f"Suspicious content: {word}")
                score += 10

        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            if action and action.startswith("http") and domain not in action:
                risks.append("External Form Submission")
                score += 15
                break

        return risks, score
    except Exception as e:
        print(f"CONTENT ANALYSIS ERROR for {url}: {e}")
        # Return 0 score on error so it doesn't break the overall calculation
        return [], 0

def analyze_risk(url):
    risks = []
    score = 0

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

    suspicious_words = [ "verify", "bank", "secure", "update", "payment", "confirm"]
    for word in suspicious_words:
        if word in url.lower():
            risks.append(f"Suspicious keyword: {word}")
            score += 10

    if sum(c.isdigit() for c in url) >= 8:
        risks.append("Excessive numbers in URL")
        score += 15

    suspicious_tlds = [".tk", ".xyz", ".top", ".gq", ".ml", ".cf"]
    for tld in suspicious_tlds:
        if tld in url.lower():
            risks.append(f"Suspicious extension: {tld}")
            score += 20

    return risks, score

# -------------------------------
# ROUTES
# -------------------------------
@app.route("/")
@app.route("/")
def home():
    return render_template("index.html")


# -------------------------------
# UNIFIED EVALUATION (from extracted folder)
# -------------------------------
def ensure_scheme(url):
    print("ensure_scheme loaded successfully")
    """Ensure URL has http:// or https:// scheme"""
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def evaluate_site(url):
    """Evaluate site for phishing detection"""
    url = ensure_scheme(url)
    
    response = None
    html = ""
    soup = None
    try:
        response = requests.get(url, timeout=4, headers={"User-Agent": "Mozilla/5.0"})
        html = response.text.lower()
        soup = BeautifulSoup(response.text, "html.parser")
    except:
        pass

    try:
        features = extract_features(url)
        
        if model:
            df_features = pd.DataFrame([features], columns=FEATURE_NAMES)
            prediction = model.predict(df_features)[0]
            prob = model.predict_proba(df_features)[0]
            phishing_conf = min(prob[1] * 100, 100)
            safe_conf = min(prob[0] * 100, 100)
        else:
            prediction = 0
            phishing_conf, safe_conf = 50.0, 50.0
    except Exception as e:
        print(f"[ERROR] Feature extraction or prediction failed: {e}")
        import traceback
        traceback.print_exc()
        # Fallback values
        prediction = 0
        phishing_conf, safe_conf = 50.0, 50.0
        features = [0] * len(FEATURE_NAMES)

    ssl_valid = check_ssl(url)
    dns_valid = dns_check(url)
    brand_spoof = check_brand_impersonation(url)
    blacklisted = check_blacklist(url)
    reputation = reputation_check(url)

    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix
    age_str = get_domain_age(domain)

    try:
        numeric_age = float(age_str.split()[0]) if "years" in age_str else 0
    except:
        numeric_age = 0

    risks, risk_score = analyze_risk(url)
    content_risks, content_score = content_analysis(url, html=html, soup=soup)
    risks.extend(content_risks)
    risk_score += content_score

    if not ssl_valid:
        risks.append("Invalid SSL Certificate")
        risk_score += 15

    if 0 < numeric_age < 0.5:
        risks.append("Very New Domain")
        risk_score += 25

    if reputation == "Suspicious":
        risks.append("Low Website Reputation")
        risk_score += 20

    if not dns_valid:
        risks.append("DNS Record Not Found")
        risk_score += 25

    if brand_spoof and (not ssl_valid or not dns_valid or blacklisted):
        risks.append("Possible Brand Impersonation")
        risk_score = min(risk_score + 20, 100)

    if risk_score > 0 or len(risks) > 0 or blacklisted:
        display = "Phishing Website Detected!"
        confidence = 99.0 if blacklisted else max(phishing_conf, 85.0)
        status = "phishing"
    else:
        display = "Safe Website"
        confidence = safe_conf
        status = "safe"

    confidence = round(min(confidence, 100), 2)
    meter_color = "#22c55e" if status == "safe" else "#ef4444"

    return {
        "prediction": display,
        "url": url,
        "confidence": confidence,
        "status": status,
        "risks": risks,
        "ssl_valid": ssl_valid,
        "reputation": reputation,
        "domain_age": age_str,
        "dns_valid": dns_valid,
        "brand_spoof": brand_spoof,
        "risk_score": risk_score,
        "meter_color": meter_color
    }


@app.route("/predict", methods=["POST"])
def predict():
    url = request.form.get("url", "").strip()
    from modules.url_service import predict_url
    res = predict_url(url)
    
    status = res.get("verdict", "safe")
    confidence = res.get("confidence", 0)
    risk_score = res.get("risk_score", 0)
    
    if res.get("blacklisted"):
        display = "⚠️ Blacklisted Phishing Website!"
    elif status == "phishing":
        display = "⚠️ Suspicious Website Detected!"
    else:
        display = "✅ Safe Website"
        
    # Save log to database
    try:
        db_helper.insert_log(url, display)
    except Exception as e:
        print("DATABASE LOG ERROR:", e)
        
    return render_template(
        "index.html",
        prediction=display,
        url=res.get("url", url),
        confidence=confidence,
        status=status,
        risks=res.get("risks", []),
        ssl_valid=res.get("ssl_valid", False),
        reputation=res.get("reputation", "Unknown"),
        domain_age=res.get("domain_age", "Not Available"),
        dns_valid=res.get("dns_valid", False),
        brand_spoof=res.get("brand_spoof", False),
        risk_score=risk_score,
        meter_color="#22c55e" if status == "safe" else "#ef4444"
    )

@app.route("/api/predict", methods=["POST"])
def api():
    url = request.json.get("url", "").strip()
    from modules.url_service import predict_url
    res = predict_url(url)
    
    return jsonify({
        "url": res.get("url", url),
        "prediction": res.get("verdict", "safe"),
        "phishing_probability": res.get("ml_probabilities", {}).get("phishing", 0.0),
        "brand_impersonation": res.get("brand_spoof", False),
        "blacklisted": res.get("blacklisted", False),
        "reputation": res.get("reputation", "Unknown"),
        "risk_score": res.get("risk_score", 0),
        "confidence": res.get("confidence", 0),
        "risks": res.get("risks", []),
        "ssl_valid": res.get("ssl_valid", False),
        "dns_valid": res.get("dns_valid", False),
        "domain_age": res.get("domain_age", "Not Available")
    })

# -------------------------------
# EMAIL ROUTES
# -------------------------------
@app.route("/email")
@app.route("/email/")
def email_home():
    return render_template("email.html")


@app.route("/predict_email", methods=["POST"])
def predict_email():
    print(">>> predict_email route reached <<<")
    sender = request.form.get("sender", "").strip()
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()
    attachments = [f.filename for f in request.files.getlist("attachments") if f.filename]

    from modules.email import analyze_email
    res = analyze_email(sender, subject, body, attachments=attachments)
    try:
        db_helper.insert_email_scan(
            sender, subject, res["verdict"],
            res["confidence"], res["risk_score"],
            [u["url"] for u in res["suspicious_urls"]]
        )
        db_helper.insert_log(f"[Email] From: {sender} | Subject: {subject[:50]}", res["display"])
    except Exception as e:
        print("DATABASE LOG ERROR:", e)

    try:
        print("=" * 80)
        print(f"EMAIL DETECTION TRACE: {sender.encode('ascii', 'ignore').decode('ascii')}")
        print(f"  BiLSTM Phishing Prob: {res['dl_result']['phishing_probability']}")
        print(f"  Risk Score: {res['risk_score']}/100")
        print(f"  Verdict: {res['verdict']}")
        print("=" * 80)
    except Exception as e:
        print("TRACE PRINT ERROR:", e)

    return render_template(
        "email.html",
        prediction=res["display"],
        status=res["verdict"],
        confidence=res["confidence"],
        risk_score=res["risk_score"],
        sender=sender,
        subject=subject,
        body=body,
        dl_result=res["dl_result"],
        sender_analysis=res["sender_analysis"],
        suspicious_keywords=res["suspicious_keywords"],
        suspicious_urls=res["suspicious_urls"],
        url_count=len(res["extracted_urls"]),
        extracted_urls=res["extracted_urls"],
        risks=res["risks"],
        heuristic_score=res["heuristic_score"],
        ssl_failures=res.get("ssl_failures", []),
        dns_failures=res.get("dns_failures", []),
        low_reputation=res.get("low_reputation", []),
    )


@app.route("/api/predict_email", methods=["POST"])
def api_predict_email():
    data = request.get_json() or {}
    from modules.email import analyze_email
    res = analyze_email(
        data.get("sender", ""), data.get("subject", ""),
        data.get("body", ""), attachments=data.get("attachments", [])
    )
    
    try:
        db_helper.insert_email_scan(
            data.get("sender", ""), data.get("subject", ""), res["verdict"], 
            res["confidence"], res["risk_score"], [u["url"] for u in res["suspicious_urls"]]
        )
    except Exception as e:
        print("DATABASE LOG ERROR:", e)
    
    return jsonify(res)


# -------------------------------
# SMS ROUTES
# -------------------------------
@app.route("/sms")
@app.route("/sms/")
def sms_home():
    return render_template("sms.html")


@app.route("/predict_sms", methods=["POST"])
def predict_sms():
    message = request.form.get("sms_text", "").strip() or request.form.get("message", "").strip()
    
    if not message:
        return render_template("sms.html", prediction="Please enter an SMS message to analyze.", status="error")
    
    try:
        from modules.sms_service import analyze_sms
        result = analyze_sms(message)
        
        # Log to database
        try:
            db_helper.insert_log(f"[SMS] {message[:50]}...", result['verdict'])
        except Exception as e:
            print("DATABASE LOG ERROR:", e)

        otp = result.get("otp_pattern", {})
        if otp.get("legitimate_otp"):
            otp_pattern = "legitimate"
        elif otp.get("malicious_otp"):
            otp_pattern = "malicious"
        else:
            otp_pattern = "none"

        extracted_urls = [
            {
                "url": r["url"],
                "status": r.get("verdict", "unknown"),
                "risks": r.get("risks", []),
                "risk_score": r.get("risk_score", 0),
                "confidence": r.get("confidence", 0),
            }
            for r in result.get("url_results", [])
        ]
        
        return render_template(
            "sms.html",
            prediction=result['verdict'].upper(),
            status=result['verdict'],
            confidence=result['confidence'],
            risk_score=result['risk_score'],
            sms_text=message,
            otp_pattern=otp_pattern,
            url_count=len(result.get("extracted_urls", [])),
            phone_count=len(result.get("phone_numbers", [])),
            extracted_urls=extracted_urls,
            phone_numbers=result['phone_numbers'],
            emails=result['emails'],
            detected_keywords=result['detected_keywords'],
            reasons=result['reasons'],
            model_used=result['model_used']
        )
    except Exception as e:
        print(f"SMS analysis error: {e}")
        import traceback
        traceback.print_exc()
        return render_template("sms.html", prediction=f"Error: {str(e)}", status="error")


@app.route("/api/predict_sms", methods=["POST"])
def api_predict_sms():
    data = request.get_json() or {}
    from modules.sms_service import analyze_sms
    res = analyze_sms(data.get("message", ""))
    
    try:
        db_helper.insert_log(f"[SMS API] {data.get('message', '')[:50]}...", res['verdict'])
    except Exception as e:
        print("DATABASE LOG ERROR:", e)
    
    return jsonify(res)


# -------------------------------
# VISHING ROUTES
# -------------------------------
@app.route("/vishing")
@app.route("/vishing/")
def vishing_home():
    return render_template("vishing.html")


@app.route("/predict_vishing", methods=["POST"])
def predict_vishing():
    audio_file = (
        request.files.get("audio_file")
        or request.files.get("audio")
    )
    if not audio_file:
        return render_template("vishing.html", error="No audio file uploaded")

    filename = (audio_file.filename or "").strip()
    if not filename:
        return render_template("vishing.html", error="No file selected")

    ext = os.path.splitext(filename)[1].lower()
    allowed = {".wav", ".mp3", ".mpeg", ".mp4", ".m4a", ".aac", ".flac", ".ogg"}
    if ext not in allowed:
        return render_template(
            "vishing.html",
            error=f"Unsupported format {ext or 'unknown'}. Allowed: {', '.join(sorted(allowed))}"
        )

    fd, audio_path = tempfile.mkstemp(suffix=ext)
    os.close(fd)
    try:
        audio_file.save(audio_path)
        from modules.vishing_service import analyze_vishing_call
        result = analyze_vishing_call(audio_path)

        if not result.get("success"):
            return render_template("vishing.html", error=result.get("error", "Analysis failed"))

        try:
            db_helper.insert_vishing_scan(
                filename=filename,
                transcription=result.get("transcription", ""),
                verdict=result.get("prediction", "Unknown"),
                confidence=result.get("confidence", 0),
                risk_score=result.get("risk_score", 0),
                reasons=result.get("reasons", []),
            )
            db_helper.insert_log(f"[Vishing] {filename}", result.get("prediction", "Unknown"))
        except Exception as e:
            print("DATABASE LOG ERROR:", e)

        return render_template(
            "vishing.html",
            prediction=result.get("prediction"),
            status=result.get("status"),
            confidence=result.get("confidence"),
            risk_score=result.get("risk_score"),
            transcription=result.get("transcription"),
            reasons=result.get("reasons"),
            scan_timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
    except Exception as e:
        return render_template("vishing.html", error="Analysis error: " + str(e))
    finally:
        if os.path.exists(audio_path):
            try:
                os.remove(audio_path)
            except OSError:
                pass


@app.route("/api/predict_vishing", methods=["POST"])
def api_predict_vishing():
    audio_file = (
        request.files.get("audio_file")
        or request.files.get("audio")
    )
    if not audio_file:
        return jsonify({"success": False, "error": "No audio file uploaded"})

    filename = (audio_file.filename or "").strip()
    if not filename:
        return jsonify({"success": False, "error": "No file selected"})

    ext = os.path.splitext(filename)[1].lower()
    allowed = {".wav", ".mp3", ".mpeg", ".mp4", ".m4a", ".aac", ".flac", ".ogg"}
    if ext not in allowed:
        return jsonify({
            "success": False,
            "error": f"Unsupported format {ext or 'unknown'}. Allowed: {', '.join(sorted(allowed))}"
        })

    fd, audio_path = tempfile.mkstemp(suffix=ext)
    os.close(fd)
    try:
        audio_file.save(audio_path)
        from modules.vishing_service import analyze_vishing_call
        result = analyze_vishing_call(audio_path)

        try:
            db_helper.insert_vishing_scan(
                filename=filename,
                transcription=result.get("transcription", ""),
                verdict=result.get("prediction", "Unknown"),
                confidence=result.get("confidence", 0),
                risk_score=result.get("risk_score", 0),
                reasons=result.get("reasons", []),
            )
        except Exception as e:
            print("DATABASE LOG ERROR:", e)

        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        if os.path.exists(audio_path):
            try:
                os.remove(audio_path)
            except OSError:
                pass


# -------------------------------
# CORS HEADERS (for Chrome Extension)
# -------------------------------
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


# -------------------------------
# QR CODE ROUTES
# -------------------------------
@app.route("/qr")
@app.route("/qr/")
def qr_home():
    return render_template("qr.html")


@app.route("/api/check-qr-url", methods=["GET", "POST"])
def check_qr_url():
    """API endpoint for QR scanner to check URLs using shared URL analysis service.

    GET  — browser redirect from qr.js camera capture; renders qr.html with results.
    POST — programmatic call (e.g. qr_scanner.py); returns JSON.
    """
    if request.method == "GET":
        url = request.args.get("url", "").strip()
    else:
        data = request.get_json(silent=True) or {}
        url = data.get("url", "").strip()

    if not url:
        if request.method == "GET":
            return render_template("qr.html", error="No URL provided"), 400
        return jsonify({
            "success": False,
            "url": "",
            "extracted_url": "",
            "prediction": "invalid",
            "status": "invalid",
            "confidence": 0,
            "risk_score": 0,
            "ssl_valid": False,
            "dns_valid": False,
            "domain_age": "Not Available",
            "reputation": "Unknown",
            "brand_spoof": False,
            "risks": ["No URL provided"]
        }), 400

    result = analyze_qr_url(url)

    if not result.get("success"):
        if request.method == "GET":
            return render_template("qr.html", error=result.get("error", "Analysis failed")), 500
        return jsonify(result), 500

    try:
        db_helper.insert_log(
            f"[QR Code] {result['extracted_url']}",
            result["status"]
        )
    except Exception as e:
        print("DATABASE LOG ERROR:", e)

    if request.method == "GET":
        template_vars = {
            "prediction": result.get("prediction", result.get("status")),
            "status": result.get("status"),
            "confidence": result.get("confidence", 0),
            "risk_score": result.get("risk_score", 0),
            "ssl_valid": result.get("ssl_valid", False),
            "dns_valid": result.get("dns_valid", False),
            "domain_age": result.get("domain_age", "Not Available"),
            "reputation": result.get("reputation", "Unknown"),
            "brand_spoof": result.get("brand_spoof", False),
            "risks": result.get("risks", []),
            "extracted_url": result.get("extracted_url"),
        }
        return render_template("qr.html", **template_vars)

    return jsonify(result)


@app.route("/api/scan-qr-frame", methods=["POST"])
def api_scan_qr_frame():
    """API endpoint for client-side camera captures."""
    if not qr_available:
        return jsonify({"success": False, "error": "QR scanning not available"}), 400

    if "qr_image" not in request.files:
        return jsonify({"success": False, "error": "No image provided"}), 400

    file = request.files["qr_image"]
    if file.filename == "":
        return jsonify({"success": False, "error": "Empty file"}), 400

    try:
        extracted_url = scan_qr_code(file)
        if not extracted_url:
            return jsonify({"success": False, "error": "No QR code detected"}), 400

        extracted_url = extracted_url.strip()
        extracted_url = "".join(char for char in extracted_url if char.isprintable())

        if not extracted_url.startswith(("http://", "https://")):
            extracted_url = "https://" + extracted_url

        return jsonify({"success": True, "url": extracted_url})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/scan-qr-file", methods=["POST"])
def scan_qr_file_main():
    """QR file upload with URL extraction using shared URL analysis service"""
    if not qr_available:
        return jsonify({"error": "QR scanning not available - OpenCV not installed"}), 400
    
    print("[DEBUG] QR file upload request received")
    if "qr_image" not in request.files:
        print("[ERROR] No image file provided")
        return jsonify({"error": "No image file provided"}), 400

    file = request.files["qr_image"]
    print(f"[DEBUG] File uploaded: {file.filename}")
    
    if file.filename == '':
        print("[ERROR] Empty filename")
        return jsonify({"error": "No file selected"}), 400
    
    try:
        print("[DEBUG] Scanning for QR code...")
        extracted_url = scan_qr_code(file)
        print(f"[DEBUG] QR scan result: {extracted_url}")
        
        if not extracted_url:
            print("[ERROR] No valid QR code found")
            return jsonify({"error": "No valid QR code found in the image. Please try a clearer image."}), 400

        print(f"[DEBUG] QR code detected successfully: {extracted_url}")
        
        # Validate and clean the URL
        extracted_url = extracted_url.strip()
        extracted_url = ''.join(char for char in extracted_url if char.isprintable())
        
        if not extracted_url.startswith(("http://", "https://")):
            extracted_url = "https://" + extracted_url
        print(f"[DEBUG] Final extracted URL: {extracted_url}")
        
        # Use common QR analysis function
        result = analyze_qr_url(extracted_url)
        
        if not result.get("success"):
            return jsonify(result), 500
        
        return jsonify({
            "success": True,
            "url": result["url"],
            "extracted_url": result["extracted_url"],
            "prediction": result["prediction"],
            "status": result["status"],
            "confidence": result["confidence"],
            "risk_score": result["risk_score"],
            "risks": result["risks"],
            "ssl_valid": result["ssl_valid"],
            "dns_valid": result["dns_valid"],
            "domain_age": result["domain_age"],
            "reputation": result["reputation"],
            "brand_spoof": result["brand_spoof"],
            "blacklisted": result["blacklisted"]
        })
    except Exception as e:
        print(f"[ERROR] QR scan failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"QR scan failed: {str(e)}"}), 500


@app.route("/scan-desktop-camera", methods=["POST"])
def scan_desktop_camera():
    """Camera scanning using shared URL analysis service"""
    if not qr_available:
        return render_template(
            "qr.html",
            prediction="QR scanning not available - OpenCV not installed",
            status="error",
            confidence=0,
            risks=["OpenCV not available"],
            extracted_url="N/A"
        )
    
    try:
        extracted_url = scan_qr_from_camera()
        if not extracted_url:
            return render_template(
                "qr.html",
                prediction="No QR code detected or scanning was canceled.",
                status="error",
                confidence=0,
                risks=["No QR code detected"],
                extracted_url="N/A"
            )
        
        # If QR code detected, validate and clean the URL
        print(f"[DEBUG] QR detected URL: {extracted_url}")
        extracted_url = extracted_url.strip()
        
        if not extracted_url.startswith(("http://", "https://")):
            extracted_url = "https://" + extracted_url
        print(f"[DEBUG] Final extracted URL: {extracted_url}")
        
        # Use common QR analysis function
        result = analyze_qr_url(extracted_url)
        
        if not result.get("success"):
            return render_template(
                "qr.html",
                prediction=result.get("error", "Analysis failed"),
                status="error",
                confidence=0,
                risks=[result.get("error", "Analysis failed")],
                extracted_url=extracted_url
            )
        
        return render_template(
            "qr.html",
            prediction=result["prediction"],
            status=result["status"],
            confidence=result["confidence"],
            risk_score=result["risk_score"],
            risks=result["risks"],
            extracted_url=result["extracted_url"],
            ssl_valid=result["ssl_valid"],
            dns_valid=result["dns_valid"],
            domain_age=result["domain_age"],
            reputation=result["reputation"],
            brand_spoof=result["brand_spoof"]
        )
    except Exception as e:
        print(f"[ERROR] Camera scan route error: {e}")
        import traceback
        traceback.print_exc()
        return render_template(
            "qr.html",
            prediction=f"Camera scan failed: {str(e)}",
            status="error",
            confidence=0,
            risk_score=0,
            risks=["Camera error"],
            extracted_url="N/A",
            ssl_valid=False,
            dns_valid=False,
            domain_age="Not Available",
            reputation="Unknown",
            brand_spoof=False
        )

# -------------------------------
# BROWSER ROUTES
# -------------------------------
@app.route("/browser")
@app.route("/browser/")
def browser_home():
    return render_template("browser.html")


def _render_browser_result(res):
    preview = res.get("screenshot_preview", "")
    if preview and preview.startswith("data:"):
        preview = preview.split(",", 1)[-1]
    return render_template(
        "browser.html",
        prediction=res["display"],
        status=res["verdict"],
        confidence=res["confidence"],
        risk_score=res["risk_score"],
        current_url=res.get("current_url", ""),
        dl_prediction=res.get("dl_prediction", "Legitimate"),
        dl_confidence=res.get("dl_result", {}).get("confidence", 0),
        screenshot_preview=preview if preview and not preview.endswith("...") else "",
        redirect_len=res.get("redirect_len", 0),
        risks=res["risks"],
        features=res["features"],
        ssl_valid=res.get("ssl_valid", True),
        dns_valid=res.get("dns_valid", True),
        reputation=res.get("reputation", "Unknown"),
        heuristic_score=res["heuristic_score"],
        popup_messages_count=res.get("popup_messages_count", 0),
        auto_downloads_count=res.get("auto_downloads_count", 0),
        notification_requests=res.get("notification_requests", 0),
    )


@app.route("/predict_browser", methods=["POST"])
def predict_browser():
    data = request.get_json(silent=True) or {}
    if not data:
        data = {
            "current_url": request.form.get("current_url", ""),
            "redirect_chain": request.form.get("redirect_chain", ""),
            "popup_messages": [request.form.get("page_content", "")],
            "extension_permissions": request.form.get("extension_permissions", ""),
            "screenshot_b64": request.form.get("screenshot_b64", ""),
        }
    
    # Handle simplified requests from extension (just current_url)
    if "current_url" in data and len(data) == 1:
        data["redirect_chain"] = data.get("current_url", "")
        data["popup_messages"] = []
        data["extension_permissions"] = ["tabs", "storage", "webNavigation", "notifications", "downloads"]
        data["screenshot_b64"] = ""
        data["auto_downloads"] = []
        data["new_tabs_count"] = 0
        data["sensitive_forms_detected"] = False
        data["alert_count"] = 0
        data["popup_attempts"] = 0
        data["fullscreen_attempts"] = 0

    from modules.browser import analyze_browser_threat
    res = analyze_browser_threat(data)
    global latest_browser_scan
    latest_browser_scan = res.copy()

    try:
        db_helper.insert_browser_scan(
            res.get("current_url", ""), res.get("dl_prediction", ""),
            res["verdict"], res["confidence"], res["risk_score"], res["risks"][:10]
        )
        db_helper.insert_log(f"[Browser] {res.get('current_url', 'N/A')}", res["display"])
    except Exception as e:
        print("DATABASE LOG ERROR:", e)

    if request.is_json or request.content_type == "application/json":
        safe_res = {k: v for k, v in res.items() if k != "screenshot_preview"}
        safe_res["screenshot_b64"] = res.get("screenshot_preview", "")[:200]
        return jsonify(safe_res)

    return _render_browser_result(res)


@app.route("/api/predict_browser", methods=["POST", "OPTIONS"])
def api_predict_browser():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json() or {}
    
    # Handle simplified requests from extension (just current_url)
    if "current_url" in data and len(data) == 1:
        data["redirect_chain"] = data.get("current_url", "")
        data["popup_messages"] = []
        data["extension_permissions"] = ["tabs", "storage", "webNavigation", "notifications", "downloads"]
        data["screenshot_b64"] = ""
        data["auto_downloads"] = []
        data["new_tabs_count"] = 0
        data["sensitive_forms_detected"] = False
        data["alert_count"] = 0
        data["popup_attempts"] = 0
        data["fullscreen_attempts"] = 0
    
    from modules.browser import analyze_browser_threat
    res = analyze_browser_threat(data)
    global latest_browser_scan
    latest_browser_scan = res.copy()

    try:
        db_helper.insert_browser_scan(
            res.get("current_url", ""), res.get("dl_prediction", ""),
            res["verdict"], res["confidence"], res["risk_score"], res["risks"][:10]
        )
    except Exception as e:
        print("DATABASE LOG ERROR:", e)

    return jsonify({
        "verdict": res["verdict"],
        "display": res["display"],
        "confidence": res["confidence"],
        "risk_score": res["risk_score"],
        "dl_prediction": res["dl_prediction"],
        "dl_confidence": res["dl_result"]["confidence"],
        "current_url": res.get("current_url", ""),
        "redirect_len": res.get("redirect_len", 0),
        "ssl_valid": res.get("ssl_valid"),
        "dns_valid": res.get("dns_valid"),
        "reputation": res.get("reputation"),
        "risks": res["risks"],
        "heuristic_score": res["heuristic_score"],
        "screenshot_preview": res.get("screenshot_preview", ""),
        "popup_messages_count": res.get("popup_messages_count", 0),
        "auto_downloads_count": res.get("auto_downloads_count", 0),
        "notification_requests": res.get("notification_requests", 0),
        "scan_timestamp": res.get("scan_timestamp", ""),
    })
@app.route("/api/latest_browser_scan", methods=["GET"])
def latest_browser_scan_api():
    if not latest_browser_scan:
        return jsonify({
            "available": False
        })

    safe_res = {
        k: v
        for k, v in latest_browser_scan.items()
        if k != "screenshot_preview"
    }

    safe_res["available"] = True

    return jsonify(safe_res)


@app.route("/dashboard")
def dashboard():
    try:
        logs = db_helper.fetch_logs()
        email_scans = db_helper.fetch_email_scans()
        browser_scans = db_helper.fetch_browser_scans()
        vishing_scans = db_helper.fetch_vishing_scans()
    except Exception as e:
        print("DATABASE LOGS FETCH ERROR:", e)
        logs, email_scans, browser_scans, vishing_scans = [], [], [], []
    return render_template(
        "dashboard.html",
        logs=logs,
        email_scans=email_scans,
        browser_scans=browser_scans,
        vishing_scans=vishing_scans,
    )

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)