from flask import Flask, render_template, request, jsonify
import joblib
import requests
import ssl
import socket
import whois
import difflib
import dns.resolver
import re
import tldextract
import pandas as pd
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)

# -------------------------------
# LOAD MODEL
# -------------------------------
model = joblib.load("model/phishing_model.pkl")


# -------------------------------
# FEATURE EXTRACTION
# -------------------------------
def extract_features(url):

    features = []
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix
    
    # 1. Having IP Address
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else -1)
    # 2. URL Length
    if len(url) < 54:
        features.append(1)
    elif len(url) <= 75:
        features.append(0)
    else:
        features.append(-1)
    # 3. URL Shortening
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co",
        "goo.gl", "is.gd", "ow.ly", "buff.ly"
    ]
    features.append(-1 if any(s in url.lower() for s in shorteners) else 1)
    # 4. @ Symbol
    features.append(-1 if "@" in url else 1)
    # 5. Double Slash Redirect
    features.append(-1 if url[8:].find("//") != -1 else 1)

    # 6. Prefix-Suffix
    features.append(-1 if "-" in ext.domain else 1)

    # 7. Subdomain Count
    subdomains = [s for s in ext.subdomain.split(".") if s]

    if len(subdomains) == 0:
        features.append(1)
    elif len(subdomains) == 1:
        features.append(0)
    else:
        features.append(-1)
    # 8. HTTPS
    features.append(1 if parsed.scheme == "https" else -1)

    try:
        age = get_domain_age(domain)

        if isinstance(age, (int, float)):
            if age >= 2:
                features.append(1)      # Old domain
            elif age >= 1:
                features.append(0)      # Medium
            else:
                features.append(-1)     # Very new
        else:
            features.append(0)

    except:
        features.append(0)
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent":"Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")
        if soup.find("link", rel=lambda x: x and "icon" in x.lower()):
            features.append(1)
        else:
            features.append(-1)
    except:
        features.append(0)
    if parsed.port is None or parsed.port in [80, 443]:
        features.append(1)
    else:
        features.append(-1)
    # HTTPS Token
    if "https" in ext.domain.lower():
        features.append(-1)
    else:
        features.append(1)
    # Request URL
    try:
        response = requests.get(
            url,
            timeout=5,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        soup = BeautifulSoup(response.text, "html.parser")

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
            if ratio < 0.22:
                features.append(1)
            elif ratio <= 0.61:
                features.append(0)
            else:
                features.append(-1)

    except:
        features.append(0)
    # URL of Anchor
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")
        anchors = soup.find_all("a")
        total = len(anchors)
        unsafe = 0
        for a in anchors:
            href = a.get("href")
            if href:
                if href.startswith("#") or href.lower().startswith("javascript"):
                    unsafe += 1
        if total == 0:
            features.append(1)
        else:
            ratio = unsafe / total
            if ratio < 0.31:
                features.append(1)
            elif ratio <= 0.67:
                features.append(0)
            else:
                features.append(-1)
    except:
        features.append(0)
    # Links in Tags
    try:
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

            if ratio < 0.17:
                features.append(1)
            elif ratio <= 0.81:
                features.append(0)
            else:
                features.append(-1)

    except:
        features.append(0)
    # SFH
    try:
        forms = soup.find_all("form")
        if len(forms) == 0:
            features.append(1)

        else:
            action = forms[0].get("action")
            if action == "" or action is None:
                features.append(-1)

            elif action.startswith("http") and domain not in action:
                features.append(0)

            else:
                features.append(1)

    except:
        features.append(0)

    # Submitting to Email
    try:
        forms = soup.find_all("form")
        found = False
        for form in forms:
            action = str(form.get("action")).lower()
            if "mailto:" in action:
                found = True
                break

        features.append(-1 if found else 1)

    except:
        features.append(1)
    # Abnormal URL
    hostname = parsed.hostname if parsed.hostname else ""

    if domain in hostname:
        features.append(1)
    else:
        features.append(-1)
    # Redirect
    try:
        r = requests.get(
            url,
            allow_redirects=True,
            timeout=5,
            headers={"User-Agent":"Mozilla/5.0"}
        )
        if len(r.history) <= 1:
            features.append(1)
        elif len(r.history) <= 3:
            features.append(0)
        else:
            features.append(-1)

    except:
        features.append(0)

    # onMouseOver
    try:
        html = response.text.lower()

        if "onmouseover" in html:
            features.append(-1)
        else:
            features.append(1)

    except:
        features.append(0)
    # Right Click Disabled
    try:
        if "event.button==2" in html or "contextmenu" in html:
            features.append(-1)
        else:
            features.append(1)

    except:
        features.append(0)
    # Popup Window
    try:
        if "alert(" in html or "window.open(" in html:
            features.append(-1)
        else:
            features.append(1)
    except:
        features.append(0)
    # Iframe
    try:
        if "<iframe" in html:
            features.append(-1)
        else:
            features.append(1)
    except:
        features.append(0)

    # Age of Domain
    if isinstance(age, (int, float)):
        if age >= 2:
            features.append(1)
        elif age >= 1:
            features.append(0)
        else:
            features.append(-1)
    else:
        features.append(0)
    # DNS Record
    features.append(1 if dns_check(url) else -1)
    features.append(0)  # web_traffic
    features.append(0)  # Page_Rank
    features.append(0)  # Google_Index
    features.append(0)  # Links_pointing_to_page
    features.append(0)  # Statistical_report
    print("Feature Count =", len(features))
    print(features)

    return features

# -------------------------------
# SSL CHECK
# -------------------------------
def check_ssl(url):

    try:

        hostname = urlparse(url).hostname

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:

            with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                certificate = ssock.getpeercert()

                return True

    except:

        return False
    # -------------------------------
# DNS CHECK
# -------------------------------
def dns_check(url):

    try:

        domain = urlparse(url).netloc

        dns.resolver.resolve(domain, "A")

        return True

    except:

        return False


# -------------------------------
# DOMAIN AGE CHECK
# -------------------------------
def get_domain_age(domain):

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

            return "Not Available"

        from datetime import datetime, timezone
        creation_date = datetime.fromisoformat(
            creation_date.replace("Z", "+00:00")
            )
        print("Creation Date =", creation_date)
        age_days = ( datetime.now(timezone.utc) - creation_date).days
        age_years = round(age_days / 365, 1)
        return f"{age_years} years"

    except Exception as e:

        print("RDAP ERROR:", e)

        return "Not Available"
# -------------------------------
# BLACKLIST CHECK
# -------------------------------
def check_blacklist(url):

    blacklist_sources = [

        "https://openphish.com/feed.txt",

        "https://urlhaus.abuse.ch/downloads/text/"

    ]

    try:

        for source in blacklist_sources:

            response = requests.get(source, timeout=5)

            phishing_urls = response.text.splitlines()

            for bad_url in phishing_urls:

                bad_url = bad_url.strip()

                # skip comments
                if bad_url.startswith("#"):

                    continue

                if url.strip().lower() == bad_url.lower():

                    return True

        return False

    except Exception as e:

        print("BLACKLIST ERROR:", e)

        return False


# -------------------------------
# WEBSITE REPUTATION
# -------------------------------
def reputation_check(url):

    trusted_sites = [
        "google.com",
        "github.com",
        "microsoft.com",
        "openai.com",
        "amazon.com",
        "facebook.com",
        "youtube.com",
        "wikipedia.org",
        "instagram.com"
    ]

    suspicious_score = 0

    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix

    for trusted in trusted_sites:

        if trusted in domain:

            return "Trusted"

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "bank",
        "update",
        "reward",
        "gift"
    ]

    for word in suspicious_words:

        if word in url.lower():

            suspicious_score += 1

    if suspicious_score >= 2:

        return "Suspicious"

    return "Unknown"
# -------------------------------
# BRAND IMPERSONATION CHECK
# -------------------------------
def check_brand_impersonation(url):

    trusted_brands = [

        "google",
        "paypal",
        "amazon",
        "microsoft",
        "facebook",
        "github",
        "apple",
        "instagram",
        "netflix"

    ]

    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix
     # Genuine domains ni skip cheyyi
    if domain in [
        "google.com",
        "paypal.com",
        "amazon.com",
        "microsoft.com",
        "facebook.com",
        "github.com",
        "apple.com",
        "instagram.com",
        "netflix.com"
    ]:
        return False
    

    for brand in trusted_brands:

        if brand in domain:
            return True

        similarity = difflib.SequenceMatcher(
            None,
            domain.replace("-", ""),
            brand
        ).ratio()

        if similarity > 0.80:

            return True

    return False
# -------------------------------
# PHISHTANK CHECK
# -------------------------------
def check_phishtank(url):

        return False
# -------------------------------
# CONTENT ANALYSIS
# -------------------------------
def content_analysis(url):
    trusted = [
        "google.com",
        "github.com",
        "microsoft.com",
        "amazon.com",
        "paypal.com",
        "facebook.com"
    ]
    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix
    if domain in trusted:
        return [],0

    risks = []
    score = 0

    try:

        response = requests.get(
            url,
            timeout=5,
            headers={"User-Agent":"Mozilla/5.0"}
        )

        html = response.text.lower()

        soup = BeautifulSoup(html, "html.parser")

        suspicious_keywords = [

            "verify your account",
            "update payment",
            "confirm identity",
            "login now",
            "urgent action",
            "claim reward",
            "bank account",
            "password expired"

        ]

        for word in suspicious_keywords:

            if word in html:

                risks.append(f"Suspicious content: {word}")

                score += 10


        # password fields
        if soup.find("input", {"type":"password"}):

            risks.append("Password Input Detected")

            score += 15


        # iframe
        if soup.find("iframe"):

            risks.append("Iframe Detected")

            score += 10


        # external form actions
        forms = soup.find_all("form")

        for form in forms:

            action = form.get("action")

            if action and action.startswith("http"):

                risks.append("External Form Submission")

                score += 15


        return risks, score


    except Exception as e:

        print("CONTENT ANALYSIS ERROR:", e)

        return [],0


# -------------------------------
# RISK ANALYSIS
# -------------------------------
def analyze_risk(url):

    risks = []
    score = 0

    # no https
    if "https" not in url:

        risks.append("No HTTPS encryption")

        score += 10
    # URL Shortener
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "buff.ly"
    ]
    if any(s in url.lower() for s in shorteners):
        risks.append("URL Shortener Detected")
        score += 30

    # @ symbol
    if "@" in url:

        risks.append("Contains @ symbol")

        score += 20

    # too many hyphens
    if url.count("-") >= 2:

        risks.append("Too many hyphens")

        score += 15

    # suspicious words
    suspicious_words = [
        "login",
        "verify",
        "bank",
        "secure",
        "update",
        "payment",
        "confirm"
    ]

    for word in suspicious_words:

        if word in url.lower():

            risks.append(f"Suspicious keyword: {word}")

            score += 10

    # many numbers
    if sum(c.isdigit() for c in url) >= 5:

        risks.append("Too many numbers in URL")

        score += 15

    # suspicious TLDs
    suspicious_tlds = [
        ".tk",
        ".xyz",
        ".top",
        ".gq",
        ".ml",
        ".cf"
    ]

    for tld in suspicious_tlds:

        if tld in url.lower():

            risks.append(f"Suspicious extension: {tld}")

            score += 20

    return risks, score


# -------------------------------
# HOME
# -------------------------------
@app.route("/")
def home():

    return render_template("index.html")


# -------------------------------
# PREDICT
# -------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    print("PREDICT CALLED")

    url = request.form["url"]

    # ML
    features = extract_features(url)

    prediction = model.predict([features])[0]

    prob = model.predict_proba([features])[0]

    phishing_conf = min(prob[1] * 100,100)

    safe_conf = min(prob[0] * 100,100)

    # SSL
    ssl_valid = check_ssl(url)
    # DNS
    dns_valid = dns_check(url)

    # Brand spoofing
    brand_spoof = check_brand_impersonation(url)

    # Domain Age
    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix
    print("checking domain:", domain)
    age = get_domain_age(domain)

    # Blacklist
    blacklisted = (
    check_blacklist(url)
    or check_phishtank(url)
)

    # Reputation
    reputation = reputation_check(url)

    # Risk analysis
    risks, risk_score = analyze_risk(url)
    content_risks, content_score = content_analysis(url)
    risks.extend(content_risks)
    risk_score += content_score
    print("Initial RISKS:", risks,flush=True)
    print("Initial RISK SCORE:", risk_score, flush=True)
    print("CONTENT SCORE =", content_score)

    # SSL risk
    if not ssl_valid:

        risks.append("Invalid SSL Certificate")

        risk_score += 10
        print("After SSL :", risk_score)

    # New domain risk

    if isinstance(age, int) and age < 180:
        risks.append("Very New Domain")
        risk_score += 25
        print("After Domain Age :", risk_score)

    # Reputation risk
    if reputation == "Suspicious":

        risks.append("Low Website Reputation")

        risk_score += 20
        print("After Reputation :", risk_score)
        # DNS risk
    if not dns_valid:

        risks.append("DNS Record Not Found")
        risk_score += 25
        print("After DNS :", risk_score)


        # Brand spoofing risk
    if brand_spoof and (
        not ssl_valid
        or not dns_valid
        or blacklisted
    ):
        risks.append("Possible Brand Impersonation")
        risk_score += 20
        #limit risk score
        risk_score = min(risk_score,100)
        print("After Brand :", risk_score)
        print("FINAL RISKS :", risks)
       

    # Final Decision
    if blacklisted:

        display = "⚠️ Blacklisted Phishing Website!"

        confidence = 99

        status = "phishing"

    elif (
        prediction == 1
        or risk_score >= 50
        or (
            brand_spoof
            and (
                not ssl_valid
                or not dns_valid
                or blacklisted
                or risk_score >= 30
            )
        )
    ):
        display = "⚠️ Suspicious Website Detected!"
        confidence = max(phishing_conf, risk_score)
        status = "phishing"

    else:
        display = "✅ Safe Website"
        confidence = safe_conf
        status = "safe"
    confidence=min(confidence, 100)
    meter_color = "#22c55e" if status == "safe" else "#ef4444"

    return render_template(
    "index.html",
    prediction=display,
    url=url,
    confidence=round(confidence, 2),
    status=status,
    risks=risks,
    ssl_valid=ssl_valid,
    reputation=reputation,
    domain_age=age,
    dns_valid=dns_valid,
    brand_spoof=brand_spoof,
    risk_score=risk_score,
    meter_color=meter_color

)


# -------------------------------
# API
# -------------------------------
@app.route("/api/predict", methods=["POST"])
def api():

    url = request.json["url"]

    blacklisted = check_blacklist(url)

    reputation = reputation_check(url)

    return jsonify({
        "url": url,
        "blacklisted": blacklisted,
        "reputation": reputation
    })


# -------------------------------
# RUN
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)