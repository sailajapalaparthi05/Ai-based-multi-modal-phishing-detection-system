"""
Shared URL phishing prediction service.
Reuses the ensemble ML model and heuristics without circular Flask imports.
"""

import joblib
import pandas as pd
import os

FEATURE_NAMES = [
    'having_IPhaving_IP_Address', 'URLURL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
    'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]

_MODEL = None


def _get_model():
    global _MODEL
    if _MODEL is None:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _MODEL = joblib.load(os.path.join(base, "model", "phishing_model.pkl"))
    return _MODEL


def predict_url(url):
    """Run full URL phishing analysis. Returns dict with prediction details."""
    from modules.phishing_checks import (
        extract_features,
        check_ssl,
        dns_check,
        check_blacklist,
        check_brand_impersonation,
        reputation_check,
        analyze_risk,
        content_analysis,
        get_domain_age,
        get_domain_age_years,
        check_phishtank,
    )
    import tldextract

    url = url.strip()
    if not url:
        return {"url": url, "verdict": "safe", "confidence": 0, "risk_score": 0, "risks": []}

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    model = _get_model()
    features = extract_features(url)
    df_features = pd.DataFrame([features], columns=FEATURE_NAMES)
    prediction = int(model.predict(df_features)[0])
    prob = model.predict_proba(df_features)[0]

    phishing_conf = min(prob[1] * 100, 100)
    safe_conf = min(prob[0] * 100, 100)

    ssl_valid = check_ssl(url)
    dns_valid = dns_check(url)
    brand_spoof = check_brand_impersonation(url)
    blacklisted = check_blacklist(url) or check_phishtank(url)
    reputation = reputation_check(url)

    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix if ext.suffix else ext.domain
    age_years = get_domain_age_years(domain)

    risks, risk_score = analyze_risk(url)
    content_risks, content_score = content_analysis(url)
    risks.extend(content_risks)
    risk_score += content_score

    if not ssl_valid:
        risks.append("Invalid SSL Certificate")
        risk_score += 15
    if age_years is not None and age_years < 0.5:
        risks.append("Very New Domain (< 6 months)")
        risk_score += 20
    if reputation == "Unknown":
        risks.append("Low Website Reputation")
        risk_score += 10
    if not dns_valid:
        risks.append("DNS Record Not Found")
        risk_score += 30
    if brand_spoof:
        risks.append("Possible Brand Impersonation / Typosquatting")
        risk_score += 25

    risk_score = min(risk_score, 100)

    if blacklisted:
        verdict = "phishing"
        confidence = 99.0
    elif prediction == 1 or risk_score >= 50:
        verdict = "phishing"
        confidence = max(phishing_conf, float(risk_score))
    else:
        verdict = "safe"
        confidence = safe_conf

    return {
        "url": url,
        "verdict": verdict,
        "confidence": round(min(confidence, 100.0), 2),
        "risk_score": risk_score,
        "risks": risks,
        "ssl_valid": ssl_valid,
        "dns_valid": dns_valid,
        "reputation": reputation,
        "brand_spoof": brand_spoof,
        "blacklisted": blacklisted,
        "ml_prediction": prediction,
        "ml_probabilities": {"safe": round(prob[0], 4), "phishing": round(prob[1], 4)},
        "domain_age": get_domain_age(domain),
    }
