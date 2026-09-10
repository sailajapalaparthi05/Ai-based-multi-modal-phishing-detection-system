"""
Browser Threat Detection Module
Combines MobileNetV2 screenshot DL, URL ML, SSL, DNS, reputation checks.
Accepts automatic metadata from Chrome Extension (no manual input).
Enhanced with real browser behavior analysis and form detection.
"""

import re
import time
from modules.browser_model import predict_screenshot, CLASS_LABELS
from modules.url_service import predict_url
from modules.phishing_checks import check_ssl, dns_check, reputation_check

SUSPICIOUS_TLDS = [".tk", ".xyz", ".top", ".gq", ".ml", ".cf", ".club", ".info", ".online", ".cc", ".ga", ".mn"]
URGENCY_WORDS = ["virus detected", "threat found", "infected", "hacked", "compromised", "security warning", "critical threat", "call support", "your computer is at risk"]
UPDATE_WORDS = ["update browser", "chrome is outdated", "browser update", "critical update", "flash player", "out of date", "update required", "install now"]
HIGH_RISK_PERMISSIONS = ["webRequest", "webRequestBlocking", "cookies", "declarativeNetRequest", "management", "debugger", "proxy", "tabs", "history"]
SUSPICIOUS_JS = ["eval(", "document.write(", "fromCharCode", "unescape(", "atob(", "crypto miner", "coinhive", "keylogger", "iframe", "script src"]
PHISHING_DOMAINS = ["login", "signin", "verify", "account", "secure", "banking", "payment", "wallet", "crypto"]

# NEW: Trusted domains for legitimate login forms
TRUSTED_DOMAINS = ["google.com", "instagram.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "linkedin.com", "twitter.com", "paypal.com", "ebay.com", "netflix.com", "appleid.apple.com", "accounts.google.com", "login.microsoftonline.com"]


def analyze_browser_threat(metadata):
    """
    Analyze browser threat from automatically collected metadata.

    metadata keys:
      current_url, redirect_chain, popup_messages, fake_update_detected,
      notification_requests, auto_downloads, ssl_status, extension_permissions,
      suspicious_js, screenshot_b64
      NEW: login_form_detected, password_field_count, username_field_count,
           email_field_count, payment_form_detected, sensitive_field_types,
           form_action_external, external_form_domains, current_domain,
           is_trusted_domain
    """
    current_url = metadata.get("current_url", "")
    redirect_chain = metadata.get("redirect_chain", [])
    if isinstance(redirect_chain, str):
        redirect_chain = [u.strip() for u in re.split(r'\s*->\s*|\n|,', redirect_chain) if u.strip()]
    popup_messages = metadata.get("popup_messages", [])
    if isinstance(popup_messages, str):
        popup_messages = [popup_messages]
    page_content = " ".join(popup_messages).lower()
    extension_permissions = metadata.get("extension_permissions", [])
    if isinstance(extension_permissions, str):
        extension_permissions = [p.strip() for p in re.split(r'[,;\n]', extension_permissions) if p.strip()]
    suspicious_js = metadata.get("suspicious_js", [])
    screenshot_b64 = metadata.get("screenshot_b64", "")
    fake_update = metadata.get("fake_update_detected", False)
    notification_requests = metadata.get("notification_requests", 0)
    auto_downloads = metadata.get("auto_downloads", [])
    new_tabs_count = metadata.get("new_tabs_count", 0)
    sensitive_forms_detected = metadata.get("sensitive_forms_detected", False)
    alert_count = metadata.get("alert_count", 0)
    popup_attempts = metadata.get("popup_attempts", 0)
    fullscreen_attempts = metadata.get("fullscreen_attempts", 0)
    
    # NEW: Enhanced form analysis fields
    login_form_detected = metadata.get("login_form_detected", False)
    password_field_count = metadata.get("password_field_count", 0)
    username_field_count = metadata.get("username_field_count", 0)
    email_field_count = metadata.get("email_field_count", 0)
    payment_form_detected = metadata.get("payment_form_detected", False)
    sensitive_field_types = metadata.get("sensitive_field_types", [])
    form_action_external = metadata.get("form_action_external", False)
    external_form_domains = metadata.get("external_form_domains", [])
    current_domain = metadata.get("current_domain", "")
    is_trusted_domain = metadata.get("is_trusted_domain", False)

    all_urls = list(redirect_chain)
    if current_url and current_url not in all_urls:
        all_urls.insert(0, current_url)

    # Deep Learning — MobileNetV2 screenshot classification
    dl_result = predict_screenshot(screenshot_b64)
    dl_threat = dl_result["class_index"] != 0
    dl_conf = dl_result["confidence"]

    # URL ML prediction on current URL
    url_result = None
    url_risk = 0
    if current_url:
        try:
            url_result = predict_url(current_url)
            url_risk = url_result["risk_score"]
        except Exception as e:
            print(f"Browser URL scan error: {e}")

    # SSL / DNS / Reputation
    ssl_valid = metadata.get("ssl_status", True)
    if current_url:
        ssl_valid = check_ssl(current_url) if metadata.get("ssl_status") is None else bool(metadata.get("ssl_status"))
    dns_valid = dns_check(current_url) if current_url else True
    reputation = reputation_check(current_url) if current_url else "Unknown"

    # Heuristic analysis
    risks = []
    heuristic_score = 0
    redirect_len = max(0, len(all_urls) - 1)

    if redirect_len >= 3:
        risks.append(f"Excessive redirect hops ({redirect_len} redirects)")
        heuristic_score += 25
    elif redirect_len == 1:
        # Single redirect is normal behavior, treat as weak/no evidence
        pass  # No risk increase for single redirect

    for url in all_urls:
        for tld in SUSPICIOUS_TLDS:
            if tld in url.lower():
                risks.append(f"Suspicious TLD in redirect chain: {url}")
                heuristic_score += 20
                break

    for word in URGENCY_WORDS:
        if word in page_content:
            risks.append(f"Scareware popup pattern: '{word}'")
            heuristic_score += 25
            break

    for word in UPDATE_WORDS:
        if word in page_content:
            risks.append(f"Fake browser update indicator: '{word}'")
            heuristic_score += 25
            break

    if fake_update:
        risks.append("Fake browser update page automatically detected")
        heuristic_score += 30

    if notification_requests > 2:
        risks.append(f"Excessive notification permission requests ({notification_requests})")
        heuristic_score += 15

    if auto_downloads:
        risks.append(f"Automatic downloads triggered: {', '.join(auto_downloads[:3])}")
        heuristic_score += 25

    # NEW: Browser behavior detection
    if new_tabs_count > 0:
        risks.append(f"New tabs/popups opened: {new_tabs_count}")
        heuristic_score += min(new_tabs_count * 15, 30)

    if sensitive_forms_detected:
        risks.append("Sensitive form fields detected on page")
        heuristic_score += 20

    if alert_count > 3:
        risks.append(f"Excessive alert dialogs: {alert_count}")
        heuristic_score += min(alert_count * 10, 25)

    if popup_attempts > 2:
        risks.append(f"Multiple popup windows: {popup_attempts}")
        heuristic_score += min(popup_attempts * 10, 25)

    if fullscreen_attempts > 1:
        risks.append(f"Fullscreen abuse detected: {fullscreen_attempts}")
        heuristic_score += 20

    # NEW: Enhanced form behavior analysis
    # Login form detection with trusted domain consideration
    if login_form_detected:
        if is_trusted_domain:
            # Normal login form on trusted domain - minimal risk
            risks.append(f"Login form detected on trusted domain: {current_domain}")
            heuristic_score += 0  # No risk increase for trusted domains
        else:
            # Login form on unknown domain - significant risk
            risks.append(f"Login form detected on unknown domain: {current_domain}")
            heuristic_score += 20
            # Additional risk if password field present
            if password_field_count > 0:
                risks.append(f"Password field detected on untrusted domain")
                heuristic_score += 10

    # Payment form detection
    if payment_form_detected:
        if is_trusted_domain:
            risks.append(f"Payment form detected on trusted domain: {current_domain}")
            heuristic_score += 5  # Small risk even on trusted domain
        else:
            risks.append(f"Payment form detected on untrusted domain: {current_domain}")
            heuristic_score += 30

    # Form action analysis
    if form_action_external:
        risks.append(f"Form submits to external domain: {', '.join(external_form_domains)}")
        heuristic_score += 25
        
        # Additional risk if password form submits externally
        if password_field_count > 0:
            risks.append("Password form submits to external domain")
            heuristic_score += 30
        
        # Additional risk if payment form submits externally
        if payment_form_detected:
            risks.append("Payment form submits to external domain")
            heuristic_score += 35

    # Multiple sensitive field types
    if len(sensitive_field_types) > 2:
        risks.append(f"Multiple sensitive field types detected: {', '.join(sensitive_field_types[:3])}")
        heuristic_score += 15

    # Extension permissions are metadata about the Chrome extension, NOT evidence of phishing
    # Only treat extremely broad permissions as weak evidence, not normal permissions like "tabs"
    extremely_broad_perms = [p for p in extension_permissions if any(h in p.lower() for h in ["<all_urls>", "*://*", "management", "debugger", "proxy"])]
    if extremely_broad_perms:
        risks.append(f"Extremely broad extension permissions: {', '.join(extremely_broad_perms[:2])}")
        heuristic_score += min(len(extremely_broad_perms) * 5, 10)  # Reduced weight

    for js_pattern in suspicious_js:
        risks.append(f"Suspicious JavaScript behaviour: {js_pattern}")
        heuristic_score += 10

    for pattern in SUSPICIOUS_JS:
        if pattern in page_content:
            risks.append(f"Malicious JS pattern in page: {pattern}")
            heuristic_score += 15

    # Additional domain pattern analysis
    if current_url:
        from urllib.parse import urlparse
        domain = urlparse(current_url).netloc.lower()
        
        # Check for phishing-related keywords in domain
        for phishing_word in PHISHING_DOMAINS:
            if phishing_word in domain:
                risks.append(f"Phishing-related keyword in domain: {phishing_word}")
                heuristic_score += 20
                break
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            risks.append(f"Excessive subdomain count: {subdomain_count}")
            heuristic_score += 15
        
        # Check for numeric patterns in domain (often used in phishing)
        if re.search(r'\d{2,}', domain.split('.')[0]):
            risks.append("Numeric patterns in subdomain")
            heuristic_score += 10
        
        # Check for IP address in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', current_url):
            risks.append("IP address used instead of domain name")
            heuristic_score += 30

    if not ssl_valid:
        risks.append("Invalid or missing SSL certificate")
        heuristic_score += 15
    if not dns_valid:
        risks.append("DNS resolution failed for current URL")
        heuristic_score += 20
    if reputation == "Suspicious":
        risks.append("Low domain reputation")
        heuristic_score += 10

    # Only add DL classification as a risk if it's a high-confidence threat
    # Low-confidence DL predictions should not override other evidence
    if dl_result["class_label"] != "Legitimate" and dl_conf > 70:
        risks.append(f"DL Visual Classification: {dl_result['class_label']} ({dl_conf}% confidence)")

    if url_result and url_result["verdict"] == "phishing" and url_risk > 60:
        risks.extend(url_result["risks"][:3])

    heuristic_score = min(heuristic_score, 100)

    # Improved weighted scoring system with confidence calibration
    # Each signal contributes independently, no single signal can override others
    
    # Base risk from URL ML model (most reliable for domain analysis)
    url_weight = 0.30
    url_contribution = url_risk * url_weight
    
    # DL visual classifier (supporting evidence only, not decision-maker)
    # The DL model was trained on synthetic images, so it should have limited influence
    dl_weight = 0.20  # Reduced from 0.35
    dl_contribution = dl_conf * dl_weight if dl_threat else 0
    
    # Heuristic analysis (behavioral patterns)
    heuristic_weight = 0.50  # Increased from 0.35
    heuristic_contribution = heuristic_score * heuristic_weight
    
    # Combined score without single-signal overrides
    combined = url_contribution + dl_contribution + heuristic_contribution
    combined = min(round(combined, 2), 100.0)
    
    # Strong security signals should reduce risk
    security_bonus = 0
    if ssl_valid and dns_valid and reputation == "Trusted":
        security_bonus = 15  # Strong security signals reduce risk
    if is_trusted_domain:
        security_bonus += 10  # Trusted domain bonus
    
    # Apply security bonus
    combined = max(0, combined - security_bonus)
    
    # Final verdict requires multiple independent signals, not just one
    # Safe if: low combined score AND no single critical threat
    # Phishing if: high combined score OR multiple independent threats
    
    critical_threats = 0
    if dl_threat and dl_conf > 80:  # Very high DL confidence
        critical_threats += 1
    if url_result and url_result["verdict"] == "phishing" and url_risk > 70:
        critical_threats += 1
    if heuristic_score > 60:  # High heuristic score
        critical_threats += 1
    if not ssl_valid and not dns_valid:  # Both SSL and DNS failed
        critical_threats += 1
    
    # Verdict logic: require strong evidence for phishing
    if combined >= 60 or critical_threats >= 2:
        verdict = "phishing"
    elif combined >= 40 and critical_threats >= 1:
        verdict = "phishing"
    else:
        verdict = "safe"
    
    # Confidence calculation
    if verdict == "phishing":
        confidence = combined
    else:
        confidence = round(100 - combined, 2)
    
    confidence = min(max(confidence, 0), 100.0)

    display = "⚠️ Suspicious Browser Threat!" if verdict == "phishing" else "✅ Safe Browser Session"
    
    # Add scan timestamp
    scan_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    features = [
        f"Redirect Chain Length: {redirect_len}",
        f"DL Prediction: {dl_result['class_label']} ({dl_conf}%)",
        f"URL ML Risk Score: {url_risk}/100",
        f"SSL Valid: {ssl_valid}",
        f"DNS Valid: {dns_valid}",
        f"Reputation: {reputation}",
        f"Heuristic Score: {heuristic_score}/100",
        f"Popup Messages: {len(popup_messages)}",
        f"Auto Downloads: {len(auto_downloads)}",
        f"Notification Requests: {notification_requests}",
        f"Suspicious JS Patterns: {len(suspicious_js)}",
        f"Extension Permissions: {len(extension_permissions)}",
        f"New Tabs/Popups: {new_tabs_count}",
        f"Alert Dialogs: {alert_count}",
        f"Popup Attempts: {popup_attempts}",
        f"Fullscreen Attempts: {fullscreen_attempts}",
        # NEW: Form analysis features
        f"Login Form Detected: {'Yes' if login_form_detected else 'No'}",
        f"Password Fields: {password_field_count}",
        f"Username/Email Fields: {username_field_count + email_field_count}",
        f"Payment Form Detected: {'Yes' if payment_form_detected else 'No'}",
        f"Form Action External: {'Yes' if form_action_external else 'No'}",
        f"Trusted Domain: {'Yes' if is_trusted_domain else 'No'}",
    ]

    return {
        "verdict": verdict,
        "display": display,
        "confidence": round(confidence, 2),
        "risk_score": combined,
        "dl_result": dl_result,
        "dl_prediction": dl_result["class_label"],
        "url_result": url_result,
        "risks": risks,
        "heuristic_score": heuristic_score,
        "features": features,
        "ssl_valid": ssl_valid,
        "dns_valid": dns_valid,
        "reputation": reputation,
        "redirect_len": redirect_len,
        "current_url": current_url,
        "screenshot_b64": screenshot_b64[:100] + "..." if len(screenshot_b64) > 100 else screenshot_b64,
        "screenshot_preview": screenshot_b64,
        "model_probabilities": dl_result.get("probabilities", {}),
        "scan_timestamp": scan_timestamp,
        "notification_requests": notification_requests,
        "fake_update_detected": fake_update,
        "popup_messages_count": len(popup_messages),
        "auto_downloads_count": len(auto_downloads),
        "new_tabs_count": new_tabs_count,
        "sensitive_forms_detected": sensitive_forms_detected,
        "alert_count": alert_count,
        "popup_attempts": popup_attempts,
        "fullscreen_attempts": fullscreen_attempts,
        # NEW: Enhanced form analysis response fields
        "login_form_detected": login_form_detected,
        "password_field_count": password_field_count,
        "username_field_count": username_field_count,
        "email_field_count": email_field_count,
        "payment_form_detected": payment_form_detected,
        "sensitive_field_types": sensitive_field_types,
        "form_action_external": form_action_external,
        "external_form_domains": external_form_domains,
        "current_domain": current_domain,
        "is_trusted_domain": is_trusted_domain,
    }
