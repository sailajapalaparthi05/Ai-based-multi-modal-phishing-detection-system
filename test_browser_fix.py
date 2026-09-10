"""
Test the browser detection fix for false positives.
Tests legitimate websites to ensure they are correctly classified as SAFE.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.browser import analyze_browser_threat

def test_legitimate_websites():
    """Test that legitimate websites are correctly classified as SAFE."""
    
    print("="*70)
    print("BROWSER DETECTION FALSE POSITIVE FIX TEST")
    print("="*70)
    
    # Test case 1: Google.com (the reported false positive)
    google_test = {
        "current_url": "https://www.google.com",
        "redirect_chain": ["https://www.google.com"],
        "popup_messages": [],
        "extension_permissions": ["tabs", "storage", "webNavigation"],  # Normal Chrome permissions
        "screenshot_b64": "",  # No screenshot for this test
        "ssl_status": True,
        "fake_update_detected": False,
        "notification_requests": 0,
        "auto_downloads": [],
        "new_tabs_count": 0,
        "sensitive_forms_detected": False,
        "alert_count": 0,
        "popup_attempts": 0,
        "fullscreen_attempts": 0,
        "login_form_detected": True,  # Google has login forms
        "password_field_count": 1,
        "username_field_count": 1,
        "email_field_count": 0,
        "payment_form_detected": False,
        "sensitive_field_types": ["password", "username"],
        "form_action_external": False,
        "external_form_domains": [],
        "current_domain": "google.com",
        "is_trusted_domain": True  # This is key - Google is a trusted domain
    }
    
    print("\n[TEST 1] Testing Google.com...")
    result = analyze_browser_threat(google_test)
    print(f"URL: {result['current_url']}")
    print(f"Final Verdict: {result['verdict'].upper()}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Confidence: {result['confidence']}%")
    print(f"URL Model Result: {result['url_result']['verdict'] if result['url_result'] else 'N/A'}")
    print(f"DL Visual Result: {result['dl_prediction']}")
    print(f"SSL: {result['ssl_valid']}")
    print(f"DNS: {result['dns_valid']}")
    print(f"Reputation: {result['reputation']}")
    print(f"Redirects: {result['redirect_len']}")
    print(f"Trusted Domain: {result['is_trusted_domain']}")
    print(f"Threat Reasons: {result['risks']}")
    
    # Test case 2: Microsoft.com
    microsoft_test = {
        "current_url": "https://www.microsoft.com",
        "redirect_chain": ["https://www.microsoft.com"],
        "popup_messages": [],
        "extension_permissions": ["tabs", "storage"],
        "screenshot_b64": "",
        "ssl_status": True,
        "fake_update_detected": False,
        "notification_requests": 0,
        "auto_downloads": [],
        "new_tabs_count": 0,
        "sensitive_forms_detected": False,
        "alert_count": 0,
        "popup_attempts": 0,
        "fullscreen_attempts": 0,
        "login_form_detected": True,
        "password_field_count": 1,
        "username_field_count": 1,
        "email_field_count": 1,
        "payment_form_detected": False,
        "sensitive_field_types": ["password", "username", "email"],
        "form_action_external": False,
        "external_form_domains": [],
        "current_domain": "microsoft.com",
        "is_trusted_domain": True
    }
    
    print("\n[TEST 2] Testing Microsoft.com...")
    result = analyze_browser_threat(microsoft_test)
    print(f"URL: {result['current_url']}")
    print(f"Final Verdict: {result['verdict'].upper()}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Confidence: {result['confidence']}%")
    print(f"Trusted Domain: {result['is_trusted_domain']}")
    print(f"Threat Reasons: {result['risks']}")
    
    # Test case 3: Wikipedia.org
    wikipedia_test = {
        "current_url": "https://www.wikipedia.org",
        "redirect_chain": ["https://www.wikipedia.org"],
        "popup_messages": [],
        "extension_permissions": ["tabs", "storage"],
        "screenshot_b64": "",
        "ssl_status": True,
        "fake_update_detected": False,
        "notification_requests": 0,
        "auto_downloads": [],
        "new_tabs_count": 0,
        "sensitive_forms_detected": False,
        "alert_count": 0,
        "popup_attempts": 0,
        "fullscreen_attempts": 0,
        "login_form_detected": False,
        "password_field_count": 0,
        "username_field_count": 0,
        "email_field_count": 0,
        "payment_form_detected": False,
        "sensitive_field_types": [],
        "form_action_external": False,
        "external_form_domains": [],
        "current_domain": "wikipedia.org",
        "is_trusted_domain": True
    }
    
    print("\n[TEST 3] Testing Wikipedia.org...")
    result = analyze_browser_threat(wikipedia_test)
    print(f"URL: {result['current_url']}")
    print(f"Final Verdict: {result['verdict'].upper()}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Confidence: {result['confidence']}%")
    print(f"Trusted Domain: {result['is_trusted_domain']}")
    print(f"Threat Reasons: {result['risks']}")
    
    # Test case 4: Suspicious phishing-style page
    phishing_test = {
        "current_url": "http://secure-login-update-account.xyz",
        "redirect_chain": ["http://secure-login-update-account.xyz"],
        "popup_messages": ["URGENT: Your account will be suspended"],
        "extension_permissions": ["tabs", "storage"],
        "screenshot_b64": "",
        "ssl_status": False,
        "fake_update_detected": True,
        "notification_requests": 5,
        "auto_downloads": ["suspicious.exe"],
        "new_tabs_count": 3,
        "sensitive_forms_detected": True,
        "alert_count": 4,
        "popup_attempts": 3,
        "fullscreen_attempts": 2,
        "login_form_detected": True,
        "password_field_count": 2,
        "username_field_count": 1,
        "email_field_count": 0,
        "payment_form_detected": False,
        "sensitive_field_types": ["password", "username", "ssn"],
        "form_action_external": True,
        "external_form_domains": ["http://steal-data.com"],
        "current_domain": "secure-login-update-account.xyz",
        "is_trusted_domain": False
    }
    
    print("\n[TEST 4] Testing suspicious phishing-style page...")
    result = analyze_browser_threat(phishing_test)
    print(f"URL: {result['current_url']}")
    print(f"Final Verdict: {result['verdict'].upper()}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Confidence: {result['confidence']}%")
    print(f"Trusted Domain: {result['is_trusted_domain']}")
    print(f"Threat Reasons: {result['risks']}")
    
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print("Expected Results:")
    print("Google.com -> SAFE")
    print("Microsoft.com -> SAFE") 
    print("Wikipedia.org -> SAFE")
    print("Phishing page -> PHISHING")
    print("="*70)

if __name__ == "__main__":
    test_legitimate_websites()
