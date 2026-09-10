"""
Vishing multilingual test scripts.

Usage:
    py -3.12 test_vishing_multilingual.py

Tests the vishing detection pipeline with Hindi, Telugu, and English
transcripts containing obvious phishing content, plus safe-call control
tests.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.vishing_service import (
    detect_vishing_patterns,
    calculate_risk_score,
    detect_legitimate_call_indicators,
)


# ---------------------------------------------------------------------------
# Classification helper — mirrors the logic in analyze_vishing_call()
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS = [
    "OTP request detected",
    "PIN request detected",
    "CVV/security code request detected",
    "Password request detected",
]

CONTEXTUAL_PATTERNS = [
    "Bank/government impersonation detected",
    "Government/official impersonation detected",
    "Urgent/threatening language detected",
    "Threatening language detected",
    "Account blocking threat detected",
]


def classify(transcription):
    """Return (verdict, risk_score, reasons) for a transcribed text."""

    patterns = detect_vishing_patterns(transcription)
    risk = calculate_risk_score(patterns)
    legit = detect_legitimate_call_indicators(transcription)

    has_cred = any(p in CREDENTIAL_PATTERNS for p in patterns)
    has_ctx = any(p in CONTEXTUAL_PATTERNS for p in patterns)

    # Strong evidence: credential request + contextual threat
    if has_cred and has_ctx:
        verdict = "Vishing"

    # Legitimate phrase + no credential request + low risk
    elif len(legit) >= 1 and not has_cred and risk < 40:
        verdict = "Safe"

    # High risk alone
    elif risk >= 80:
        verdict = "Vishing"
    else:
        verdict = "Safe"

    return verdict, risk, patterns, legit


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

HINDI_PHISHING_1 = (
    "नमस्ते सर, मैं आपके बैंक के कस्टमर सपोर्ट से बात कर रही हूँ। "
    "आपके अकाउंट में एक सुरक्षा समस्या पाई गई है। "
    "आपके मोबाइल पर एक OTP आएगा। कृपया वह OTP मुझे बताइए। "
    "अपना ATM PIN और CVV भी बताइए। अगर आपने ये जानकारी "
    "तुरंत नहीं दी, तो आपका अकाउंट ब्लॉक कर दिया जाएगा।"
)

HINDI_PHISHING_2 = (
    "आपके बैंक अकाउं� को बंद होने से बचाने के लिए OTP, ATM PIN "
    "और CVV बताइए। अगर अभी नहीं बताया तो अकाउंट ब्लॉक कर देंगे।"
)

TELUGU_PHISHING_1 = (
    "హలో సార్, నేను మీ బ్యాంక్ కస్టమర్ సపోర్ట్ నుంచి "
    "మాట్లాడుతున్నాను. మీ అకౌంట్‌లో సెక్యూరిటీ సమస్య ఉంది. "
    "మీ మొబైల్‌కు ఒక OTP వస్తుంది. కృపయా ఆ OTP నాకు చెప్పండి. "
    "మీ ATM PIN మరియు CVV కూడా చెప్పండి. "
    "ఇవి ఇవ్వకపోతే మీ అకౌంట్‌ను వెంటనే బ్లాక్ చేస్తాము."
)

TELUGU_PHISHING_2 = (
    "మీ బ్యాంక్ అకౌంట్‌ను బ్లాక్ చేయకుండా ఉండటానికి "
    "మీకు వచ్చిన OTP చెప్పండి. మీ ATM PIN మరియు CVV కూడా "
    "చెప్పండి. ఇప్పుడే చెప్పకపోతే అకౌంట్ బ్లాక్ చేస్తాము."
)

ENGLISH_PHISHING = (
    "Hello sir, this is your bank customer support. Your account "
    "will be blocked due to security issues. Please provide your OTP "
    "code, ATM PIN and CVV immediately or your account will be suspended."
)

SAFE_TELUGU = (
    "మీ హాస్పిటల్ అపాయింట్మెంట్ రేపు ఉదయం 10 గంటలకు "
    "కన్ఫర్మ్ అయింది. ఏవైనా మార్పులు ఉంటే "
    "హాస్పిటల్ రిసెప్షన్ ను సంప్రదించండి."
)

SAFE_ENGLISH = (
    "This is an informational call about your account balance. "
    "No action is required at this time. Thank you for your time."
)

TESTS = [
    # (name, text, expected_verdict)
    ("Hindi Phishing 1",   HINDI_PHISHING_1,  "Vishing"),
    ("Hindi Phishing 2",   HINDI_PHISHING_2,  "Vishing"),
    ("Telugu Phishing 1",  TELUGU_PHISHING_1, "Vishing"),
    ("Telugu Phishing 2",  TELUGU_PHISHING_2, "Vishing"),
    ("English Phishing",   ENGLISH_PHISHING,   "Vishing"),
    ("Safe Telugu",        SAFE_TELUGU,        "Safe"),
    ("Safe English",       SAFE_ENGLISH,       "Safe"),
]


def main():
    print("=" * 70)
    print("VISHING MULTILINGUAL TESTS")
    print("=" * 70)

    all_pass = True

    for name, text, expected in TESTS:
        verdict, risk, reasons, _legit = classify(text)
        ok = "PASS" if verdict == expected else "FAIL"
        if verdict != expected:
            all_pass = False

        print(f"\n[{ok}] {name}")
        print(f"  Expected: {expected}")
        print(f"  Got:      {verdict}")
        print(f"  Risk:     {risk}/100")
        print(f"  Reasons:  {reasons}")

    print("\n" + "=" * 70)
    print("ALL TESTS PASSED" if all_pass else "SOME TESTS FAILED")
    print("=" * 70)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
