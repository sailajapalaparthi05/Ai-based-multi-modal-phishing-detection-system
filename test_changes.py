"""
Quick Test Script to Verify SMS and QR Changes
Run this to verify the backend changes are working
"""

print("="*70)
print(" TESTING SMS DETECTION CHANGES")
print("="*70)

from modules.sms_service import analyze_sms

# Test 1: Legitimate OTP (HirePro)
print("\nTest 1: HirePro Legitimate OTP")
print("-" * 70)
result = analyze_sms("Use OTP EFF610 to verify your mobile number. Valid for 10 mins. Please do not share it with anyone - By HirePro")
print(f"Verdict: {result['verdict']}")
print(f"Risk Score: {result['risk_score']}/100")
print(f"Confidence: {result['confidence']}%")
print(f"Reasons: {result['reasons']}")
print(f"Expected: SAFE with risk score < 10")
print(f"Status: {'PASS' if result['verdict'] == 'safe' and result['risk_score'] < 10 else 'FAIL'}")

# Test 2: Malicious OTP Theft
print("\nTest 2: Malicious OTP Theft")
print("-" * 70)
result = analyze_sms("Your account will be suspended. Send your OTP immediately to confirm your identity.")
print(f"Verdict: {result['verdict']}")
print(f"Risk Score: {result['risk_score']}/100")
print(f"Confidence: {result['confidence']}%")
print(f"Reasons: {result['reasons']}")
print(f"Expected: PHISHING with risk score > 50")
print(f"Status: {'PASS' if result['verdict'] == 'phishing' and result['risk_score'] > 50 else 'FAIL'}")

print("\n" + "="*70)
print(" TESTING QR URL ANALYSIS CHANGES")
print("="*70)

from app import analyze_qr_url

# Test 3: GitHub Login URL
print("\nTest 3: GitHub Login URL")
print("-" * 70)
result = analyze_qr_url("https://github.com/login")
print(f"Success: {result['success']}")
print(f"Extracted URL: {result.get('extracted_url')}")
print(f"Domain Age: {result.get('domain_age')}")
print(f"Reputation: {result.get('reputation')}")
print(f"SSL: {result.get('ssl_valid')}")
print(f"DNS: {result.get('dns_valid')}")
print(f"Expected: Complete analysis with all fields")
print(f"Status: {'PASS' if result['success'] and result.get('domain_age') != 'Not Available' else 'FAIL'}")

print("\n" + "="*70)
print(" SUMMARY")
print("="*70)
print("If all tests show PASS, the changes are working correctly.")
print("If FAIL, the changes may not have been saved or loaded.")
print("="*70)
