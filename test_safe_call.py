"""
Test with a safe call to check false positive issue
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.vishing_service import analyze_vishing_call

# Test with the converted WAV file
print("Testing with simulated safe call transcription...")
print("Creating safe transcription for testing...")

# Simulate the actual safe call transcription
safe_transcription = "Hello, this is a customer service call. We are calling to provide information about your account. There is no urgent action required. You do not need to share your password, OTP, PIN, or banking details. If you have any questions, please contact our official customer support through the website."

# Directly test the pattern detection and risk calculation
from modules.vishing_service import detect_vishing_patterns, calculate_risk_score, classify_vishing, detect_legitimate_call_indicators

patterns = detect_vishing_patterns(safe_transcription)
print(f"Patterns detected: {patterns}")

legitimate_indicators = detect_legitimate_call_indicators(safe_transcription)
print(f"Legitimate indicators: {legitimate_indicators}")

risk_score = calculate_risk_score(patterns)
print(f"Risk score: {risk_score}/100")

ml_prediction, ml_confidence = classify_vishing(safe_transcription)
print(f"ML prediction: {ml_prediction}")
print(f"ML confidence: {ml_confidence}%")

# Final verdict logic (new with legitimate call detection)
ml_prediction_str = "vishing" if ml_prediction == 1 or ml_prediction == "vishing" else "safe"
credential_patterns = ["OTP request detected", "PIN request detected", "CVV/security code request detected", "Password request detected"]
has_credential_request = any(p in credential_patterns for p in patterns)

if len(legitimate_indicators) >= 1:
    verdict = "Safe"
    print("Legitimate call indicators detected - classifying as Safe")
elif has_credential_request and risk_score >= 70:
    verdict = "Vishing"
elif ml_prediction_str == "vishing" and ml_confidence >= 80 and risk_score >= 60:
    verdict = "Vishing"
else:
    verdict = "Safe"

print(f"Final verdict: {verdict}")
print(f"Has credential request: {has_credential_request}")
print(f"ML confidence: {ml_confidence}%")
print(f"Risk score: {risk_score}/100")
