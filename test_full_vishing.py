"""
Test complete Vishing detection pipeline
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.vishing_service import analyze_vishing_call

# Test with the converted WAV file
print("Testing complete Vishing detection pipeline with test_converted.wav...")
result = analyze_vishing_call("test_converted.wav")

print("\n" + "=" * 70)
print("VISHING DETECTION RESULT")
print("=" * 70)
print(f"Success: {result.get('success')}")
print(f"Status: {result.get('status')}")
print(f"Prediction: {result.get('prediction')}")
print(f"Confidence: {result.get('confidence')}%")
print(f"Risk Score: {result.get('risk_score')}/100")
print(f"Transcription: {result.get('transcription')}")
print(f"Reasons: {result.get('reasons')}")
print(f"Pattern Count: {result.get('pattern_count')}")
print("=" * 70)
