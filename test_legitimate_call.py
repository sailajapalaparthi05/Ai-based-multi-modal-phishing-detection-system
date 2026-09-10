"""
Test with legitimate call using the actual vishing service
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.vishing_service import analyze_vishing_call

# Create a temporary WAV file with the safe transcription
import tempfile
import wave

def create_test_wav(transcription_text, output_file):
    """Create a simple test WAV file with text converted to speech"""
    # For now, we'll just test the transcription logic directly
    # since we can't easily create speech from text without TTS
    pass

# Test the actual safe call
safe_transcription = "Hello, this is a customer service call. We are calling to provide information about your account. There is no urgent action required. You do not need to share your password, OTP, PIN, or banking details. If you have any questions, please contact our official customer support through the website."

# Test pattern detection directly
from modules.vishing_service import detect_vishing_patterns, detect_legitimate_call_indicators

patterns = detect_vishing_patterns(safe_transcription)
print(f"Patterns detected: {patterns}")

legitimate_indicators = detect_legitimate_call_indicators(safe_transcription)
print(f"Legitimate indicators: {legitimate_indicators}")
print(f"Number of legitimate indicators: {len(legitimate_indicators)}")

# Simulate the verdict logic
if len(legitimate_indicators) >= 1:
    print("Legitimate call indicators detected - should be SAFE")
else:
    print("No legitimate indicators detected")
