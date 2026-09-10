"""
Test transcription with the converted WAV file
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.vishing_service import transcribe_audio

# Test with the converted WAV file
print("Testing transcription with test_converted.wav...")
result = transcribe_audio("test_converted.wav")

print("\n" + "=" * 70)
if result:
    print("TRANSCRIPTION SUCCESSFUL")
    print(f"Transcription: {result}")
else:
    print("TRANSCRIPTION FAILED")
    print("This is the actual speech file from gTTS, so it should work")
    print("If it fails, there might be a network issue with Google Speech API")
print("=" * 70)
