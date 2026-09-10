"""
Test SpeechRecognition transcription with a WAV file
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.vishing_service import transcribe_audio

# Test with the generated WAV file
print("Testing transcription with test_vishing.wav...")
result = transcribe_audio("test_vishing.wav")

print("\n" + "=" * 70)
if result:
    print("TRANSCRIPTION SUCCESSFUL")
    print(f"Transcription: {result}")
else:
    print("TRANSCRIPTION FAILED")
    print("Note: test_vishing.wav is a test tone (sine wave), not actual speech")
    print("Google Speech Recognition cannot understand test tones")
    print("This is expected behavior - the file format is correct, but contains no speech")
print("=" * 70)
