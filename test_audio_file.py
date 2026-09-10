"""
Test script to diagnose WAV audio file compatibility with SpeechRecognition
"""
import os
import sys
import speech_recognition as sr
import wave

def test_wav_file(file_path):
    """Test if WAV file is compatible with SpeechRecognition"""
    
    print("=" * 70)
    print("WAV FILE DIAGNOSTIC TEST")
    print("=" * 70)
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"ERROR: File does not exist: {file_path}")
        return False
    
    print(f"File exists: {file_path}")
    print(f"File size: {os.path.getsize(file_path)} bytes")
    
    # Check file extension
    file_extension = os.path.splitext(file_path)[1].lower()
    print(f"File extension: {file_extension}")
    
    if file_extension != ".wav":
        print("ERROR: File is not a WAV file")
        return False
    
    # Try to read WAV file details using wave module
    try:
        with wave.open(file_path, 'rb') as wav_file:
            print("\nWAV FILE DETAILS:")
            print(f"  Channels: {wav_file.getnchannels()}")
            print(f"  Sample width: {wav_file.getsampwidth()} bytes")
            print(f"  Frame rate: {wav_file.getframerate()} Hz")
            print(f"  Number of frames: {wav_file.getnframes()}")
            print(f"  Duration: {wav_file.getnframes() / wav_file.getframerate():.2f} seconds")
            print(f"  Compression type: {wav_file.getcomptype()}")
            print(f"  Compression name: {wav_file.getcompname()}")
            
            # Check for compatibility
            channels = wav_file.getnchannels()
            sampwidth = wav_file.getsampwidth()
            framerate = wav_file.getframerate()
            print("\nCOMPATIBILITY CHECK:")
            
            if channels > 2:
                print(f"  WARNING: {channels} channels - SpeechRecognition prefers mono (1 channel)")
            else:
                print(f"  OK: {channels} channel(s)")
            
            if sampwidth != 2:
                print(f"  WARNING: Sample width {sampwidth} bytes - SpeechRecognition prefers 2 bytes (16-bit)")
            else:
                print(f"  OK: Sample width {sampwidth} bytes (16-bit)")
            
            if framerate not in [8000, 16000, 22050, 44100, 48000]:
                print(f"  WARNING: Sample rate {framerate} Hz - Non-standard sample rate")
            else:
                print(f"  OK: Sample rate {framerate} Hz")
                
    except Exception as e:
        print(f"ERROR: Could not read WAV file with wave module: {e}")
        return False
    
    # Try to open with SpeechRecognition
    print("\nSPEECH RECOGNITION TEST:")
    try:
        recognizer = sr.Recognizer()
        print("  Recognizer created successfully")
        
        with sr.AudioFile(file_path) as source:
            print("  WAV file opened successfully with SpeechRecognition")
            
            # Get duration
            try:
                duration = source.DURATION
                print(f"  Duration: {duration:.2f} seconds")
            except:
                print("  Duration: Unknown")
            
            # Read audio data
            audio_data = recognizer.record(source)
            print(f"  Audio data loaded successfully")
            print(f"  Audio data type: {type(audio_data)}")
            
        print("\nSUCCESS: WAV file is compatible with SpeechRecognition")
        return True
        
    except ValueError as e:
        print(f"ERROR: Invalid audio format for SpeechRecognition: {e}")
        return False
    except Exception as e:
        print(f"ERROR: SpeechRecognition test failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_audio_file.py <path_to_wav_file>")
        print("Example: python test_audio_file.py test.wav")
        sys.exit(1)
    
    wav_file = sys.argv[1]
    success = test_wav_file(wav_file)
    
    print("\n" + "=" * 70)
    if success:
        print("RESULT: WAV file is COMPATIBLE")
        print("The audio file should work with Vishing module.")
    else:
        print("RESULT: WAV file is NOT COMPATIBLE")
        print("Please convert your audio to a standard WAV format:")
        print("  - Mono (1 channel)")
        print("  - 16-bit (2 bytes sample width)")
        print("  - 16kHz or 44.1kHz sample rate")
    print("=" * 70)
