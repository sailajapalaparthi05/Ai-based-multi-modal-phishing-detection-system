"""
Generate a test WAV file with actual speech using Google Text-to-Speech
This creates a proper audio file for testing the Vishing module
"""
import sys
import os

def generate_speech_wav():
    """Generate a WAV file with speech using Google Text-to-Speech"""
    
    print("Generating test WAV file with speech...")
    
    try:
        from gtts import gTTS
        print("gTTS library found")
    except ImportError:
        print("gTTS not installed. Installing...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "gTTS"])
        from gtts import gTTS
        print("gTTS installed successfully")
    
    # Vishing test message
    vishing_message = """
    This is your bank security department. Your account has been blocked because of suspicious activity. 
    Please provide your OTP and CVV immediately to verify your account. 
    This is an urgent matter. Act now to prevent permanent account closure.
    """
    
    print(f"Generating speech: {vishing_message[:50]}...")
    
    # Generate speech using Google Text-to-Speech
    tts = gTTS(text=vishing_message, lang='en', slow=False)
    
    # Save as MP3 first (gTTS output format)
    mp3_file = "test_speech_vishing.mp3"
    tts.save(mp3_file)
    print(f"Speech saved as MP3: {mp3_file}")
    
    # Convert MP3 to WAV using pydub (if available)
    try:
        from pydub import AudioSegment
        print("Converting MP3 to WAV...")
        
        audio = AudioSegment.from_mp3(mp3_file)
        
        # Convert to mono 16kHz for better compatibility
        audio = audio.set_channels(1)
        audio = audio.set_frame_rate(16000)
        
        wav_file = "test_speech_vishing.wav"
        audio.export(wav_file, format="wav")
        
        print(f"✅ SUCCESS: WAV file created: {wav_file}")
        print(f"File contains vishing test message for testing")
        print(f"Upload this file to: http://127.0.0.1:5000/vishing")
        
        # Clean up MP3
        os.remove(mp3_file)
        print(f"Temporary MP3 file removed")
        
        return wav_file
        
    except ImportError:
        print("pydub not available. MP3 file created instead.")
        print(f"✅ SUCCESS: MP3 file created: {mp3_file}")
        print(f"Note: MP3 may not work with current WAV-only implementation")
        print(f"Please convert to WAV using online tool: https://cloudconvert.com/mp3-to-wav")
        return mp3_file
    
    except Exception as e:
        print(f"Error converting to WAV: {e}")
        print(f"✅ SUCCESS: MP3 file created: {mp3_file}")
        print(f"Note: MP3 may not work with current WAV-only implementation")
        print(f"Please convert to WAV using online tool: https://cloudconvert.com/mp3-to-wav")
        return mp3_file

if __name__ == "__main__":
    try:
        wav_file = generate_speech_wav()
        print(f"\nYou can now test with: {wav_file}")
    except Exception as e:
        print(f"Error generating speech: {e}")
        print("\nAlternative: Record your own voice using Windows Voice Recorder:")
        print("1. Open Windows Voice Recorder")
        print("2. Record yourself saying: 'This is your bank security department. Your account has been blocked because of suspicious activity. Please provide your OTP and CVV immediately to verify your account.'")
        print("3. Save as WAV file")
        print("4. Upload to the Vishing module")
