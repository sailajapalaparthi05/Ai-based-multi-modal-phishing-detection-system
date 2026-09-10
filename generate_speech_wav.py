"""
Generate a test WAV file with actual speech using text-to-speech
This creates a proper audio file for testing the Vishing module
"""
import sys

def generate_speech_wav():
    """Generate a WAV file with speech using text-to-speech"""
    
    print("Generating test WAV file with speech...")
    
    try:
        import pyttsx3
        print("pyttsx3 library found")
    except ImportError:
        print("pyttsx3 not installed. Installing...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyttsx3"])
        import pyttsx3
        print("pyttsx3 installed successfully")
    
    # Initialize text-to-speech engine
    engine = pyttsx3.init()
    
    # Set properties for better quality
    engine.setProperty('rate', 150)    # Speed of speech
    engine.setProperty('volume', 1.0)  # Volume level
    
    # Save to WAV file
    output_file = "test_speech_vishing.wav"
    
    # Vishing test message
    vishing_message = """
    This is your bank security department. Your account has been blocked because of suspicious activity. 
    Please provide your OTP and CVV immediately to verify your account. 
    This is an urgent matter. Act now to prevent permanent account closure.
    """
    
    print(f"Generating speech: {vishing_message[:50]}...")
    
    # Save speech to WAV file
    engine.save_to_file(vishing_message, output_file)
    engine.runAndWait()
    
    print(f"\n✅ SUCCESS: Speech WAV file created: {output_file}")
    print(f"File contains vishing test message for testing")
    print(f"Upload this file to: http://127.0.0.1:5000/vishing")
    
    return output_file

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
