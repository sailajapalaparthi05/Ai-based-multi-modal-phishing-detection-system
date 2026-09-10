"""
Create a simple test WAV file using standard Python libraries
This creates a proper WAV file compatible with SpeechRecognition
"""
import wave
import struct
import math

def create_test_wav(output_file="test_vishing.wav", duration=5, frequency=440):
    """
    Create a simple test WAV file with sine wave
    Duration: seconds
    Frequency: Hz (440 = A4 note)
    """
    
    # WAV file parameters (compatible with SpeechRecognition)
    sample_rate = 16000  # 16kHz
    num_channels = 1     # Mono
    sampwidth = 2        # 16-bit (2 bytes)
    
    # Calculate number of samples
    num_samples = int(duration * sample_rate)
    
    # Open WAV file for writing
    with wave.open(output_file, 'wb') as wav_file:
        wav_file.setnchannels(num_channels)
        wav_file.setsampwidth(sampwidth)
        wav_file.setframerate(sample_rate)
        
        # Generate sine wave data
        for i in range(num_samples):
            t = i / sample_rate
            # Simple sine wave (this won't contain speech, but tests the format)
            value = int(32767 * 0.5 * math.sin(2 * math.pi * frequency * t))
            data = struct.pack('<h', value)  # Pack as 16-bit signed integer
            wav_file.writeframes(data)
    
    print(f"Test WAV file created: {output_file}")
    print(f"Duration: {duration} seconds")
    print(f"Sample rate: {sample_rate} Hz")
    print(f"Channels: {num_channels} (mono)")
    print(f"Sample width: {sampwidth} bytes (16-bit)")
    print(f"\nNote: This is a test tone, not actual speech.")
    print("For actual transcription, you need a real recording with speech.")

if __name__ == "__main__":
    create_test_wav()
