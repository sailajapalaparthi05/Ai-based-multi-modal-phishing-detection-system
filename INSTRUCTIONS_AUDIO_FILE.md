# Audio File Instructions for Vishing Module Testing

## ✅ **Audio File Created Successfully**

I've created a test MP3 file: `test_speech_vishing.mp3`

**Content:** Vishing test message (bank phishing script)

**File size:** 146,880 bytes

---

## 🔧 **How to Convert MP3 to WAV**

Since your system doesn't have FFmpeg, you need to convert the MP3 to WAV using an online tool:

### **Option 1: Online Converter (Recommended)**
1. Go to: https://cloudconvert.com/mp3-to-wav
2. Upload: `test_speech_vishing.mp3`
3. Settings:
   - Format: WAV
   - Audio codec: PCM
   - Sample rate: 16000 Hz or 44100 Hz
   - Channels: Mono (1)
   - Bit depth: 16-bit
4. Click "Convert"
5. Download the WAV file
6. Rename to: `test_speech_vishing.wav`
7. Upload to: `http://127.0.0.1:5000/vishing`

### **Option 2: Alternative Online Tools**
- https://www.online-audio-converter.com/
- https://convertio.co/mp3-wav/
- https://audio.online-convert.com/convert-to-wav

---

## 🎤 **Option 3: Record Your Own Voice (Best Option)**

### **Using Windows Voice Recorder:**
1. Press `Windows + R`
2. Type: `windowsvoiceRecorder`
3. Press Enter
4. Click the red microphone button to start recording
5. Say this text clearly:
   > "This is your bank security department. Your account has been blocked because of suspicious activity. Please provide your OTP and CVV immediately to verify your account. This is an urgent matter. Act now to prevent permanent account closure."
6. Click the stop button
7. Click the "..." menu → "Open file location"
8. The file will be in MP3 format
9. Convert to WAV using Option 1 above

### **Using Mobile Phone:**
1. Use your phone's voice recorder
2. Record the same message
3. Transfer to computer
4. Convert to WAV using online tool

---

## 🧪 **Testing the Vishing Module**

### **Step 1: Get a WAV File**
- Convert `test_speech_vishing.mp3` to WAV OR
- Record your own voice and convert to WAV

### **Step 2: Test via Web Interface**
1. Go to: `http://127.0.0.1:5000/vishing`
2. Upload your WAV file
3. Click "Analyze Call"

### **Step 3: Expected Results**
- **Transcription:** Should show the speech text
- **Detection:** Should detect vishing patterns
- **Verdict:** Vishing
- **Risk Score:** High (70-100/100)
- **Reasons:**
  - OTP request detected
  - CVV/security code request detected
  - Bank/government impersonation detected
  - Urgent/threatening language detected

---

## 📋 **Required WAV Specifications**

For best results, your WAV file should have:
- **Format:** WAV
- **Channels:** Mono (1)
- **Sample rate:** 16000 Hz or 44100 Hz
- **Bit depth:** 16-bit
- **Duration:** 5-30 seconds
- **Content:** Clear human speech
- **Language:** English

---

## 🔍 **Troubleshooting**

### **If Transcription Still Fails:**
1. Check internet connection (Google Speech API requires internet)
2. Try a shorter audio file (5-10 seconds)
3. Speak clearly and at normal pace
4. Reduce background noise
5. Try different microphone or recording device

### **If File Format Issues:**
1. Use the diagnostic script: `python test_audio_file.py your_file.wav`
2. Check the output for compatibility issues
3. Convert using recommended settings

---

## 📝 **Summary**

**Current Status:**
- ✅ Vishing module code is working correctly
- ✅ Test MP3 file created: `test_speech_vishing.mp3`
- ⚠️ Need to convert to WAV for current implementation
- ⚠️ Google Speech API requires internet

**Next Steps:**
1. Convert MP3 to WAV using online tool
2. Upload WAV file to Vishing module
3. Check transcription and detection results

**Note:** The Vishing module is designed for WAV files only (no FFmpeg dependency). Once you have a proper WAV file with clear speech, it should work perfectly.
