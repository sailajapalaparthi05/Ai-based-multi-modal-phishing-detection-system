"""
End-to-end vishing test with REAL audio generated via gTTS.
Tests Hindi, Telugu, and English audio files through the full pipeline.
"""
import sys, os, io, time
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gtts import gTTS
from modules.vishing_service import analyze_vishing_call

def text_to_wav(text, lang, filename):
    """Generate a WAV audio file from text using gTTS."""
    tts = gTTS(text=text, lang=lang)
    tts.save(filename)
    print(f"  Generated: {filename}")

TESTS = [
    # (name, text, lang, expected_verdict)
    ("Hindi Phishing 1",
     "नमस्ते सर, मैं आपके बैंक के सपोर्ट से बात कर रही हूँ। आपके अकाउंट में सुरक्षा समस्या है। आपको OTP मिलेगा। उसे बताइए। अपना ATM PIN और CVV बताइए। अन्यथा अकाउंट ब्लॉक कर दिया जाएगा।",
     "hi", "Vishing"),
    ("Hindi Phishing 2",
     "आपके बैंक अकाउंट को बंद होने से बचाने के लिए OTP, ATM PIN और CVV बताइए। अगर अभी नहीं बताया तो अकाउंट ब्लॉक कर देंगे।",
     "hi", "Vishing"),
    ("Telugu Phishing 1",
     "హలో సార్, నేను మీ బ్యాంక్ సపోర్ట్ నుంచి మాట్లాడుతున్నాను. మీ అకౌంట్‌లో సెక్యూరిటీ సమస్య ఉంది. మీ మొబైల్‌కు OTP వస్తుంది. ఆ OTP నాకు చెప్పండి. మీ ATM PIN మరియు CVV కూడా చెప్పండి. ఇవి ఇవ్వకపోతే మీ అకౌంట్‌ను వెంటనే బ్లాక్ చేస్తాము.",
     "te", "Vishing"),
    ("Telugu Phishing 2",
     "మీ బ్యాంక్ అకౌంట్‌ను బ్లాక్ చేయకుండా ఉండటానికి మీకు వచ్చిన OTP చెప్పండి. మీ ATM PIN మరియు CVV కూడా చెప్పండి. ఇప్పుడే చెప్పకపోతే అకౌంట్ బ్లాక్ చేస్తాము.",
     "te", "Vishing"),
    ("English Phishing",
     "Hello sir, this is your bank customer support. Your account will be blocked due to security issues. Please provide your OTP code, ATM PIN and CVV immediately or your account will be suspended.",
     "en", "Vishing"),
    ("Safe Telugu",
     "మీ హాస్పిటల్ అపాయింట్మెంట్ రేపు ఉదయం 10 గంటలకు కన్ఫర్మ్ అయింది. ఏవైనా మార్పులు ఉంటే హాస్పిటల్ రిసెప్షన్ ను సంప్రదించండి.",
     "te", "Safe"),
    ("Safe English",
     "This is an informational call about your account balance. No action is required at this time. Thank you for your time.",
     "en", "Safe"),
]

print("=" * 70)
print("END-TO-END VISHING TEST (real audio via gTTS)")
print("=" * 70)

all_pass = True

for i, (name, text, lang, expected) in enumerate(TESTS):
    print(f"\n[{i+1}/7] {name} ({lang})")

    # Generate audio
    filename = f"test_audio_{i}.wav"
    text_to_wav(text, lang, filename)

    # Run through vishing module
    t0 = time.time()
    result = analyze_vishing_call(filename)
    elapsed = time.time() - t0

    # Clean up
    try:
        os.remove(filename)
    except:
        pass

    success = result.get("success", False)
    if not success:
        verdict = "ERROR"
        risk = result.get("error", "")[:60]
        reasons = []
    else:
        verdict = result.get("prediction", "Unknown")
        risk = result.get("risk_score", "?")
        reasons = result.get("reasons", [])

    ok = "PASS" if verdict == expected else "FAIL"
    if verdict != expected:
        all_pass = False

    print(f"  {ok} Expected: {expected} | Got: {verdict} | Risk: {risk} | Time: {elapsed:.1f}s")
    if reasons:
        print(f"  Reasons: {reasons}")
    if not success and "error" in result:
        print(f"  Error: {result['error'][:80]}")

print("\n" + "=" * 70)
print("ALL TESTS PASSED" if all_pass else "SOME TESTS FAILED")
print("=" * 70)
