"""
Vishing (Voice Phishing) Detection Module

Features:
1. Accepts WAV, MP3 and M4A audio files (MP3/M4A are converted to WAV via FFmpeg).
2. Converts speech to text using SpeechRecognition (Google Web Speech API),
   with local openai-whisper as a graceful offline fallback.
3. Detects phishing/vishing patterns.
4. Uses the existing TF-IDF + Logistic Regression ML model when available.
5. Calculates a risk score.
"""

import re
import joblib
import os
import tempfile
import subprocess
import unicodedata


# ============================================================
# VISHING DETECTION PATTERNS
# ============================================================

OTP_PATTERNS = [
    r'\botp\b',
    r'\bone time password\b',
    r'\bverification code\b',
    r'\bauth code\b',
    # Hindi / Telugu native-script equivalents
    r'ओटीपी', r'वन\s*टाइम\s*पासवर्ड', r'वेरिफिकेशन\s*कोड',
    r'ओटीपी\s*कोड', r'ओटीपी\s*नंबर',
    r'ఓటీపీ', r'ఓటిపి', r'వన్\s*టైమ్\s*పాస్[వ్వ]ర్డ్',
    r'వెరిఫికేషన్\s*కోడ్', r'ఆథ్\s*కోడ్',
]

PIN_PATTERNS = [
    r'\bpin\b',
    r'\bpersonal identification number\b',
    r'\batm pin\b',
    # Hindi / Telugu
    r'पिन', r'एटीएम\s*पिन',
    r'పిన్', r'ఏటీఎం\s*పిన్', r'ఎటిఎం\s*పిన్',
]

CVV_PATTERNS = [
    r'\bcvv\b',
    r'\bcvc\b',
    r'\bcard verification\b',
    r'\bsecurity code\b',
    # Hindi / Telugu
    r'सीवीवी', r'कार्ड\s*वेरिफिकेशन', r'सिक्योरिटी\s*कोड',
    r'సీవీవీ', r'సివివి', r'కార్డ్\s*వెరిఫికేషన్', r'సెక్యూరిటీ\s*కోడ్',
]

PASSWORD_PATTERNS = [
    r'\bpassword\b',
    r'\bpasscode\b',
    r'\bsecret\b',
    r'\bcredential',
    # Hindi / Telugu
    r'पासवर्ड', r'पासकोड',
    r'పాస్‌వర్డ్', r'పాస్వర్డ్', r'పాస్‌కోడ్',
]

BANK_IMPERSONATION = [
    r'\b(?:bank|banking)\s+(?:employee|officer|staff|customer\s*care|customer\s*support)\b',
    r'\b(?:bank|banking).{0,40}\b(?:security|fraud|account)\s+(?:team|department)\b',
    r'\b(?:bank|banking)\s+(?:is\s+)?(?:calling|speaking)\b',
    r'बैंक\s+(?:अधिकारी|कर्मचारी|कस्टमर\s*केयर|ग्राहक\s*सेवा|सुरक्षा\s*टीम)',
    r'बैंक\s*से\s*बोल\s*रहा\s*हूँ', r'बैंक\s*से\s*बोल\s*रही\s*हूँ',
    r'बैंक\s*अकाउंट', r'फ्रॉड\s*डिपार्टमेंट',
    r'బ్యాంక్\s*(?:ఉద్యోగి|కస్టమర్\s*కేర్|సెక్యూరిటీ\s*టీమ్|అకౌంట్)',
    r'బ్యాంక్\s*నుంచి\s*మాట్లాడుతున్నా(?:ను)?', r'ఫ్రాడ్\s*డిపార్ట్మెంట్',
]

GOVERNMENT_IMPERSONATION = [
    r'\bpolice\b',
    r'\bgovernment\b',
    r'\btax.*department\b',
    r'\birr\b',
    r'\bincome.*tax\b',
    r'\bcourt\b',
    r'\blaw.*enforcement\b',
    r'\bcyber\s*crime(?:\s*department)?\b', r'\blegal\s*department\b',
    # Hindi / Telugu
    r'पुलिस', r'साइबर\s*क्राइम(?:\s*विभाग)?', r'सरकार', r'इनकम\s*टैक्स',
    r'टैक्स\s*विभाग', r'कोर्ट', r'कानूनी\s*कार्रवाई',
    r'పోలీస్', r'సైబర్\s*క్రైమ్(?:\s*డిపార్ట్మెంట్)?', r'ప్రభుత్వ',
    r'ఇన్‌కమ్\s*ట్యాక్స్', r'ఇంకమ్\s*ట్యాక్స్', r'కోర్టు',
    r'లీగల్\s*యాక్షన్', r'చట్టపరమైన\s*చర్య',
]

URGENCY_PATTERNS = [
    r'\burgent\b',
    r'\bimmediately\b',
    r'\bright now\b',
    r'\blast chance\b',
    r'\blimited time\b',
    r'\bdeadline\b',
    r'\bexpir\b',
    r'\bact now\b',
    r'\btoday\b', r'\bwithin\s+(?:\d+|ten)\s+minutes?\b',
    # Hindi / Telugu
    r'तुरंत', r'अभी', r'अभी\s*बताइए', r'आज\s*ही', r'तुरंत\s*करें',
    r'जल्दी\s*करें', r'अभी\s*नहीं\s*तो', r'आखिरी\s*मौका',
    r'వెంటనే', r'ఇప్పుడే', r'ఈరోజే', r'త్వరగా', r'త్వరిగా',
    r'వెంటనే\s*చేయండి', r'ఇప్పుడే\s*చెప్పండి', r'ఆలస్యం\s*చేస్తే',
]

THREAT_PATTERNS = [
    r'\bblocked\b',
    r'\bsuspend\b',
    r'\bfreeze\b',
    r'\bclose\b',
    r'\bshut down\b',
    r'\bdeactivat\b',
    r'\bterminat\b',
    r'\blegal action\b',
    r'\bpolice case\b',
    r'\barrest\b',
    # Hindi / Telugu
    r'ब्लॉक', r'सस्पेंड', r'फ्रीज', r'फ्रीज़', r'बंद', r'कानूनी\s*कार्रवाई',
    r'पुलिस\s*केस', r'गिरफ्तार',
    r'బ్లాక్', r'సస్పెండ్', r'ఫ్రీజ్', r'నిలిపివేస్తాం', r'లీగల్\s*యాక్షన్',
    r'పోలీస్\s*కేసు', r'అరెస్ట్',
]

PRIZE_SCAMS = [
    r'\bprize\b',
    r'\blottery\b',
    r'\bwinner\b',
    r'\bcongratulations\b',
    r'\bgift\b',
    r'\bfree.*money\b',
    r'\bclaim.*now\b',
    r'\baward\b',
    # Hindi / Telugu
    r'पुरस्कार',
    r'लॉटरी',
    r'పురస్కార',
    r'లాటరీ',
]

KYC_SCAMS = [
    r'\bkyc\b',
    r'\bknow your customer\b',
    r'\bidentity.*verif\b',
    r'\bdocument.*upload\b',
    r'\baccount.*verif\b',
    r'\bupdate.*detail\b',
    # Hindi / Telugu
    r'केवाईसी', r'के\s*वाई\s*सी',
    r'కేవైసీ', r'కెవైసీ',
]

REFUND_SCAMS = [
    r'\brefund\b',
    r'\bmoney back\b',
    r'\bcompensation\b',
    r'\bclaim\s+(?:your\s+)?refund\b', r'\brefund\s+(?:amount|payment|processing)\b',
    # Hindi / Telugu
    r'रिफंड', r'रिफंड\s*(?:राशि|प्रोसेस)',
    r'రిఫండ్', r'రిఫండ్\s*(?:మొత్తం|ప్రాసెస్)',
]

PAYMENT_SCAMS = [
    r'\b(?:pay|payment|transfer|deposit|processing fee|verification fee)\b',
    r'भुगतान', r'पैसे\s*(?:भेजें|ट्रांसफर|जमा)',
    r'చెల్లింపు', r'డబ్బు\s*(?:పంపండి|బదిలీ|జమ)',
]

PARCEL_DELIVERY_SCAMS = [
    r'\b(?:parcel|delivery|courier|package).{0,45}\b(?:verify|verification|payment|fee|refund|held|pending|customs|release)\b',
    r'\b(?:verify|verification|payment|fee|refund).{0,45}\b(?:parcel|delivery|courier|package)\b',
    r'(?:पार्सल|डिलीवरी|कूरियर).{0,45}(?:वेरिफ|भुगतान|फीस|रिफंड|रुका|अटका)',
    r'(?:పార్సెల్|డెలివరీ|కొరియర్).{0,45}(?:వెరిఫ|చెల్లింపు|ఫీజు|రిఫండ్|ఆగి|పెండింగ్)',
]

ELECTRICITY_SCAMS = [
    r'\b(?:electricity|power)\s*(?:bill|connection|department)\b',
    r'बिजली\s*(?:बिल|कनेक्शन|विभाग)', r'కరెంట్\s*(?:బిల్లు|కనెక్షన్)',
]

LOAN_SCAMS = [
    r'\b(?:loan|credit card)\s*(?:approval|offer|department|payment)\b',
    r'लोन\s*(?:अप्रूवल|ऑफर|भुगतान)', r'లోన్\s*(?:అప్రూవల్|ఆఫర్|చెల్లింపు)',
]

INSURANCE_SCAMS = [
    r'\b(?:insurance|policy)\s*(?:claim|refund|renewal|payment)\b',
    r'बीमा\s*(?:क्लेम|रिफंड|पॉलिसी)', r'ఇన్సూరెన్స్\s*(?:క్లెయిమ్|రిఫండ్|పాలసీ)',
]

JOB_SCAMS = [
    r'\b(?:job|recruitment|hr|employment)\s*(?:offer|payment|registration|fee)\b',
    r'(?:नौकरी|जॉब)\s*(?:ऑफर|रजिस्ट्रेशन|फीस)', r'(?:ఉద్యోగం|జాబ్)\s*(?:ఆఫర్|రిజిస్ట్రేషన్|ఫీజు)',
]

REMOTE_ACCESS = [
    r'\bremote access\b',
    r'\bcontrol.*computer\b',
    r'\banydesk\b',
    r'\bteamviewer\b',
    r'\bscreen.*share\b',
    r'\bdownload.*app\b',
    r'\binstall.*software\b',
    # Hindi / Telugu
    r'रिमोट\s*एक्सेस', r'एनीडेस्क', r'टीमव्यूअर', r'स्क्रीन\s*शेयर',
    r'రిమోట్\s*యాక్సెస్', r'ఎనిడెస్క్', r'టీమ్‌వ్యూయర్', r'స్క్రీన్\s*షేర్',
]

SENSITIVE_INFO = [
    r'\baadhar\b',
    r'\baadhaar\b',
    r'\bpan\s*(?:number|card|detail)\b',
    r'\bsocial security\b',
    r'\bssn\b',
    r'\bcredit card\b',
    r'\bdebit card\b',
    r'\bbank account(?:\s*number)?\b',
    r'\brouting number\b',
    r'\bpersonal detail\b',
    # Hindi / Telugu
    r'आधार', r'पैन\s*(?:नंबर|कार्ड)', r'जन्म\s*तिथि', r'व्यक्तिगत\s*जानकारी',
    r'ఆధార్', r'పాన్\s*(?:నంబర్|కార్డ్)', r'పుట్టిన\s*తేదీ', r'వ్యక్తిగత\s*సమాచారం',
]

SUSPICIOUS_LINKS = [
    r'https?://[^\s]+',
    r'www\.[^\s]+'
]

# Legitimate call indicators (not asking for credentials)
LEGITIMATE_CALL_PATTERNS = [
    r'do not share',
    r'no need to share',
    r'not required',
    r'no action required',
    r'informational purposes',
    r'just an informational',
    r'for your information',
    r'this is not a request',
    r'no need to provide',
    r'you do not need to share',
    r'for informational purposes',
    r'just for information',
    r'customer service',
    r'customer support',
    r'information only',
    r'no credentials needed',
    r'not asking for',
    r'we are calling to inform',
    r'we are calling to provide',
    r'this is just to inform',
    r'this is to let you know',
    r'your account is safe',
    r'your account is secure',
    r'for your information only',
    r'no need to verify',
    r'no verification needed',
    r'official customer support',
    r'legitimate call',
    r'not an urgent matter',
    r'take your time',
    r'thank you for your time',
    r'bank staff will never ask',
    r'never ask you to share',
    r'no otp is required',
    r'hospital.*appointment',
    r'(?:parcel|delivery|courier).*(?:successfully\s+)?delivered',
    # Hindi / Telugu legitimate indicators
    r'साझा\s*न\s*करें', r'कोई\s*जानकारी\s*नहीं\s*चाहिए',
    r'बैंक.*कभी.*नहीं.*मांग', r'अस्पताल.*अपॉइंट',
    r'పంచుకోవద్దు', r'సమాచారం\s*లేదు', r'బ్యాంక్.*ఎప్పుడూ.*అడగ',
    r'హాస్పిటల్.*అపాయింట్',
]


# A credential word alone is not necessarily a request.  For example, a
# legitimate security reminder can say "do not share your OTP or PIN".  Keep
# these contexts close to the pattern detection rather than treating every
# occurrence of a credential word as evidence of fraud.
PROTECTIVE_CREDENTIAL_CONTEXT_PATTERNS = [
    r"\b(?:do not|don't|never|not)\s+(?:share|provide|give|reveal|disclose|tell|send|enter|confirm|read|state)\b",
    r"\b(?:no|not)\s+(?:need|required|necessary)\s+to\s+(?:share|provide|give|reveal|disclose|tell|send|enter|confirm|read|state)\b",
    r"\b(?:we|our (?:bank|team|support))\s+(?:will|would|do)\s+never\s+(?:ask|request|need|require)\b",
    r"\bbank\s+(?:staff|employee|officer)\s+(?:will\s+)?never\s+(?:ask|request)\b",
    r"\b(?:not|never)\s+asking\s+(?:for\s+)?\b",
    r"\bno\s+(?:otp|pin|cvv|cvc|password|passcode|verification code)\s+(?:is\s+)?required\b",
    # Hindi / Telugu equivalents of "do not share / do not tell".
    r"(?:साझा\s*न\s*करें|मत\s*बताइए|नहीं\s*देना|పంచుకోవద్దు|చెప్పవద్దు|ఇవ్వవద్దు)",
]

# A fraudster can also misuse a safety phrase, for example: "Do not share
# your OTP with anyone else; give it to me."  In that situation an explicit
# request always takes precedence over the apparent safety language.
SUSPICIOUS_CREDENTIAL_REQUEST_CONTEXT_PATTERNS = [
    r"\b(?:please|kindly)\s+(?:provide|give|tell|share|send|read|state|enter)\b",
    r"\b(?:provide|give|tell|share|send|read|state)\s+(?:it|them)\s+(?:to\s+)?(?:me|us)\b",
    r"\b(?:tell|give|send|read|state)\s+(?:me|us)\b",
    r"\b(?:except|only)\s+(?:to\s+)?(?:me|us|our\s+(?:agent|team|support))\b",
    r"\b(?:i|we)\s+(?:need|require|want)\s+(?:your\s+)?(?:otp|pin|cvv|cvc|password|verification code|auth code)\b",
    r"(?:बताइए|बताएं|बताना|शेयर\s*करें|भेजें|दें|दीजिए)",
    r"(?:చెప్పండి|చెప్పు|షేర్\s*చేయండి|పంపండి|ఇవ్వండి|తెలపండి)",
]

CREDENTIAL_REQUEST_CONTEXT_PATTERNS = [
    r"\b(?:tell|share|provide|give|send|read|state|enter)\b.{0,40}\b(?:otp|pin|cvv|cvc|password|passcode|verification code|auth code)\b",
    r"\b(?:otp|pin|cvv|cvc|password|passcode|verification code|auth code)\b.{0,48}\b(?:tell|share|provide|give|send|read|state|enter)\b",
    r"(?:ओटीपी|पिन|सीवीवी|पासवर्ड|पासकोड|वेरिफिकेशन\s*कोड).{0,48}(?:बताइए|बताएं|बताना|शेयर\s*करें|भेजें|दें|दीजिए)",
    r"(?:बताइए|बताएं|बताना|शेयर\s*करें|भेजें|दें|दीजिए).{0,48}(?:ओटीपी|पिन|सीवीवी|पासवर्ड|पासकोड|वेरिफिकेशन\s*कोड)",
    r"(?:ఓటీపీ|ఓటిపి|పిన్|సీవీవీ|సివివి|పాస్[‌్]?వర్డ్|పాస్[‌్]?కోడ్|వెరిఫికేషన్\s*కోడ్).{0,48}(?:చెప్పండి|చెప్పు|షేర్\s*చేయండి|పంపండి|ఇవ్వండి|తెలపండి)",
    r"(?:చెప్పండి|చెప్పు|షేర్\s*చేయండి|పంపండి|ఇవ్వండి|తెలపండి).{0,48}(?:ఓటీపీ|ఓటిపి|పిన్|సీవీవీ|సివివి|పాస్[‌్]?వర్డ్|పాస్[‌్]?కోడ్|వెరిఫికేషన్\s*కోడ్)",
]

NON_URGENT_CONTEXT_PATTERNS = [
    r"\b(?:no|not)\s+(?:urgent|urgency)\b",
    r"\bno\s+(?:immediate|urgent)\s+action\s+(?:is\s+)?required\b",
    r"\b(?:take your time|whenever convenient|not an urgent matter)\b",
]


# Account blocking / suspension / freezing threats (separate from bank impersonation
# so the caller can see the specific reason).
ACCOUNT_BLOCK_PATTERNS = [
    r'\baccount.{0,45}\b(?:block|suspend|freeze|close|shut down|deactivat)',
    r'\bcard.{0,45}\b(?:block|suspend|freeze)',
    # Hindi / Telugu
    r'अकाउंट.{0,45}(?:ब्लॉक|सस्पेंड|फ्रीज|फ्रीज़|बंद)',
    r'अकाउंट.{0,45}(?:होने\s*वाला|कर\s*दिया\s*जाएगा)',
    r'అకౌంట్.{0,45}(?:బ్లాక్|సస్పెండ్|ఫ్రీజ్|నిలిపివేస్తాం)',
    r'అకౌంత్.{0,45}(?:బ్లాక్|సస్పెండ్|ఫ్రీజ్|నిలిపివేస్తాం)',
]


# ============================================================
# AUDIO TRANSCRIPTION
# SpeechRecognition (Google Web Speech API) is preferred when
# available because it is lightweight and needs no model. MP3/M4A
# files are converted to WAV via FFmpeg (bundled by imageio-ffmpeg
# or a system ffmpeg) before transcription. Local Whisper is only
# used as a graceful offline fallback.
# ============================================================

SUPPORTED_AUDIO_EXTENSIONS = (".wav", ".mp3", ".m4a", ".mpeg", ".mp4", ".aac", ".flac", ".ogg")

_FFmpeg_PATH = None
_FFmpeg_CHECKED = False
_WHISPER_MODEL = None
_WHISPER_LOAD_ATTEMPTED = False


def normalize_vishing_text(text):
    """Normalize text for matching without altering the displayed transcript."""
    if not isinstance(text, str):
        return ""
    return unicodedata.normalize("NFKC", text).lower().strip()


def detect_transcription_language(text):
    """Identify English, Hindi, Telugu, or mixed Unicode transcription text."""
    normalized = normalize_vishing_text(text)
    if not normalized:
        return "unknown"

    counts = {
        "hindi": sum("\u0900" <= char <= "\u097f" for char in normalized),
        "telugu": sum("\u0c00" <= char <= "\u0c7f" for char in normalized),
        "english": sum(char.isascii() and char.isalpha() for char in normalized),
    }
    present = [language for language, count in counts.items() if count > 0]
    if len(present) > 1:
        return "mixed"
    return present[0] if present else "unknown"


def _transcription_candidate_score(text, language_code):
    """Prefer recognition output whose script matches the requested language."""
    language = detect_transcription_language(text)
    expected = {"hi-IN": "hindi", "te-IN": "telugu", "en-IN": "english", "en-US": "english"}[language_code]
    score = min(len(normalize_vishing_text(text)), 80)
    if language == expected:
        score += 100
    elif language == "mixed":
        score += 70
    return score


def _select_best_transcription(candidates):
    """Select the most language-consistent non-empty recognition candidate."""
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1].strip()


def _to_json_safe(value):
    """Convert numpy / non-JSON-serializable values to plain Python types."""
    try:
        import numpy as _np
        if isinstance(value, _np.generic):
            return value.item()
    except Exception:
        pass
    if isinstance(value, dict):
        return {k: _to_json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_json_safe(v) for v in value]
    return value


def _get_ffmpeg_path():
    """Locate a usable ffmpeg binary. Returns the path or None."""
    global _FFmpeg_PATH, _FFmpeg_CHECKED
    if _FFmpeg_CHECKED:
        return _FFmpeg_PATH
    _FFmpeg_CHECKED = True
    # 1) Bundled static binary provided by imageio-ffmpeg
    try:
        import imageio_ffmpeg
        candidate = imageio_ffmpeg.get_ffmpeg_exe()
        if candidate and os.path.exists(candidate):
            _FFmpeg_PATH = candidate
            return _FFmpeg_PATH
    except Exception:
        pass
    # 2) System ffmpeg on PATH
    try:
        import shutil
        candidate = shutil.which("ffmpeg")
        if candidate:
            _FFmpeg_PATH = candidate
            return _FFmpeg_PATH
    except Exception:
        pass
    return None


def _detect_audio_format(input_path):
    """Detect the actual audio format from the file header (not the extension)."""
    try:
        with open(input_path, "rb") as f:
            header = f.read(12)
        if header.startswith(b"RIFF") and b"WAVE" in header[:12]:
            return ".wav"
        if header.startswith(b"\xff\xfb") or header.startswith(b"\xff\xf3") or header.startswith(b"\xff\xf2"):
            return ".mp3"
        if header.startswith(b"ID3"):
            return ".mp3"
        if header.startswith(b"M4a") or header.startswith(b"ftyp"):
            return ".m4a"
        if header.startswith(b"OggS"):
            return ".ogg"
        if header.startswith(b"fLaC"):
            return ".flac"
        return os.path.splitext(input_path)[1].lower()
    except Exception:
        return os.path.splitext(input_path)[1].lower()


def _convert_audio_to_wav(input_path):
    """Convert an audio file to a 16kHz mono WAV temp file using ffmpeg.

    Returns the path to the temporary WAV. Raises RuntimeError on failure.
    """
    ffmpeg = _get_ffmpeg_path()
    if ffmpeg is None:
        raise RuntimeError("ffmpeg is not available; cannot convert audio file to WAV")
    fd, wav_path = tempfile.mkstemp(suffix=".wav")
    os.close(fd)
    cmd = [ffmpeg, "-y", "-i", input_path, "-ar", "16000", "-ac", "1", wav_path]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(wav_path) or os.path.getsize(wav_path) == 0:
        if os.path.exists(wav_path):
            try:
                os.remove(wav_path)
            except OSError:
                pass
        raise RuntimeError("Audio conversion failed: " + (proc.stderr or "").strip()[:200])
    return wav_path


def transcribe_audio(audio_file_path):
    """Transcribe an audio file (WAV/MP3/M4A) to text.

    Primary engine: SpeechRecognition with the Google Web Speech API.
    Fallback: local openai-whisper when Google fails or is unavailable.

    Returns the transcribed string, or None on failure (no stack trace
    is leaked to the caller).
    """
    try:
        print("[VISHING] Audio file received:", audio_file_path)

        # --- Validate presence ---
        if not audio_file_path or not os.path.exists(audio_file_path):
            print("[VISHING] ERROR: Audio file does not exist")
            return None

        # --- Validate format (detect actual format from header, not extension) ---
        file_extension = _detect_audio_format(audio_file_path)
        if file_extension not in SUPPORTED_AUDIO_EXTENSIONS:
            print(f"[VISHING] ERROR: Unsupported audio format: {file_extension}")
            return None
        print("[VISHING] Format validated:", file_extension)

        # --- Obtain a WAV suitable for SpeechRecognition ---
        # Always convert to a proper 16kHz mono WAV, regardless of extension.
        # This handles mislabeled files (e.g. MP3 content with .wav extension).
        wav_path = audio_file_path
        temp_wav = None
        try:
            temp_wav = _convert_audio_to_wav(audio_file_path)
            wav_path = temp_wav
            print(f"[VISHING] Converted to WAV: {wav_path}")
        except Exception as conv_err:
            print("[VISHING] Conversion to WAV failed:", conv_err)

        # --- Primary: SpeechRecognition (Google Web Speech API) ---
        text = None
        if wav_path and os.path.exists(wav_path):
            text = _recognize_with_speech_recognition(wav_path)

        if text:
            # Do not print the transcript: Windows consoles can reject
            # Hindi/Telugu characters, and call content should not be leaked
            # into application logs.
            print("[VISHING] Transcription successful (SpeechRecognition).")
        else:
            # --- Fallback: local Whisper (use the proper WAV if conversion succeeded) ---
            print("[VISHING] SpeechRecognition failed; trying local Whisper fallback...")
            whisper_input = temp_wav if (temp_wav and os.path.exists(temp_wav)) else audio_file_path
            text = _recognize_with_whisper(whisper_input)
            if text:
                print("[VISHING] Transcription successful (Whisper fallback).")

        # Clean up temporary WAV created for non-wav inputs
        if temp_wav and os.path.exists(temp_wav):
            try:
                os.remove(temp_wav)
            except OSError:
                pass

        if text:
            return text

        print("[VISHING] ERROR: All transcription engines failed")
        return None

    except Exception as e:
        print("[VISHING] ERROR: Audio transcription failed")
        print(f"[VISHING] Error type: {type(e).__name__}")
        print(f"[VISHING] Error message: {str(e)}")
        return None


def _recognize_with_speech_recognition(wav_path):
    """Transcribe a WAV file with SpeechRecognition, returning text or None.

    Tries Hindi, Telugu and Indian/US English for every recording.  Google can
    return non-empty text for the wrong language, so all usable candidates are
    collected and the script-consistent candidate is selected.
    """
    try:
        import speech_recognition as sr
    except ImportError:
        print("[VISHING] SpeechRecognition not available")
        return None

    # Languages to attempt, in priority order per requirements:
    #   hi-IN → te-IN → en-IN → en-US
    LANGUAGES = ["hi-IN", "te-IN", "en-IN", "en-US"]

    recognizer = sr.Recognizer()
    try:
        with sr.AudioFile(wav_path) as source:
            recognizer.adjust_for_ambient_noise(source, duration=min(0.5, getattr(source, 'DURATION', 0.5)))
            recognizer.energy_threshold = max(recognizer.energy_threshold, 100)
            recognizer.dynamic_energy_threshold = True
            recognizer.pause_threshold = 0.8
            audio_data = recognizer.record(source)

        candidates = []
        for lang in LANGUAGES:
            try:
                text = recognizer.recognize_google(audio_data, language=lang)
                if text and text.strip():
                    candidates.append((_transcription_candidate_score(text, lang), text))
                    print(f"[VISHING] SpeechRecognition produced a candidate for '{lang}'")
            except sr.UnknownValueError:
                print(f"[VISHING] SpeechRecognition: unintelligible in '{lang}'")
                continue
            except sr.RequestError as e:
                print(f"[VISHING] SpeechRecognition API request failed ({lang}): {e}")
                continue
            except Exception as e:
                print(f"[VISHING] SpeechRecognition '{lang}' error: {type(e).__name__}: {e}")
                continue

        return _select_best_transcription(candidates)
    except Exception as e:
        print(f"[VISHING] SpeechRecognition error: {type(e).__name__}: {e}")
        return None


def _load_wav_to_np(path):
    """Load a WAV file into a float32 numpy array in [-1, 1]."""
    try:
        import wave
        import numpy as np
        with wave.open(path, "rb") as w:
            frames = w.readframes(w.getnframes())
            arr = np.frombuffer(frames, dtype=np.int16).astype(np.float32) / 32768.0
            if w.getnchannels() > 1:
                arr = arr.reshape(-1, w.getnchannels()).mean(axis=1)
            return arr
    except Exception as e:
        print("[VISHING] WAV load error:", e)
        return None


def _recognize_with_whisper(audio_file_path):
    """Transcribe using local openai-whisper (lazy-loaded, cached). Returns text or None."""
    global _WHISPER_MODEL, _WHISPER_LOAD_ATTEMPTED
    if _WHISPER_MODEL is None:
        if _WHISPER_LOAD_ATTEMPTED:
            print("[VISHING] Whisper is unavailable in this process")
            return None
        _WHISPER_LOAD_ATTEMPTED = True
        try:
            import whisper

            print("[VISHING] Loading local Whisper model (base)...")
            model = whisper.load_model("base")

            # Patch Whisper's audio loader so it can find ffmpeg on Windows
            # without relying on PATH propagation to subprocesses.
            try:
                import imageio_ffmpeg
                ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()
            except Exception:
                ffmpeg_exe = None
            if ffmpeg_exe:
                try:
                    import whisper.audio as _wa
                    _orig_load_audio = _wa.load_audio

                    def _patched_load_audio(file, sr=16000):
                        import subprocess as _sp
                        cmd = [
                            ffmpeg_exe,
                            "-nostdin",
                            "-threads", "0",
                            "-i", file,
                            "-f", "s16le",
                            "-ac", "1",
                            "-acodec", "pcm_s16le",
                            "-ar", str(sr),
                            "-",
                        ]
                        out = _sp.run(cmd, capture_output=True, check=True).stdout
                        import numpy as np
                        return np.frombuffer(out, np.int16).flatten().astype(np.float32) / 32768.0

                    _wa.load_audio = _patched_load_audio
                    print(f"[VISHING] Patched Whisper audio loader with ffmpeg: {ffmpeg_exe}")
                except Exception as patch_err:
                    print(f"[VISHING] Whisper patch skipped: {patch_err}")

            print("[VISHING] Whisper model loaded successfully")
            _WHISPER_MODEL = model
        except Exception as e:
            print(f"[VISHING] Whisper unavailable: {type(e).__name__}: {e}")
            return None
    # Keep _WHISPER_MODEL as None on load failure; never use booleans as a
    # stand-in model object.
    if _WHISPER_MODEL is None or not hasattr(_WHISPER_MODEL, "transcribe"):
        print("[VISHING] Whisper model not available")
        return None
    try:
        candidates = []

        # Whisper is multilingual. Try language hints in priority order so
        # Hindi and Telugu audio is transcribed more accurately than English.
        # Auto-detect is the final fallback.
        language_hints = ["hi", "te", "en"]
        for lang in language_hints:
            try:
                result = _WHISPER_MODEL.transcribe(
                    audio_file_path,
                    language=lang,
                    task="transcribe"
                )
                candidate = result.get("text", "").strip()
                if candidate:
                    candidates.append((_transcription_candidate_score(candidate, {
                        "hi": "hi-IN", "te": "te-IN", "en": "en-IN"
                    }[lang]), candidate))
                    print(f"[VISHING] Whisper produced a candidate for '{lang}'")
            except Exception as e:
                print(f"[VISHING] Whisper language hint '{lang}' failed: {type(e).__name__}: {e}")

        # Fallback: let Whisper auto-detect the language.
        if not candidates:
            try:
                result = _WHISPER_MODEL.transcribe(
                    audio_file_path,
                    task="transcribe"
                )
                candidate = result.get("text", "").strip()
                if candidate:
                    candidates.append((min(len(normalize_vishing_text(candidate)), 80), candidate))
            except Exception as e:
                print(f"[VISHING] Whisper auto-detect failed: {type(e).__name__}: {e}")

        return _select_best_transcription(candidates)
    except Exception as e:
        print(f"[VISHING] Whisper transcription error: {type(e).__name__}: {e}")
        return None


# ============================================================
# VISHING PATTERN DETECTION
# ============================================================

_CREDENTIAL_DESCRIPTIONS = {
    "OTP request detected",
    "PIN request detected",
    "CVV/security code request detected",
    "Password request detected",
}

def _sentence_for_match(text, match):
    """Return the sentence/clause containing a regex match."""
    start_candidates = [text.rfind(separator, 0, match.start()) for separator in ".!?\n।"]
    start = max(start_candidates) + 1
    end_candidates = [
        position for position in (text.find(separator, match.end()) for separator in ".!?\n।")
        if position != -1
    ]
    end = min(end_candidates) if end_candidates else len(text)
    return text[start:end]


def _has_any_pattern(patterns, text):
    return any(re.search(pattern, text) for pattern in patterns)


def _is_protective_credential_mention(text, match):
    """True when a credential is mentioned as safety advice, not requested."""
    sentence = _sentence_for_match(text, match)
    return (
        _has_any_pattern(PROTECTIVE_CREDENTIAL_CONTEXT_PATTERNS, sentence)
        and not _has_any_pattern(SUSPICIOUS_CREDENTIAL_REQUEST_CONTEXT_PATTERNS, sentence)
    )


def _is_credential_request(text, match):
    """Require a request verb near a credential term; a bare OTP is not fraud."""
    sentence = _sentence_for_match(text, match)
    if _is_protective_credential_mention(text, match):
        return False
    return _has_any_pattern(
        CREDENTIAL_REQUEST_CONTEXT_PATTERNS + SUSPICIOUS_CREDENTIAL_REQUEST_CONTEXT_PATTERNS,
        sentence,
    )


def _is_sensitive_information_request(text, match):
    """Avoid flagging safety advice that merely mentions personal information."""
    sentence = _sentence_for_match(text, match)
    if _is_protective_credential_mention(text, match):
        return False
    return _has_any_pattern(SUSPICIOUS_CREDENTIAL_REQUEST_CONTEXT_PATTERNS, sentence)


def _is_non_urgent_mention(text, match):
    """True when urgency language is explicitly negated in the same sentence."""
    return _has_any_pattern(NON_URGENT_CONTEXT_PATTERNS, _sentence_for_match(text, match))

def detect_vishing_patterns(text):
    """
    Analyze transcribed text for vishing patterns.

    Returns:
        List of detected suspicious indicators.
    """

    if not text:
        return []

    text_lower = normalize_vishing_text(text)

    detected_patterns = []

    pattern_categories = [

        (OTP_PATTERNS,
         "OTP request detected"),

        (PIN_PATTERNS,
         "PIN request detected"),

        (CVV_PATTERNS,
         "CVV/security code request detected"),

        (PASSWORD_PATTERNS,
         "Password request detected"),

        (BANK_IMPERSONATION,
         "Bank impersonation detected"),

        (GOVERNMENT_IMPERSONATION,
         "Government/police impersonation detected"),

        (URGENCY_PATTERNS,
         "Urgent/threatening language detected"),

        (THREAT_PATTERNS,
         "Threatening language detected"),

        (ACCOUNT_BLOCK_PATTERNS,
         "Account blocking threat detected"),

        (PRIZE_SCAMS,
         "Prize/lottery scam detected"),

        (KYC_SCAMS,
         "KYC/update scam detected"),

        (REFUND_SCAMS,
         "Refund scam context detected"),

        (PAYMENT_SCAMS,
         "Payment request detected"),

        (PARCEL_DELIVERY_SCAMS,
         "Parcel/delivery scam context detected"),

        (ELECTRICITY_SCAMS,
         "Electricity bill scam context detected"),

        (LOAN_SCAMS,
         "Loan scam context detected"),

        (INSURANCE_SCAMS,
         "Insurance scam context detected"),

        (JOB_SCAMS,
         "Job scam context detected"),

        (REMOTE_ACCESS,
         "Remote access request detected"),

        (SENSITIVE_INFO,
         "Sensitive information request detected")
    ]

    for patterns, description in pattern_categories:
        for pattern in patterns:
            matches = list(re.finditer(pattern, text_lower))
            if description in _CREDENTIAL_DESCRIPTIONS:
                matches = [
                    match for match in matches
                    if _is_credential_request(text_lower, match)
                ]
            elif description == "Sensitive information request detected":
                matches = [
                    match for match in matches
                    if _is_sensitive_information_request(text_lower, match)
                ]
            elif description in {
                "Bank impersonation detected",
                "Government/police impersonation detected",
            }:
                matches = [
                    match for match in matches
                    if not _is_protective_credential_mention(text_lower, match)
                ]
            elif description == "Urgent/threatening language detected":
                matches = [
                    match for match in matches
                    if not _is_non_urgent_mention(text_lower, match)
                ]

            if matches:
                if description not in detected_patterns:
                    detected_patterns.append(description)
                break

    # Suspicious links
    for pattern in SUSPICIOUS_LINKS:

        if re.search(pattern, text_lower):

            detected_patterns.append(
                "Suspicious link mentioned in speech"
            )

            break

    return detected_patterns


def detect_legitimate_call_indicators(text):
    """
    Detect when a call explicitly says NOT to share credentials.
    This helps reduce false positives for legitimate customer service calls.
    
    Returns:
        List of detected legitimate call indicators.
    """
    
    if not text:
        return []
    
    text_lower = normalize_vishing_text(text)
    legitimate_indicators = []
    
    for pattern in LEGITIMATE_CALL_PATTERNS:
        if re.search(pattern, text_lower):
            # Extract the matched phrase for reporting
            legitimate_indicators.append(f"Legitimate call indicator: {pattern}")
    
    return legitimate_indicators


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(detected_patterns):
    """
    Calculates vishing risk score between 0 and 100.
    More conservative to avoid false positives.
    Only high-risk credential requests get high scores.
    Bank mentions alone get lower scores.
    """

    if not detected_patterns:
        return 5

    risk_score = 5  # Base risk (lower to avoid false positives)

    # High-risk indicators (credential requests)
    high_risk_categories = {
        "OTP request detected": 35,
        "PIN request detected": 35,
        "CVV/security code request detected": 35,
        "Password request detected": 30,
        "Remote access request detected": 30,
        "Sensitive information request detected": 25
    }

    # Medium-risk indicators (but not high alone)
    medium_risk_categories = {
        "Bank impersonation detected": 20,
        "Government/police impersonation detected": 20,
        "Urgent/threatening language detected": 10,
        "Threatening language detected": 15,
        "Account blocking threat detected": 20,
        "Prize/lottery scam detected": 15,
        "Refund scam context detected": 15,
        "Payment request detected": 15,
        "KYC/update scam detected": 15,
        "Parcel/delivery scam context detected": 10,
        "Electricity bill scam context detected": 10,
        "Loan scam context detected": 10,
        "Insurance scam context detected": 10,
        "Job scam context detected": 10,
        "Suspicious link mentioned in speech": 10,
    }

    # Calculate risk based on unique pattern categories
    for pattern in detected_patterns:
        if pattern in high_risk_categories:
            risk_score += high_risk_categories[pattern]
        elif pattern in medium_risk_categories:
            risk_score += medium_risk_categories[pattern]
        else:
            risk_score += 5  # Other suspicious patterns (lower weight)

    # Only add bonus if there are actual credential requests
    credential_patterns = ["OTP request detected", "PIN request detected", "CVV/security code request detected", "Password request detected"]
    has_credential_request = any(p in credential_patterns for p in detected_patterns)
    
    if has_credential_request and len(detected_patterns) >= 3:
        risk_score += 15  # Multiple indicators including credential request
    elif len(detected_patterns) >= 4:
        risk_score += 10  # Many suspicious patterns but no credential request

    return min(risk_score, 100)


# ============================================================
# ML CLASSIFICATION
# ============================================================

def classify_vishing(text):
    """
    Classifies transcribed text using the existing
    vishing ML model.

    If ML model is unavailable, uses rule-based detection.
    """

    # Resolve models relative to this module so the classifier keeps working
    # when Flask is started from a different current working directory.
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_path = os.path.join(project_dir, "models", "vishing_model.pkl")
    vectorizer_path = os.path.join(project_dir, "models", "vishing_vectorizer.pkl")

    # --------------------------------------------------------
    # Try ML model
    # --------------------------------------------------------

    if os.path.exists(model_path) and os.path.exists(vectorizer_path):

        try:

            model = joblib.load(model_path)

            vectorizer = joblib.load(
                vectorizer_path
            )

            text_features = vectorizer.transform(
                [text]
            )

            prediction = model.predict(
                text_features
            )[0]

            probability = model.predict_proba(
                text_features
            )[0]

            confidence = max(probability) * 100

            return prediction, confidence

        except Exception as e:

            print(
                f"[!] ML model error: {e}"
            )

    # --------------------------------------------------------
    # Rule-based fallback
    # --------------------------------------------------------

    patterns = detect_vishing_patterns(text)

    risk_score = calculate_risk_score(
        patterns
    )

    if risk_score >= 40:

        return "vishing", risk_score

    return "safe", 100 - risk_score



# ============================================================
# MAIN VISHING ANALYSIS
# ============================================================

def analyze_vishing_call(audio_file_path):
    """
    Main function to analyze vishing call from WAV audio file.
    WAV files only - no conversion.
    """

    try:
        print("=" * 70)
        print("[VISHING] CALL ANALYSIS STARTED")
        print("=" * 70)
        print(f"[VISHING] Audio file: {audio_file_path}")

        # Step 1: Transcribe audio (WAV only)
        transcription = transcribe_audio(audio_file_path)

        if not transcription:
            return {
                "success": False,
                "error": "Could not transcribe audio. Please upload a clear audio file with clear speech."
            }

        transcription_language = detect_transcription_language(transcription)
        print(f"[VISHING] Transcription language: {transcription_language}")

        # Step 2: Detect suspicious patterns
        print("[VISHING] Detecting vishing patterns...")
        detected_patterns = detect_vishing_patterns(transcription)
        print(f"[VISHING] Patterns detected: {len(detected_patterns)}")
        
        # Step 2.5: Detect legitimate call indicators
        print("[VISHING] Checking for legitimate call indicators...")
        legitimate_indicators = detect_legitimate_call_indicators(transcription)
        print(f"[VISHING] Legitimate indicators: {len(legitimate_indicators)}")

        # Step 3: ML classification
        print("[VISHING] Running ML classification...")
        ml_prediction, ml_confidence = classify_vishing(transcription)
        print(f"[VISHING] ML prediction: {ml_prediction}")
        print(f"[VISHING] ML confidence: {ml_confidence:.2f}%")

        # Step 4: Risk score (pattern-based)
        print("[VISHING] Calculating risk score...")
        risk_score = calculate_risk_score(detected_patterns)
        print(f"[VISHING] Risk score: {risk_score}/100")

        # Step 5: Combined final verdict and confidence
        # Confidence = how confident the system is about the final classification
        # Risk Score = how dangerous the conversation is (0-100)
        
        # Normalize ML prediction to string for consistency
        ml_prediction_str = "vishing" if ml_prediction == 1 or ml_prediction == "vishing" else "safe"
        
        # Credential theft indicators are only added by detect_vishing_patterns
        # when a sharing/request verb appears in the same sentence.
        credential_patterns = [
            "OTP request detected", "PIN request detected",
            "CVV/security code request detected", "Password request detected"
        ]
        has_credential_request = any(p in credential_patterns for p in detected_patterns)

        pattern_set = set(detected_patterns)
        has_bank_impersonation = "Bank impersonation detected" in pattern_set
        has_government_impersonation = "Government/police impersonation detected" in pattern_set
        has_urgency = "Urgent/threatening language detected" in pattern_set
        has_threat = "Threatening language detected" in pattern_set
        has_account_block = "Account blocking threat detected" in pattern_set
        has_sensitive_request = "Sensitive information request detected" in pattern_set
        has_remote_access = "Remote access request detected" in pattern_set
        has_kyc = "KYC/update scam detected" in pattern_set
        has_refund_or_payment = bool(pattern_set & {
            "Refund scam context detected", "Payment request detected"
        })
        has_parcel = "Parcel/delivery scam context detected" in pattern_set
        has_service_scam = bool(pattern_set & {
            "Electricity bill scam context detected", "Loan scam context detected",
            "Insurance scam context detected", "Job scam context detected",
            "Prize/lottery scam detected", "Suspicious link mentioned in speech",
        })

        scam_context_count = sum([
            has_bank_impersonation, has_government_impersonation, has_urgency,
            has_threat, has_account_block, has_kyc, has_refund_or_payment,
            has_parcel, has_remote_access, has_service_scam,
        ])
        has_strong_legitimate_context = (
            bool(legitimate_indicators)
            and not (has_credential_request or has_sensitive_request or has_remote_access)
            and risk_score < 40
        )

        # ---- Classification ----
        # IMPORTANT order: strong phishing evidence is checked FIRST,
        # so legitimate phrases like "customer support" can never override
        # a credential-request + threat combination.

        # Strong rule evidence always wins over an ML "Safe" prediction.
        if has_strong_legitimate_context:
            verdict = "Safe"
            status = "safe"
            print("[VISHING] Strong legitimate context - classifying as Safe")

        # Credential request plus financial, government, pressure or service
        # context is a strong vishing combination.
        elif has_credential_request and (
            has_bank_impersonation or has_government_impersonation or has_urgency
            or has_threat or has_account_block or has_kyc or has_refund_or_payment
            or has_parcel or has_remote_access
        ):
            verdict = "Vishing"
            status = "vishing"
            print("[VISHING] Strong phishing evidence (credential + context) - Vishing")

        # Police/government impersonation with a threat is dangerous even when
        # a short transcription does not preserve every credential word.
        elif has_government_impersonation and (has_threat or has_account_block):
            verdict = "Vishing"
            status = "vishing"
            print("[VISHING] Government/police impersonation with threat - Vishing")

        elif has_remote_access and (
            has_bank_impersonation or has_government_impersonation
            or has_sensitive_request or has_credential_request
        ):
            verdict = "Vishing"
            status = "vishing"
            print("[VISHING] Remote access with scam context - Vishing")

        elif has_parcel and has_urgency and (
            has_credential_request or has_sensitive_request or has_refund_or_payment or has_kyc
        ):
            verdict = "Vishing"
            status = "vishing"
            print("[VISHING] Parcel/delivery scam combination - Vishing")

        # Multiple independent indicators must not be dismissed just because
        # the existing English-trained ML model predicts Safe.
        elif risk_score >= 70 or (risk_score >= 40 and scam_context_count >= 2):
            verdict = "Vishing"
            status = "vishing"

        # ML adds support only when rule evidence is already meaningful; it is
        # never allowed to override the strong rule combinations above.
        elif ml_prediction_str == "vishing" and risk_score >= 45 and scam_context_count >= 2:
            verdict = "Vishing"
            status = "vishing"

        # Otherwise safe
        else:
            verdict = "Safe"
            status = "safe"

        # ---- Confidence ----
        if verdict == "Vishing":
            if has_credential_request and risk_score >= 70:
                final_confidence = risk_score
            elif ml_prediction_str == "vishing" and risk_score >= 45:
                final_confidence = max(float(ml_confidence), float(risk_score))
            else:
                final_confidence = max(float(risk_score), 60.0)
        else:
            if risk_score <= 30:
                final_confidence = 100 - risk_score
            elif ml_prediction_str == "safe":
                final_confidence = max(float(ml_confidence) - 10, 50)
            else:
                final_confidence = max(float(ml_confidence) - 20, 40)

        print(f"[VISHING] Final verdict: {verdict}")
        print(f"[VISHING] Final confidence: {final_confidence:.2f}%")
        print(f"[VISHING] ML confidence: {ml_confidence:.2f}%")
        print(f"[VISHING] Risk score: {risk_score}/100")
        print("=" * 70)

        return _to_json_safe({
            "success": True,
            "status": status,
            "prediction": verdict,
            "confidence": round(float(final_confidence), 2),
            "risk_score": int(risk_score),
            "ml_prediction": ml_prediction,
            "ml_confidence": round(float(ml_confidence), 2),
            "transcription": transcription,
            "reasons": detected_patterns,
            "pattern_count": len(detected_patterns)
        })

    except Exception as e:
        print("[VISHING] ERROR: Analysis failed")
        print(f"[VISHING] Error type: {type(e).__name__}")
        print(f"[VISHING] Error message: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return _to_json_safe({
            "success": False,
            "error": f"Analysis failed: {str(e)}"
        })
