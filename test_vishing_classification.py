"""Regression tests for vishing classification decisions.

These tests bypass speech-to-text so they are fast and deterministic.  Audio
transcription itself is covered separately by the audio tests in this project.
"""

import os
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import vishing_service


SAFE_SECURITY_REMINDER = (
    "Hello, this is a customer service call. We are calling to provide "
    "information about your account. There is no urgent action required. "
    "You do not need to share your password, OTP, PIN, or banking details. "
    "If you have any questions, please contact our official customer support "
    "through the website."
)

OTP_SCAM = (
    "Hello, this is your bank customer support. Your account will be blocked "
    "due to security issues. Please provide your OTP code, ATM PIN and CVV "
    "immediately or your account will be suspended."
)

DISGUISED_OTP_SCAM = (
    "Do not share your OTP with anyone else; provide it to me immediately or "
    "your account will be blocked."
)

HINDI_VISHING = (
    "मैं बैंक से बोल रहा हूँ। आपका अकाउंट आज ब्लॉक होने वाला है। "
    "आपके मोबाइल पर OTP आएगा। वह OTP और ATM PIN तुरंत बताइए।"
)

TELUGU_VISHING = (
    "నేను మీ బ్యాంక్ నుంచి మాట్లాడుతున్నాను. మీ అకౌంట్ ఈరోజు బ్లాక్ అవుతుంది. "
    "మీ మొబైల్‌కు OTP వస్తుంది. ఆ OTP మరియు ATM PIN వెంటనే చెప్పండి."
)

HINDI_SAFE = (
    "नमस्ते, आपका अस्पताल का अपॉइंटमेंट कल सुबह 10 बजे कन्फर्म है। "
    "किसी बदलाव के लिए अस्पताल के रिसेप्शन से संपर्क करें।"
)

TELUGU_SAFE = (
    "నమస్తే, మీ హాస్పిటల్ అపాయింట్‌మెంట్ రేపు ఉదయం 10 గంటలకు కన్ఫర్మ్ అయింది. "
    "ఏమైనా మార్పులు ఉంటే హాస్పిటల్ రిసెప్షన్‌ను సంప్రదించండి."
)

LEGITIMATE_BANK_MESSAGE = (
    "Bank staff will never ask you to share your OTP, PIN or CVV. "
    "Do not share these details with anyone."
)

MIXED_TELUGU_ENGLISH_VISHING = (
    "నేను bank customer care నుంచి మాట్లాడుతున్నాను. మీ account block అవుతుంది. "
    "OTP వెంటనే చెప్పండి."
)


class VishingClassificationTests(unittest.TestCase):
    def _analyze_transcription(self, text, ml_result=(0, 95.0)):
        with patch.object(vishing_service, "transcribe_audio", return_value=text), \
             patch.object(vishing_service, "classify_vishing", return_value=ml_result):
            return vishing_service.analyze_vishing_call("unused.wav")

    def test_security_reminder_does_not_create_credential_or_urgency_alerts(self):
        patterns = vishing_service.detect_vishing_patterns(SAFE_SECURITY_REMINDER)

        self.assertEqual(patterns, [])
        self.assertEqual(vishing_service.calculate_risk_score(patterns), 5)

    def test_security_reminder_is_safe_even_when_ml_is_noisy(self):
        # The previous implementation classified this exact kind of reminder as
        # vishing because every credential word was treated as a request.
        with patch.object(vishing_service, "transcribe_audio", return_value=SAFE_SECURITY_REMINDER), \
             patch.object(vishing_service, "classify_vishing", return_value=(1, 95.0)):
            result = vishing_service.analyze_vishing_call("unused.wav")

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "safe")
        self.assertEqual(result["prediction"], "Safe")
        self.assertEqual(result["risk_score"], 5)

    def test_credential_request_with_account_threat_is_vishing(self):
        result = self._analyze_transcription(OTP_SCAM)

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "vishing")
        self.assertEqual(result["prediction"], "Vishing")
        self.assertGreaterEqual(result["risk_score"], 70)

    def test_fake_safety_phrase_does_not_hide_an_otp_request(self):
        patterns = vishing_service.detect_vishing_patterns(DISGUISED_OTP_SCAM)

        self.assertIn("OTP request detected", patterns)
        self.assertIn("Urgent/threatening language detected", patterns)

    def test_hindi_and_telugu_vishing_override_a_safe_ml_prediction(self):
        for text in (HINDI_VISHING, TELUGU_VISHING, MIXED_TELUGU_ENGLISH_VISHING):
            with self.subTest(text=text):
                result = self._analyze_transcription(text, ml_result=(0, 95.0))
                self.assertEqual(result["prediction"], "Vishing")
                self.assertGreaterEqual(result["risk_score"], 40)
                self.assertIn("OTP request detected", result["reasons"])

    def test_hindi_telugu_and_legitimate_bank_messages_are_safe(self):
        for text in (HINDI_SAFE, TELUGU_SAFE, LEGITIMATE_BANK_MESSAGE):
            with self.subTest(text=text):
                result = self._analyze_transcription(text, ml_result=(1, 95.0))
                self.assertEqual(result["prediction"], "Safe")
                self.assertLess(result["risk_score"], 40)

    def test_language_detection_handles_each_supported_script_and_mixed_text(self):
        self.assertEqual(vishing_service.detect_transcription_language("Hello from the bank"), "english")
        self.assertEqual(vishing_service.detect_transcription_language(HINDI_VISHING), "mixed")
        self.assertEqual(vishing_service.detect_transcription_language(TELUGU_SAFE), "telugu")
        self.assertEqual(
            vishing_service.detect_transcription_language(MIXED_TELUGU_ENGLISH_VISHING),
            "mixed",
        )

    def test_candidate_selection_does_not_keep_the_first_wrong_language_result(self):
        english = "this is an English recognition result"
        telugu = "ఇది తెలుగు గుర్తింపు ఫలితం"
        candidates = [
            (vishing_service._transcription_candidate_score(english, "hi-IN"), english),
            (vishing_service._transcription_candidate_score(telugu, "te-IN"), telugu),
        ]

        self.assertEqual(vishing_service._select_best_transcription(candidates), telugu)

    def test_whisper_failure_keeps_the_model_reference_as_none(self):
        original_model = vishing_service._WHISPER_MODEL
        original_attempted = vishing_service._WHISPER_LOAD_ATTEMPTED
        try:
            vishing_service._WHISPER_MODEL = None
            vishing_service._WHISPER_LOAD_ATTEMPTED = True
            self.assertIsNone(vishing_service._recognize_with_whisper("unused.wav"))
            self.assertIsNone(vishing_service._WHISPER_MODEL)
        finally:
            vishing_service._WHISPER_MODEL = original_model
            vishing_service._WHISPER_LOAD_ATTEMPTED = original_attempted


if __name__ == "__main__":
    unittest.main()
