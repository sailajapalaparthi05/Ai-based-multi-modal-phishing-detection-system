"""
SMS Phishing Detection Service
Integrates SMS ML model with URL phishing detection for comprehensive analysis
"""

import joblib
import os
import numpy as np
import re
from typing import Dict, List, Any
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split

from modules.sms_features import SMSFeatureExtractor, create_feature_matrix
from modules.train_sms_model import SMSModelTrainer


class SMSService:
    """
    SMS phishing detection service with URL integration
    """
    
    def __init__(self, model_path: str = "model/sms_model.pkl"):
        """
        Initialize SMS service
        
        Args:
            model_path: Path to trained SMS model
        """
        self.model_path = model_path
        self.model = None
        self.feature_extractor = None
        self.model_name = None
        self.load_model()
    
    def load_model(self):
        """Load trained SMS model and feature extractor"""
        try:
            if os.path.exists(self.model_path):
                print(f"[+] Loading SMS model from {self.model_path}")
                model_data = joblib.load(self.model_path)
                self.model = model_data['model']
                self.feature_extractor = model_data['feature_extractor']
                self.model_name = model_data['model_name']
                self.results = model_data['results']
                
                # Update feature extractor with new attributes if missing
                if not hasattr(self.feature_extractor, 'legitimate_brands'):
                    self.feature_extractor.legitimate_brands = ['airtel', 'flipkart', 'amazon', 'paytm', 'googlepay', 'phonepe', 'icici', 'hdfc', 'sbi', 'axis', 'kotak', 'canara', 'perplexity', 'netflix', 'spotify', 'prime']
                
                print(f"[+] SMS model loaded: {self.model_name}")
            else:
                print(f"[!] Model file not found at {self.model_path}")
                print("[!] Training new model...")
                self._train_new_model()
        except Exception as e:
            print(f"[!] Error loading model: {e}")
            print("[!] Training new model...")
            self._train_new_model()
    
    def _train_new_model(self):
        """Train a new model if file doesn't exist"""
        trainer = SMSModelTrainer()
        df = trainer.load_dataset()
        X, y, feature_names = trainer.prepare_features(df)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        trainer.train_models(X_train, X_test, y_train, y_test)
        trainer.evaluate_models(X_test, y_test)
        trainer.select_best_model()
        trainer.save_best_model(self.model_path)
        
        self.model = trainer.best_model
        self.feature_extractor = trainer.feature_extractor
        self.model_name = trainer.best_model_name
        self.results = trainer.results
    
    def extract_features(self, text: str) -> np.ndarray:
        """
        Extract features from SMS message
        
        Args:
            text: SMS message
            
        Returns:
            Feature array
        """
        feature_data = self.feature_extractor.extract_all_features(text)
        features_dict = {**feature_data['numerical_features'], **feature_data['keyword_features']}
        
        # Add TF-IDF features
        tfidf_features = self.feature_extractor.extract_tfidf_features([feature_data['lemmatized_text']])
        
        # Combine features
        numerical_features = np.array(list(features_dict.values()))
        combined_features = np.hstack([numerical_features, tfidf_features[0]])
        
        return combined_features
    
    def predict_sms(self, text: str) -> Dict[str, Any]:
        """
        Predict if SMS is phishing using ML model
        
        Args:
            text: SMS message
            
        Returns:
            Prediction results
        """
        try:
            features = self.extract_features(text)
            features = features.reshape(1, -1)
            
            # Get prediction
            prediction = self.model.predict(features)[0]
            probability = self.model.predict_proba(features)[0]
            
            phishing_prob = probability[1]
            safe_prob = probability[0]
            
            return {
                'prediction': int(prediction),
                'phishing_probability': phishing_prob,
                'safe_probability': safe_prob,
                'confidence': max(phishing_prob, safe_prob) * 100
            }
        except Exception as e:
            print(f"[!] SMS prediction error: {e}")
            return {
                'prediction': 0,
                'phishing_probability': 0.0,
                'safe_probability': 1.0,
                'confidence': 50.0
            }
    
    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        """
        Extract entities from SMS message
        
        Args:
            text: SMS message
            
        Returns:
            Dictionary of extracted entities
        """
        return {
            'urls': self.feature_extractor.extract_urls(text),
            'phone_numbers': self.feature_extractor.extract_phone_numbers(text),
            'emails': self.feature_extractor.extract_emails(text),
            'keywords': self.feature_extractor.detect_keywords(text)
        }
    
    def analyze_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze extracted URLs using existing URL phishing detection
        
        Args:
            urls: List of URLs to analyze
            
        Returns:
            List of URL analysis results
        """
        url_results = []
        
        for url in urls:
            try:
                # Import URL service from existing module
                from modules.url_service import predict_url
                result = predict_url(url)
                
                url_results.append({
                    'url': url,
                    'verdict': result.get('verdict', 'unknown'),
                    'confidence': result.get('confidence', 0),
                    'risk_score': result.get('risk_score', 0),
                    'risks': result.get('risks', [])
                })
            except Exception as e:
                print(f"[!] URL analysis error for {url}: {e}")
                url_results.append({
                    'url': url,
                    'verdict': 'unknown',
                    'confidence': 0,
                    'risk_score': 0,
                    'risks': []
                })
        
        return url_results
    
    def detect_legitimate_otp_pattern(self, text: str) -> Dict[str, Any]:
        """
        Detect legitimate OTP/verification message patterns
        
        Args:
            text: SMS message
            
        Returns:
            Dictionary with OTP pattern detection results
        """
        text_lower = text.lower()
        
        # Legitimate OTP patterns
        otp_patterns = [
            r'use otp\s+\w+',
            r'your otp is\s+\w+',
            r'verification code\s+is\s+\w+',
            r'one time password\s+is\s+\w+',
            r'verify your mobile number',
            r'valid for\s+\d+\s+minutes?',
            r'do not share.*otp',
            r'do not share it with anyone',
            r'never share.*otp',
            r'valid for\s+\d+\s+mins',
            r'please do not share'
        ]
        
        # Strong malicious patterns (override OTP legitimacy)
        malicious_patterns = [
            r'send your otp',
            r'share your otp',
            r'provide.*otp',
            r'enter.*otp.*here',
            r'click.*to.*verify.*otp',
            r'otp.*to.*confirm.*identity',
            r'account will be blocked.*otp',
            r'account suspended.*otp',
            r'otp.*bank.*account',
            r'otp.*paypal.*account',
            r'otp.*immediately'
        ]
        
        otp_detected = False
        malicious_detected = False
        
        for pattern in otp_patterns:
            if re.search(pattern, text_lower):
                otp_detected = True
                break
        
        for pattern in malicious_patterns:
            if re.search(pattern, text_lower):
                malicious_detected = True
                break
        
        return {
            'legitimate_otp': otp_detected and not malicious_detected,
            'malicious_otp': malicious_detected,
            'otp_present': otp_detected
        }
    
    def detect_strong_phishing_indicators(self, text: str) -> Dict[str, Any]:
        """
        Detect strong phishing indicators that should override generic keyword matches
        
        Args:
            text: SMS message
            
        Returns:
            Dictionary with phishing indicator detection results
        """
        text_lower = text.lower()
        
        # Credential theft indicators
        credential_patterns = [
            r'send your password',
            r'share your otp',
            r'provide.*pin',
            r'send cvv',
            r'give card number',
            r'confirm password',
            r'enter credentials',
            r'your otp.*send',
            r'otp.*to.*this.*number'
        ]
        
        # Financial request indicators
        financial_patterns = [
            r'transfer money',
            r'send payment',
            r'pay immediately',
            r'account payment',
            r'bank details',
            r'upi payment',
            r'refund fee',
            r'prize fee',
            r'processing fee',
            r'claim.*pay'
        ]
        
        # Malicious urgency indicators
        urgency_patterns = [
            r'account will be closed',
            r'account will be suspended',
            r'account suspended',
            r'act immediately',
            r'last warning',
            r'click now',
            r'urgent payment',
            r'verify immediately',
            r'limited time.*account',
            r'expires.*account',
            r'immediately.*confirm',
            r'immediately.*send',
            r'immediately.*otp'
        ]
        
        credential_detected = any(re.search(p, text_lower) for p in credential_patterns)
        financial_detected = any(re.search(p, text_lower) for p in financial_patterns)
        urgency_detected = any(re.search(p, text_lower) for p in urgency_patterns)
        
        return {
            'credential_theft': credential_detected,
            'financial_request': financial_detected,
            'malicious_urgency': urgency_detected,
            'strong_phishing': credential_detected or financial_detected or urgency_detected
        }
    
    def calculate_risk_score(self, sms_result: Dict, url_results: List[Dict], entities: Dict, text: str) -> float:
        """
        Calculate final risk score combining SMS ML, URL analysis, and behavioral indicators
        
        Args:
            sms_result: SMS model prediction result
            url_results: URL analysis results
            entities: Extracted entities
            text: Original SMS message
            
        Returns:
            Final risk score (0-100)
        """
        risk_score = 0.0
        
        # Detect behavioral patterns
        otp_pattern = self.detect_legitimate_otp_pattern(text)
        phishing_indicators = self.detect_strong_phishing_indicators(text)
        
        # Base risk from ML model (reduced weight from 50% to 30%)
        sms_contribution = sms_result['phishing_probability'] * 30
        risk_score += sms_contribution
        
        # URL contribution (35% weight - increased importance)
        if url_results:
            phishing_urls = sum(1 for result in url_results if result['verdict'] == 'phishing')
            url_contribution = (phishing_urls / len(url_results)) * 35
            risk_score += url_contribution
        
        # Strong phishing indicators (high weight - overrides ML)
        if phishing_indicators['credential_theft']:
            risk_score += 35
        if phishing_indicators['financial_request']:
            risk_score += 30
        if phishing_indicators['malicious_urgency']:
            risk_score += 30  # Increased from 25
        
        # Legitimate OTP pattern (reduces risk significantly)
        if otp_pattern['legitimate_otp'] and not phishing_indicators['strong_phishing']:
            risk_score -= 20  # Significant reduction for legitimate OTP
        
        # Malicious OTP pattern (increases risk significantly)
        if otp_pattern['malicious_otp']:
            risk_score += 40  # Increased from 30
        
        # Combination of malicious OTP + urgency = very high risk
        if otp_pattern['malicious_otp'] and phishing_indicators['malicious_urgency']:
            risk_score += 20  # Additional penalty
        
        # Keyword contribution (reduced weight from 20% to 10%)
        keyword_score = 0
        keyword_categories = ['urgent', 'bank', 'auth', 'reward', 'crypto']
        for category in keyword_categories:
            if entities['keywords'].get(category):
                keyword_score += len(entities['keywords'][category]) * 1  # Reduced from 2
        
        keyword_contribution = min(keyword_score, 10)
        risk_score += keyword_contribution
        
        # Legitimate brand detection (reduces risk score)
        if entities['keywords'].get('legitimate_brands'):
            brand_count = len(entities['keywords']['legitimate_brands'])
            brand_reduction = min(brand_count * 5, 15)  # Up to 15% reduction
            risk_score -= brand_reduction
        
        # URL safety bonus (if URL is safe and brand detected)
        if url_results and entities['keywords'].get('legitimate_brands'):
            safe_urls = sum(1 for result in url_results if result['verdict'] == 'safe')
            if safe_urls == len(url_results):  # All URLs are safe
                risk_score -= 10  # Additional 10% reduction
        
        # No URL bonus (slight reduction for messages without URLs when OTP pattern present)
        if not url_results and otp_pattern['legitimate_otp']:
            risk_score -= 5
        
        return max(min(risk_score, 100.0), 0.0)
    
    def generate_reasons(self, sms_result: Dict, url_results: List[Dict], entities: Dict, risk_score: float, otp_pattern: Dict, phishing_indicators: Dict) -> List[str]:
        """
        Generate human-readable reasons for prediction
        
        Args:
            sms_result: SMS model prediction result
            url_results: URL analysis results
            entities: Extracted entities
            risk_score: Final risk score
            otp_pattern: OTP pattern detection results
            phishing_indicators: Strong phishing indicator results
            
        Returns:
            List of reasons
        """
        reasons = []
        
        # Legitimate OTP pattern (safety indicator)
        if otp_pattern['legitimate_otp']:
            reasons.append("Legitimate OTP verification pattern detected")
        
        # Malicious OTP pattern (risk indicator)
        if otp_pattern['malicious_otp']:
            reasons.append("Malicious OTP request detected")
        
        # Strong phishing indicators
        if phishing_indicators['credential_theft']:
            reasons.append("Credential theft attempt detected")
        if phishing_indicators['financial_request']:
            reasons.append("Financial payment request detected")
        if phishing_indicators['malicious_urgency']:
            reasons.append("Malicious urgency/threat detected")
        
        # Legitimate brand detection (safety indicator)
        if entities['keywords'].get('legitimate_brands'):
            reasons.append(f"Legitimate brand detected: {', '.join(entities['keywords']['legitimate_brands'][:3])}")
        
        # SMS model reasons
        if sms_result['phishing_probability'] > 0.7:
            reasons.append("SMS pattern indicates phishing")
        elif sms_result['phishing_probability'] > 0.5:
            reasons.append("SMS shows suspicious patterns")
        
        # URL reasons
        if url_results:
            safe_urls = [result for result in url_results if result['verdict'] == 'safe']
            phishing_urls = [result for result in url_results if result['verdict'] == 'phishing']
            
            if safe_urls:
                reasons.append(f"Safe URL detected: {safe_urls[0]['url']}")
            if phishing_urls:
                reasons.append(f"Phishing URL detected: {phishing_urls[0]['url']}")
                for risk in phishing_urls[0]['risks']:
                    reasons.append(f"URL risk: {risk}")
        
        # Keyword reasons (only if not legitimate OTP)
        if not otp_pattern['legitimate_otp']:
            keywords = entities['keywords']
            if keywords['urgent']:
                reasons.append(f"Urgent language used: {', '.join(keywords['urgent'][:3])}")
            if keywords['bank']:
                reasons.append(f"Banking keywords found: {', '.join(keywords['bank'][:3])}")
            if keywords['auth']:
                reasons.append(f"Authentication keywords: {', '.join(keywords['auth'][:3])}")
            if keywords['reward']:
                reasons.append(f"Reward keywords found: {', '.join(keywords['reward'][:3])}")
            if keywords['crypto']:
                reasons.append(f"Cryptocurrency keywords: {', '.join(keywords['crypto'][:3])}")
        
        # Entity reasons
        if entities['phone_numbers']:
            reasons.append(f"Phone numbers detected: {len(entities['phone_numbers'])}")
        if entities['emails']:
            reasons.append(f"Email addresses detected: {len(entities['emails'])}")
        
        return reasons
    
    def analyze_sms(self, message: str) -> Dict[str, Any]:
        """
        Complete SMS analysis with URL integration and behavioral pattern detection
        
        Args:
            message: SMS message to analyze
            
        Returns:
            Complete analysis results
        """
        print("=" * 60)
        print(" SMS DETECTION TRACE")
        print("=" * 60)
        print(f"SMS: {message.encode('utf-8', errors='replace').decode('utf-8')}")
        
        # Extract entities
        entities = self.extract_entities(message)
        print(f"Extracted URLs: {len(entities['urls'])}")
        print(f"Extracted Phone Numbers: {len(entities['phone_numbers'])}")
        
        # SMS model prediction
        sms_result = self.predict_sms(message)
        print(f"ML Prediction: {'Phishing' if sms_result['prediction'] == 1 else 'Safe'}")
        print(f"ML Phishing Probability: {sms_result['phishing_probability']:.2%}")
        
        # Detect behavioral patterns
        otp_pattern = self.detect_legitimate_otp_pattern(message)
        phishing_indicators = self.detect_strong_phishing_indicators(message)
        
        print(f"OTP Pattern: {'Legitimate' if otp_pattern['legitimate_otp'] else 'Malicious' if otp_pattern['malicious_otp'] else 'None'}")
        print(f"Suspicious Keywords: {entities['keywords']}")
        print(f"Suspicious URL: {'Yes' if entities['urls'] else 'No'}")
        print(f"Credential Request: {'Yes' if phishing_indicators['credential_theft'] else 'No'}")
        print(f"Financial Request: {'Yes' if phishing_indicators['financial_request'] else 'No'}")
        print(f"Urgency Score: {'High' if phishing_indicators['malicious_urgency'] else 'Low'}")
        
        # URL analysis
        url_results = []
        if entities['urls']:
            print(f"Analyzing {len(entities['urls'])} URL(s)...")
            url_results = self.analyze_urls(entities['urls'])
            for result in url_results:
                print(f"  URL Analysis: {result['url']} -> {result['verdict']} ({result['confidence']:.1f}%)")
        else:
            print("URL Analysis: No URLs found")
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(sms_result, url_results, entities, message)
        print(f"Final Risk Score: {risk_score:.1f}/100")
        
        # Generate reasons
        reasons = self.generate_reasons(sms_result, url_results, entities, risk_score, otp_pattern, phishing_indicators)
        
        # Final verdict
        if risk_score >= 50:
            verdict = "phishing"
            confidence = min(risk_score + 20, 100)
        else:
            verdict = "safe"
            confidence = 100 - risk_score
        
        print(f"Final Verdict: {verdict}")
        print(f"Final Confidence: {confidence:.1f}%")
        print("=" * 60)
        
        return {
            'message': message,
            'verdict': verdict,
            'confidence': round(confidence, 2),
            'risk_score': round(risk_score, 2),
            'sms_prediction': int(sms_result['prediction']),
            'sms_confidence': round(sms_result['confidence'], 2),
            'extracted_urls': entities['urls'],
            'url_results': url_results,
            'phone_numbers': entities['phone_numbers'],
            'emails': entities['emails'],
            'detected_keywords': entities['keywords'],
            'reasons': reasons,
            'model_used': self.model_name,
            'entities': entities,
            'otp_pattern': otp_pattern,
            'phishing_indicators': phishing_indicators
        }


# Global SMS service instance
_sms_service = None

def get_sms_service() -> SMSService:
    """
    Get or create global SMS service instance
    
    Returns:
        SMSService instance
    """
    global _sms_service
    if _sms_service is None:
        _sms_service = SMSService()
    return _sms_service

def analyze_sms(message: str) -> Dict[str, Any]:
    """
    Analyze SMS message for phishing detection
    
    Args:
        message: SMS message to analyze
        
    Returns:
        Analysis results
    """
    service = get_sms_service()
    return service.analyze_sms(message)


if __name__ == "__main__":
    # Test the SMS service
    test_messages = [
        "URGENT: Your bank account has been suspended. Click here to verify: http://fake-bank.com",
        "Hey, are we still meeting for dinner tonight?",
        "Your OTP is 123456. Never share this with anyone. Verify your account: http://phishing-site.com"
    ]
    
    service = SMSService()
    
    for message in test_messages:
        print("\n" + "="*60)
        print(f"Message: {message}")
        print("="*60)
        result = service.analyze_sms(message)
        print(f"Verdict: {result['verdict']}")
        print(f"Confidence: {result['confidence']}%")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Reasons: {', '.join(result['reasons'])}")