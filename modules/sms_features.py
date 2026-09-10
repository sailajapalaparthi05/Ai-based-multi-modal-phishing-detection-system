"""
SMS Feature Extraction Module
Handles text preprocessing, feature engineering, and numerical feature extraction for SMS phishing detection
"""

import re
import string
import numpy as np
from typing import List, Dict, Tuple
from collections import Counter
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

try:
    nltk.data.find('corpora/wordnet')
except LookupError:
    nltk.download('wordnet')


class SMSFeatureExtractor:
    """
    Extracts both text and numerical features from SMS messages for phishing detection
    """
    
    def __init__(self):
        """Initialize feature extractor with required resources"""
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        
        # Define keyword categories
        self.urgent_words = ['urgent', 'immediately', 'blocked', 'suspended', 'expire', 'limited time', 'hurry', 'act now', 'deadline']
        self.bank_keywords = ['bank', 'sbi', 'icici', 'hdfc', 'axis', 'kotak', 'account', 'credit', 'debit', 'transaction']
        self.auth_keywords = ['otp', 'verify', 'confirm', 'login', 'password', 'account', 'security', 'authenticate']
        self.reward_keywords = ['reward', 'prize', 'gift', 'cashback', 'lottery', 'winner', 'claim', 'free']
        self.crypto_keywords = ['bitcoin', 'crypto', 'wallet', 'investment', 'trading', 'ethereum', 'blockchain']
        
        # Legitimate brand keywords (reduce false positives)
        self.legitimate_brands = ['airtel', 'flipkart', 'amazon', 'paytm', 'googlepay', 'phonepe', 'icici', 'hdfc', 'sbi', 'axis', 'kotak', 'canara', 'perplexity', 'netflix', 'spotify', 'prime']
        
        # Initialize TF-IDF vectorizer
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.tfidf_fitted = False
        
    def preprocess_text(self, text: str) -> str:
        """
        Preprocess SMS text
        
        Args:
            text: Raw SMS message
            
        Returns:
            Preprocessed text
        """
        # Convert to lowercase
        text = text.lower()
        
        # Remove HTML tags
        text = re.sub(r'<.*?>', '', text)
        
        # Remove URLs temporarily (will be extracted separately)
        text = re.sub(r'http\S+|www\.\S+', '', text)
        
        # Remove email addresses temporarily
        text = re.sub(r'\S+@\S+', '', text)
        
        # Remove phone numbers temporarily
        text = re.sub(r'\d{10,}', '', text)
        
        # Remove punctuation
        text = text.translate(str.maketrans('', '', string.punctuation))
        
        # Remove special characters except spaces
        text = re.sub(r'[^a-zA-Z\s]', '', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text
    
    def lemmatize_text(self, text: str) -> str:
        """
        Lemmatize preprocessed text
        
        Args:
            text: Preprocessed text
            
        Returns:
            Lemmatized text
        """
        tokens = word_tokenize(text)
        lemmatized_tokens = [self.lemmatizer.lemmatize(token) for token in tokens if token not in self.stop_words]
        return ' '.join(lemmatized_tokens)
    
    def extract_numerical_features(self, text: str) -> Dict[str, float]:
        """
        Extract numerical features from SMS
        
        Args:
            text: Raw SMS message
            
        Returns:
            Dictionary of numerical features
        """
        features = {}
        
        # Basic length features
        features['sms_length'] = len(text)
        features['word_count'] = len(text.split())
        features['char_count'] = len(text.replace(' ', ''))
        
        # Character type features
        features['digit_count'] = sum(c.isdigit() for c in text)
        features['uppercase_count'] = sum(c.isupper() for c in text)
        features['uppercase_ratio'] = features['uppercase_count'] / max(features['char_count'], 1)
        
        # URL extraction
        urls = re.findall(r'http\S+|www\.\S+', text)
        features['url_count'] = len(urls)
        
        # Phone number extraction
        phone_numbers = re.findall(r'\d{10,}', text)
        features['phone_count'] = len(phone_numbers)
        
        # Email extraction
        emails = re.findall(r'\S+@\S+', text)
        features['email_count'] = len(emails)
        
        # Currency symbols
        currency_symbols = ['$', '€', '£', '₹', '¥']
        features['currency_count'] = sum(text.count(symbol) for symbol in currency_symbols)
        
        # Exclamation marks
        features['exclamation_count'] = text.count('!')
        
        # Question marks
        features['question_count'] = text.count('?')
        
        return features
    
    def extract_keyword_features(self, text: str) -> Dict[str, int]:
        """
        Extract keyword-based features
        
        Args:
            text: Preprocessed text
            
        Returns:
            Dictionary of keyword features
        """
        text_lower = text.lower()
        features = {}
        
        # Urgent words
        features['urgent_word_count'] = sum(1 for word in self.urgent_words if word in text_lower)
        
        # Bank keywords
        features['bank_keyword_count'] = sum(1 for word in self.bank_keywords if word in text_lower)
        
        # Authentication keywords
        features['auth_keyword_count'] = sum(1 for word in self.auth_keywords if word in text_lower)
        
        # Reward keywords
        features['reward_keyword_count'] = sum(1 for word in self.reward_keywords if word in text_lower)
        
        # Crypto keywords
        features['crypto_keyword_count'] = sum(1 for word in self.crypto_keywords if word in text_lower)
        
        return features
    
    def extract_urls(self, text: str) -> List[str]:
        """
        Extract URLs from SMS message
        
        Args:
            text: Raw SMS message
            
        Returns:
            List of extracted URLs
        """
        urls = re.findall(r'http\S+|www\.\S+', text)
        return [url for url in urls if url]
    
    def extract_phone_numbers(self, text: str) -> List[str]:
        """
        Extract phone numbers from SMS message
        
        Args:
            text: Raw SMS message
            
        Returns:
            List of extracted phone numbers
        """
        phone_numbers = re.findall(r'\d{10,}', text)
        return phone_numbers
    
    def extract_emails(self, text: str) -> List[str]:
        """
        Extract email addresses from SMS message
        
        Args:
            text: Raw SMS message
            
        Returns:
            List of extracted email addresses
        """
        emails = re.findall(r'\S+@\S+', text)
        return emails
    
    def detect_keywords(self, text: str) -> Dict[str, List[str]]:
        """
        Detect suspicious keywords in SMS
        
        Args:
            text: Raw SMS message
            
        Returns:
            Dictionary of detected keywords by category
        """
        text_lower = text.lower()
        detected_keywords = {}
        
        # Detect urgent words
        detected_keywords['urgent'] = [word for word in self.urgent_words if word in text_lower]
        
        # Detect bank keywords
        detected_keywords['bank'] = [word for word in self.bank_keywords if word in text_lower]
        
        # Detect authentication keywords
        detected_keywords['auth'] = [word for word in self.auth_keywords if word in text_lower]
        
        # Detect reward keywords
        detected_keywords['reward'] = [word for word in self.reward_keywords if word in text_lower]
        
        # Detect crypto keywords
        detected_keywords['crypto'] = [word for word in self.crypto_keywords if word in text_lower]
        
        # Detect legitimate brands
        detected_keywords['legitimate_brands'] = [brand for brand in self.legitimate_brands if brand in text_lower]
        
        return detected_keywords
    
    def extract_tfidf_features(self, texts: List[str]) -> np.ndarray:
        """
        Extract TF-IDF features from text
        
        Args:
            texts: List of preprocessed texts
            
        Returns:
            TF-IDF feature matrix
        """
        if not self.tfidf_fitted:
            tfidf_features = self.tfidf_vectorizer.fit_transform(texts)
            self.tfidf_fitted = True
        else:
            tfidf_features = self.tfidf_vectorizer.transform(texts)
        
        return tfidf_features.toarray()
    
    def extract_all_features(self, text: str) -> Dict[str, any]:
        """
        Extract all features from SMS message
        
        Args:
            text: Raw SMS message
            
        Returns:
            Dictionary containing all extracted features
        """
        # Preprocess text
        preprocessed_text = self.preprocess_text(text)
        lemmatized_text = self.lemmatize_text(preprocessed_text)
        
        # Extract numerical features
        numerical_features = self.extract_numerical_features(text)
        
        # Extract keyword features
        keyword_features = self.extract_keyword_features(text)
        
        # Extract entities
        urls = self.extract_urls(text)
        phone_numbers = self.extract_phone_numbers(text)
        emails = self.extract_emails(text)
        
        # Detect keywords
        detected_keywords = self.detect_keywords(text)
        
        return {
            'original_text': text,
            'preprocessed_text': preprocessed_text,
            'lemmatized_text': lemmatized_text,
            'numerical_features': numerical_features,
            'keyword_features': keyword_features,
            'urls': urls,
            'phone_numbers': phone_numbers,
            'emails': emails,
            'detected_keywords': detected_keywords
        }


def create_feature_matrix(texts: List[str], feature_extractor: SMSFeatureExtractor) -> Tuple[np.ndarray, List]:
    """
    Create feature matrix for ML training
    
    Args:
        texts: List of SMS messages
        feature_extractor: SMSFeatureExtractor instance
        
    Returns:
        Tuple of (feature matrix, feature names)
    """
    # Extract numerical features for all texts
    numerical_features_list = []
    keyword_features_list = []
    preprocessed_texts = []
    
    for text in texts:
        features = feature_extractor.extract_all_features(text)
        numerical_features_list.append(features['numerical_features'])
        keyword_features_list.append(features['keyword_features'])
        preprocessed_texts.append(features['lemmatized_text'])
    
    # Convert to numpy arrays
    numerical_array = np.array([list(f.values()) for f in numerical_features_list])
    keyword_array = np.array([list(f.values()) for f in keyword_features_list])
    
    # Get TF-IDF features
    tfidf_features = feature_extractor.extract_tfidf_features(preprocessed_texts)
    
    # Combine all features
    feature_matrix = np.hstack([numerical_array, keyword_array, tfidf_features])
    
    # Create feature names
    numerical_names = list(numerical_features_list[0].keys())
    keyword_names = list(keyword_features_list[0].keys())
    tfidf_names = [f'tfidf_{i}' for i in range(tfidf_features.shape[1])]
    feature_names = numerical_names + keyword_names + tfidf_names
    
    return feature_matrix, feature_names