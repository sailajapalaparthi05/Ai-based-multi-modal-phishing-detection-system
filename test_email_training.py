"""
Test script to train the email model with the new dataset.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.email_model import get_email_model, predict_email_text

print("Testing email model training with new dataset...")

try:
    model, tokenizer = get_email_model()
    print("Model loaded successfully!")
    
    # Test with a phishing email
    phishing_text = "urgent action required verify your account immediately click link update payment details"
    result = predict_email_text(phishing_text)
    print(f"\nPhishing test: {result}")
    
    # Test with a safe email
    safe_text = "team meeting scheduled for tomorrow please review attached agenda"
    result = predict_email_text(safe_text)
    print(f"Safe test: {result}")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
