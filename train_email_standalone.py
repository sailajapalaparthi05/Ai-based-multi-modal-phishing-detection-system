"""
Standalone email model training script to complete the interrupted training.
"""

import sys
import os

# Add the project directory to the path
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

# Import email model module
from modules.email_model import get_email_model, predict_email_text

def main():
    """Main training function"""
    print("="*60)
    print("EMAIL PHISHING DETECTION MODEL TRAINING")
    print("="*60)
    
    # Force retraining by deleting existing model files
    import shutil
    model_dir = os.path.join(project_dir, 'model')
    email_model_path = os.path.join(model_dir, 'email_bilstm.h5')
    vocab_path = os.path.join(model_dir, 'email_vocab.json')
    
    if os.path.exists(email_model_path):
        os.remove(email_model_path)
        print(f"[+] Removed existing model: {email_model_path}")
    if os.path.exists(vocab_path):
        os.remove(vocab_path)
        print(f"[+] Removed existing vocab: {vocab_path}")
    
    # Train model with new dataset
    print("[+] Training email model with new dataset...")
    model, tokenizer = get_email_model()
    
    print("[+] Email model training completed successfully!")
    
    # Test the model
    print("\n[+] Testing email model predictions:")
    print("="*60)
    
    test_emails = [
        ("urgent action required verify your account immediately click link update payment details", 1),
        ("team meeting scheduled for tomorrow please review attached agenda", 0),
        ("congratulations you won reward claim gift card click here limited time offer", 1),
        ("thank you for your order confirmation shipping details enclosed", 0),
    ]
    
    correct = 0
    total = len(test_emails)
    
    for email_text, expected_label in test_emails:
        result = predict_email_text(email_text)
        prediction = result['prediction']
        is_correct = prediction == expected_label
        if is_correct:
            correct += 1
        
        status = "CORRECT" if is_correct else "WRONG"
        label_str = "PHISHING" if prediction == 1 else "SAFE"
        expected_str = "PHISHING" if expected_label == 1 else "SAFE"
        
        print(f"{status}: {email_text[:50]}...")
        print(f"  Expected: {expected_str}, Predicted: {label_str}")
        print(f"  Confidence: {result['confidence']:.2f}%")
        print()
    
    accuracy = (correct / total) * 100
    print("="*60)
    print(f"Test Accuracy: {accuracy:.2f}% ({correct}/{total} correct)")
    print("\n" + "="*60)
    print("EMAIL MODEL TRAINING COMPLETED SUCCESSFULLY")
    print("="*60)

if __name__ == "__main__":
    main()
