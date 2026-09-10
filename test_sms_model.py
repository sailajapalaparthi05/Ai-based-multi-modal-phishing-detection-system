"""
Test the retrained SMS model with sample messages.
"""

import sys
import os
import joblib

# Add the project directory to the path
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

# Load the trained model
model_path = os.path.join(project_dir, 'model', 'sms_model.pkl')
print(f"Loading model from {model_path}")

model_data = joblib.load(model_path)
model = model_data['model']
model_name = model_data['model_name']
feature_extractor = model_data['feature_extractor']

print(f"Model loaded: {model_name}")

# Import feature matrix creation function
from modules.sms_features import create_feature_matrix

# Test messages
test_messages = [
    ("URGENT: Your bank account has been suspended. Click here to verify: http://fake-bank.com", 1),
    ("Hey, are we still meeting for dinner tonight?", 0),
    ("Free entry in 2 a wkly comp to win FA Cup final tkts 21st May 2005. Text FA to 87121", 1),
    ("Ok lar... Joking wif u oni...", 0),
    ("FreeMsg Hey there darling it's been 3 week's now and no word back! I'd like some fun you up for it still?", 1),
    ("I'm gonna be home soon and i don't want to talk about this stuff anymore tonight, k?", 0),
    ("WINNER!! As a valued network customer you have been selected to receivea £900 prize reward!", 1),
    ("I've been searching for the right words to thank you for this breather.", 0),
]

print("\nTesting SMS model predictions:")
print("="*60)

correct = 0
total = len(test_messages)

for message, expected_label in test_messages:
    # Extract features using the proper function
    feature_matrix, feature_names = create_feature_matrix([message], feature_extractor)
    
    # Predict
    prediction = model.predict(feature_matrix)[0]
    probability = model.predict_proba(feature_matrix)[0][1] if hasattr(model, 'predict_proba') else 0.0
    
    # Check if correct
    is_correct = prediction == expected_label
    if is_correct:
        correct += 1
    
    # Print result
    status = "CORRECT" if is_correct else "WRONG"
    label_str = "PHISHING" if prediction == 1 else "SAFE"
    expected_str = "PHISHING" if expected_label == 1 else "SAFE"
    
    print(f"{status}: {message[:50]}...")
    print(f"  Expected: {expected_str}, Predicted: {label_str} (prob: {probability:.4f})")
    print()

accuracy = (correct / total) * 100
print("="*60)
print(f"Test Accuracy: {accuracy:.2f}% ({correct}/{total} correct)")
