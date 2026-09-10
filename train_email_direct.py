"""
Direct email model training without import conflicts.
"""

import os
import json
import numpy as np
import pandas as pd

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Embedding, Bidirectional, LSTM, Dense, Dropout
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

MAX_WORDS = 5000
MAX_LEN = 200
EMBED_DIM = 128
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
MODEL_PATH = os.path.join(MODEL_DIR, "email_bilstm.h5")
VOCAB_PATH = os.path.join(MODEL_DIR, "email_vocab.json")
DATASET_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset_email.csv")

def _build_model(vocab_size):
    model = Sequential([
        Embedding(input_dim=vocab_size, output_dim=EMBED_DIM, input_length=MAX_LEN),
        Bidirectional(LSTM(64, return_sequences=True)),
        Bidirectional(LSTM(32)),
        Dropout(0.3),
        Dense(64, activation="relu"),
        Dropout(0.3),
        Dense(1, activation="sigmoid"),
    ])
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model

def train_and_save():
    # Load dataset from CSV
    if os.path.exists(DATASET_PATH):
        df = pd.read_csv(DATASET_PATH)
        print(f"Loaded dataset: {len(df)} rows")
        
        # Use a smaller sample for faster training
        df = df.sample(n=20000, random_state=42)
        print(f"Using sample: {len(df)} rows")
        
        # Ensure we have the required columns
        if 'text_combined' not in df.columns or 'label' not in df.columns:
            raise ValueError("Dataset must contain 'text_combined' and 'label' columns")
        
        texts = df['text_combined'].fillna('').astype(str).tolist()
        labels = df['label'].astype(int).tolist()
    else:
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")

    tokenizer = Tokenizer(num_words=MAX_WORDS, oov_token="<OOV>")
    tokenizer.fit_on_texts(texts)
    sequences = tokenizer.texts_to_sequences(texts)
    padded = pad_sequences(sequences, maxlen=MAX_LEN, padding="post", truncating="post")

    vocab_size = min(MAX_WORDS, len(tokenizer.word_index) + 1)
    model = _build_model(vocab_size)

    X = np.array(padded)
    y = np.array(labels, dtype=np.float32)
    
    # Train with fewer epochs for faster completion
    print("Starting training...")
    model.fit(X, y, epochs=2, batch_size=128, verbose=1)

    os.makedirs(MODEL_DIR, exist_ok=True)
    model.save(MODEL_PATH)
    with open(VOCAB_PATH, "w") as f:
        json.dump({"word_index": tokenizer.word_index, "max_len": MAX_LEN, "max_words": MAX_WORDS}, f)
    print("Email BiLSTM model trained and saved.")
    
    return model, tokenizer

def predict_email_text(text, model, tokenizer):
    """Run BiLSTM prediction on preprocessed email text."""
    seq = tokenizer.texts_to_sequences([text])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding="post", truncating="post")
    prob = float(model.predict(padded, verbose=0)[0][0])
    return {
        "prediction": 1 if prob >= 0.5 else 0,
        "phishing_probability": round(prob, 4),
        "safe_probability": round(1 - prob, 4),
        "confidence": round(max(prob, 1 - prob) * 100, 2),
    }

def main():
    print("="*60)
    print("EMAIL PHISHING DETECTION MODEL TRAINING")
    print("="*60)
    
    # Remove existing model files to force retraining
    if os.path.exists(MODEL_PATH):
        os.remove(MODEL_PATH)
        print(f"[+] Removed existing model: {MODEL_PATH}")
    if os.path.exists(VOCAB_PATH):
        os.remove(VOCAB_PATH)
        print(f"[+] Removed existing vocab: {VOCAB_PATH}")
    
    # Train model
    model, tokenizer = train_and_save()
    
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
        result = predict_email_text(email_text, model, tokenizer)
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
