"""
BiLSTM Email Phishing Classifier — TensorFlow/Keras Deep Learning Model

Architecture:
  1. Embedding Layer    — Maps word indices to dense vectors (learns word semantics)
  2. Bidirectional LSTM — Reads text forward AND backward (captures context from both directions)
  3. Bidirectional LSTM — Second layer for deeper sequential pattern learning
  4. Dropout             — Prevents overfitting by randomly dropping neurons
  5. Dense (64, ReLU)   — Fully connected hidden layer for feature combination
  6. Dropout             — Additional regularization
  7. Dense (1, Sigmoid) - Binary output: 0=Safe, 1=Phishing
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
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "model")
MODEL_PATH = os.path.join(MODEL_DIR, "email_bilstm.h5")
TOKENIZER_PATH = os.path.join(MODEL_DIR, "email_tokenizer.json")
VOCAB_PATH = os.path.join(MODEL_DIR, "email_vocab.json")
DATASET_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dataset_email.csv")

_model = None
_tokenizer = None


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


def _train_and_save():
    global _model, _tokenizer
    
    # Load dataset from CSV
    if os.path.exists(DATASET_PATH):
        df = pd.read_csv(DATASET_PATH)
        print(f"Loaded dataset: {len(df)} rows")
        
        # Ensure we have the required columns
        if 'text_combined' not in df.columns or 'label' not in df.columns:
            raise ValueError("Dataset must contain 'text_combined' and 'label' columns")
        
        texts = df['text_combined'].fillna('').astype(str).tolist()
        labels = df['label'].astype(int).tolist()
    else:
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")

    _tokenizer = Tokenizer(num_words=MAX_WORDS, oov_token="<OOV>")
    _tokenizer.fit_on_texts(texts)
    sequences = _tokenizer.texts_to_sequences(texts)
    padded = pad_sequences(sequences, maxlen=MAX_LEN, padding="post", truncating="post")

    vocab_size = min(MAX_WORDS, len(_tokenizer.word_index) + 1)
    _model = _build_model(vocab_size)

    X = np.array(padded)
    y = np.array(labels, dtype=np.float32)
    
    # Train with more epochs for larger dataset
    _model.fit(X, y, epochs=10, batch_size=32, verbose=1)

    os.makedirs(MODEL_DIR, exist_ok=True)
    _model.save(MODEL_PATH)
    with open(VOCAB_PATH, "w") as f:
        json.dump({"word_index": _tokenizer.word_index, "max_len": MAX_LEN, "max_words": MAX_WORDS}, f)
    print("Email BiLSTM model trained and saved.")


def _load_tokenizer():
    with open(VOCAB_PATH, "r") as f:
        data = json.load(f)
    tok = Tokenizer(num_words=data["max_words"], oov_token="<OOV>")
    tok.word_index = data["word_index"]
    return tok


def get_email_model():
    global _model, _tokenizer
    if _model is None:
        if os.path.exists(MODEL_PATH) and os.path.exists(VOCAB_PATH):
            _model = load_model(MODEL_PATH)
            _tokenizer = _load_tokenizer()
        else:
            _train_and_save()
    return _model, _tokenizer


def predict_email_text(text):
    """Run BiLSTM prediction on preprocessed email text."""
    if not text or not text.strip():
        return {
            "prediction": 0,
            "phishing_probability": 0.0,
            "safe_probability": 1.0,
            "confidence": 100.0,
        }
    model, tokenizer = get_email_model()
    seq = tokenizer.texts_to_sequences([text])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding="post", truncating="post")
    prob = float(model.predict(padded, verbose=0)[0][0])
    return {
        "prediction": 1 if prob >= 0.5 else 0,
        "phishing_probability": round(prob, 4),
        "safe_probability": round(1 - prob, 4),
        "confidence": round(max(prob, 1 - prob) * 100, 2),
    }
