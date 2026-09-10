"""
Training script for Vishing Detection Model
Uses TF-IDF + Logistic Regression for text classification
"""

import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import re
import os

def clean_text(text):
    """Clean and preprocess text."""
    if not isinstance(text, str):
        return ""
    
    # Convert to lowercase
    text = text.lower()
    
    # Remove special characters but keep words
    text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def train_vishing_model():
    """Train the vishing detection model."""
    
    # Load dataset
    dataset_path = "dataset_vishing.csv"
    
    if not os.path.exists(dataset_path):
        print(f"Dataset not found: {dataset_path}")
        print("Please create the dataset file first.")
        return
    
    print("Loading dataset...")
    df = pd.read_csv(dataset_path)
    
    # Clean text
    print("Cleaning text data...")
    df['cleaned_text'] = df['text'].apply(clean_text)
    
    # Prepare features and labels
    X = df['cleaned_text']
    y = df['label']
    
    # Convert labels to binary (vishing=1, safe=0)
    y = y.map({'vishing': 1, 'safe': 0})
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Create TF-IDF vectorizer
    print("Creating TF-IDF vectorizer...")
    vectorizer = TfidfVectorizer(
        max_features=1000,
        ngram_range=(1, 2),
        stop_words='english'
    )
    
    # Fit and transform
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    # Train Logistic Regression model
    print("Training Logistic Regression model...")
    model = LogisticRegression(
        C=1.0,
        max_iter=1000,
        random_state=42,
        class_weight='balanced'
    )
    
    model.fit(X_train_tfidf, y_train)
    
    # Evaluate
    print("Evaluating model...")
    y_pred = model.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nModel Accuracy: {accuracy:.2%}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Vishing']))
    
    # Create models directory if it doesn't exist
    os.makedirs("models", exist_ok=True)
    
    # Save model and vectorizer
    print("\nSaving model and vectorizer...")
    joblib.dump(model, "models/vishing_model.pkl")
    joblib.dump(vectorizer, "models/vishing_vectorizer.pkl")
    
    print("Model training completed successfully!")
    print("Saved to: models/vishing_model.pkl")
    print("Saved to: models/vishing_vectorizer.pkl")
    
    return model, vectorizer

if __name__ == "__main__":
    train_vishing_model()