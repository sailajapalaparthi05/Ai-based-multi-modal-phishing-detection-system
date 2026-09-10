"""
UNIFIED MODEL TRAINING SCRIPT
Trains all phishing detection models: URL, SMS, Email, and Vishing
"""

import os
import joblib
import pandas as pd
import numpy as np
import re
import warnings
warnings.filterwarnings('ignore')

# ==========================
# URL PHISHING MODEL TRAINING
# ==========================

def train_url_model():
    """Train URL phishing detection model using ensemble learning."""
    print("\n" + "="*70)
    print(" TRAINING URL PHISHING MODEL")
    print("="*70)
    
    from sklearn.ensemble import (
        RandomForestClassifier,
        ExtraTreesClassifier,
        VotingClassifier
    )
    from xgboost import XGBClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    
    # Load combined dataset
    print("Loading combined dataset...")
    df = pd.read_csv("dataset.csv")
    print(f"Dataset loaded: {len(df)} samples")
    
    if "index" in df.columns:
        df.drop("index", axis=1, inplace=True)
    
    X = df.drop("Result", axis=1)
    y = df["Result"].replace({
        -1: 1,
         1: 0
    })
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )
    
    # Models
    rf = RandomForestClassifier(
        n_estimators=500,
        max_depth=30,
        random_state=42,
        n_jobs=-1
    )
    
    et = ExtraTreesClassifier(
        n_estimators=500,
        random_state=42,
        n_jobs=-1
    )
    
    xgb = XGBClassifier(
        n_estimators=300,
        learning_rate=0.1,
        max_depth=6,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42
    )
    
    # Ensemble
    model = VotingClassifier(
        estimators=[
            ("rf", rf),
            ("et", et),
            ("xgb", xgb)
        ],
        voting="soft"
    )
    
    print("Training Ensemble...")
    model.fit(X_train, y_train)
    
    pred = model.predict(X_test)
    acc = accuracy_score(y_test, pred)
    
    print(f"\nURL Model Accuracy: {round(acc*100,4)}%")
    print("\nClassification Report")
    print(classification_report(y_test, pred))
    print("\nConfusion Matrix")
    print(confusion_matrix(y_test, pred))
    
    os.makedirs("model", exist_ok=True)
    joblib.dump(model, "model/phishing_model.pkl")
    print("\nURL Model Saved: model/phishing_model.pkl")
    
    return acc


# ==========================
# SMS PHISHING MODEL TRAINING
# ==========================

def train_sms_model():
    """Train SMS phishing detection model using LightGBM/RF/XGBoost."""
    print("\n" + "="*70)
    print(" TRAINING SMS PHISHING MODEL")
    print("="*70)
    
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report
    import lightgbm as lgb
    from sklearn.ensemble import RandomForestClassifier
    from xgboost import XGBClassifier
    
    # Import SMS feature extractor
    from modules.sms_features import SMSFeatureExtractor, create_feature_matrix
    
    class SMSModelTrainer:
        def __init__(self):
            self.feature_extractor = SMSFeatureExtractor()
            self.models = {}
            self.results = {}
            self.best_model = None
            self.best_model_name = None
        
        def load_dataset(self, dataset_path=None):
            # Default to new dataset if no path provided
            if dataset_path is None:
                dataset_path = "dataset_sms.csv"
            
            if dataset_path and os.path.exists(dataset_path):
                print(f"Loading dataset from {dataset_path}")
                df = pd.read_csv(dataset_path)
                print(f"Dataset loaded: {len(df)} messages")
                print(f"Label distribution: {df['label'].value_counts().to_dict()}")
            elif os.path.exists('SMSSpamCollection'):
                print("Loading UCI SMS Spam Collection dataset")
                df = pd.read_csv('SMSSpamCollection', sep='\t', header=None, names=['label', 'message'])
                df['label'] = df['label'].map({'ham': 0, 'spam': 1})
                print(f"Dataset loaded: {len(df)} messages")
                print(f"Label distribution: {df['label'].value_counts().to_dict()}")
            else:
                print("Creating sample dataset for demonstration")
                df = self._create_sample_dataset()
            
            print(f"Dataset loaded: {len(df)} messages")
            return df
        
        def _create_sample_dataset(self):
            phishing_messages = [
                "URGENT: Your bank account has been suspended. Click here to verify: http://fake-bank.com",
                "Congratulations! You have won $1000000. Claim your prize now: http://lottery-scam.com",
                "Your OTP is 123456. Never share this with anyone. Verify your account: http://phishing-site.com",
                "Free iPhone! Limited time offer. Click here: http://fake-offer.com",
                "Your account will be blocked unless you act immediately. Login: http://fake-login.com",
                "Bitcoin investment opportunity! 100x returns guaranteed. Invest now: http://crypto-scam.com",
                "Dear customer, your SBI account has been compromised. Update details: http://fake-sbi.com",
                "You have been selected for a cashback of ₹50000. Claim: http://reward-scam.com",
                "Your PayPal account has been limited. Verify: http://fake-paypal.com",
                "Axis Bank: Verify your identity. OTP: 987654. Click: http://axis-phishing.com"
            ]
            
            safe_messages = [
                "Hey, are we still meeting for dinner tonight?",
                "Your order has been shipped and will arrive tomorrow",
                "The meeting is scheduled for 3 PM tomorrow",
                "Thanks for your payment! We'll process it soon",
                "Your package has been delivered to your doorstep",
                "Mom called, she wants you to call back",
                "Don't forget to bring the documents tomorrow",
                "The movie starts at 7 PM, see you there",
                "Your subscription has been renewed successfully",
                "Happy birthday! Have a great day ahead",
                # Legitimate OTP messages
                "Use OTP EFF610 to verify your mobile number. Valid for 10 mins. Please do not share it with anyone - By HirePro",
                "Your OTP is 482913. Valid for 10 minutes. Do not share it with anyone.",
                "Your verification code is 739201. Do not share this code with anyone.",
                "Use OTP 123456 to verify your mobile number. Valid for 10 mins. Please do not share it.",
                "Your OTP is 839201. Never share this with anyone.",
                "Your verification code is 456789. Valid for 5 minutes.",
                "Use OTP 987654 to verify your account. Do not share it with anyone.",
                "Your OTP is 321654. Valid for 10 minutes. Please do not share.",
                "Verification code: 789123. Do not share with anyone.",
                "Your OTP is 654321. This code expires in 10 minutes.",
                "Use OTP 258147 to verify your mobile number. Valid for 10 mins.",
                "Your verification code is 963852. Please do not share this code.",
                "OTP: 741852. Valid for 10 minutes. Do not share.",
                "Your OTP is 159357. Verify your mobile number. Do not share.",
                "Use OTP 357159 to verify your account. Valid for 10 mins.",
                "Your OTP is 951753. Never share this with anyone.",
                "Verification code: 852963. Valid for 5 minutes.",
                "Your OTP is 456123. Please do not share it with anyone.",
                "Use OTP 789456 to verify your mobile number. Valid for 10 mins. Please do not share it with anyone.",
                "Your OTP is 321987. Valid for 10 minutes. Do not share."
            ]
            
            data = {
                'message': phishing_messages + safe_messages,
                'label': [1] * len(phishing_messages) + [0] * len(safe_messages)
            }
            return pd.DataFrame(data)
        
        def prepare_features(self, df):
            print("Extracting features...")
            texts = df['message'].tolist()
            labels = df['label'].tolist()
            
            feature_matrix, feature_names = create_feature_matrix(texts, self.feature_extractor)
            
            print(f"Feature matrix shape: {feature_matrix.shape}")
            print(f"Number of features: {len(feature_names)}")
            
            return feature_matrix, np.array(labels), feature_names
        
        def train_models(self, X_train, X_test, y_train, y_test):
            print("Training models...")
            
            # LightGBM
            print("[*] Training LightGBM...")
            lgb_model = lgb.LGBMClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=42,
                verbose=-1
            )
            lgb_model.fit(X_train, y_train)
            self.models['LightGBM'] = lgb_model
            
            # Random Forest
            print("[*] Training Random Forest...")
            rf_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            rf_model.fit(X_train, y_train)
            self.models['RandomForest'] = rf_model
            
            # XGBoost
            print("[*] Training XGBoost...")
            xgb_model = XGBClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=42,
                eval_metric='logloss',
                verbosity=0
            )
            xgb_model.fit(X_train, y_train)
            self.models['XGBoost'] = xgb_model
            
            print("All models trained successfully")
        
        def evaluate_models(self, X_test, y_test):
            print("Evaluating models...")
            
            for name, model in self.models.items():
                print(f"[*] Evaluating {name}...")
                y_pred = model.predict(X_test)
                y_prob = model.predict_proba(X_test)[:, 1]
                
                accuracy = accuracy_score(y_test, y_pred)
                precision = precision_score(y_test, y_pred, zero_division=0)
                recall = recall_score(y_test, y_pred, zero_division=0)
                f1 = f1_score(y_test, y_pred, zero_division=0)
                roc_auc = roc_auc_score(y_test, y_prob)
                
                # Cross-validation
                cv_scores = cross_val_score(model, X_test, y_test, cv=5, scoring='f1')
                cv_f1 = np.mean(cv_scores)
                cv_std = np.std(cv_scores)
                
                self.results[name] = {
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'f1': f1,
                    'roc_auc': roc_auc,
                    'cv_f1': cv_f1,
                    'cv_std': cv_std
                }
                
                print(f"    Accuracy: {accuracy:.4f}")
                print(f"    Precision: {precision:.4f}")
                print(f"    Recall: {recall:.4f}")
                print(f"    F1 Score: {f1:.4f}")
                print(f"    ROC AUC: {roc_auc:.4f}")
                print(f"    CV F1: {cv_f1:.4f} (+/- {cv_std:.4f})")
        
        def select_best_model(self):
            print("Selecting best model...")
            
            best_score = 0
            best_name = None
            
            for name, metrics in self.results.items():
                # Composite score: (F1 + ROC AUC) / 2
                composite_score = (metrics['f1'] + metrics['roc_auc']) / 2
                
                if composite_score > best_score:
                    best_score = composite_score
                    best_name = name
            
            self.best_model = self.models[best_name]
            self.best_model_name = best_name
            
            print(f"Best model: {best_name}")
            print(f"    Composite Score: {best_score:.4f}")
            print(f"    F1 Score: {self.results[best_name]['f1']:.4f}")
            print(f"    ROC AUC: {self.results[best_name]['roc_auc']:.4f}")
        
        def save_best_model(self, model_path):
            print(f"Saving best model to {model_path}...")
            
            model_data = {
                'model': self.best_model,
                'feature_extractor': self.feature_extractor,
                'model_name': self.best_model_name,
                'results': self.results
            }
            
            joblib.dump(model_data, model_path)
            print("Model saved successfully")
    
    # Train SMS model
    trainer = SMSModelTrainer()
    df = trainer.load_dataset()
    X, y, feature_names = trainer.prepare_features(df)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    trainer.train_models(X_train, X_test, y_train, y_test)
    trainer.evaluate_models(X_test, y_test)
    trainer.select_best_model()
    trainer.save_best_model('model/sms_model.pkl')
    
    best_f1 = trainer.results[trainer.best_model_name]['f1']
    print(f"\nSMS Model Best F1 Score: {best_f1:.4f}")
    
    return best_f1


# ==========================
# EMAIL PHISHING MODEL TRAINING
# ==========================

def train_email_model():
    """Train Email phishing detection model using BiLSTM Deep Learning."""
    print("\n" + "="*70)
    print(" TRAINING EMAIL PHISHING MODEL")
    print("="*70)
    
    import json
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
    
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.layers import Embedding, Bidirectional, LSTM, Dense, Dropout
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    
    MAX_WORDS = 5000
    MAX_LEN = 200
    EMBED_DIM = 128
    MODEL_DIR = "model"
    MODEL_PATH = os.path.join(MODEL_DIR, "email_bilstm.h5")
    VOCAB_PATH = os.path.join(MODEL_DIR, "email_vocab.json")
    DATASET_PATH = "dataset_email.csv"
    
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
    
    # Load dataset from CSV
    if os.path.exists(DATASET_PATH):
        df = pd.read_csv(DATASET_PATH)
        print(f"Loaded dataset: {len(df)} rows")
        
        # Use a smaller sample for faster training
        df = df.sample(n=min(20000, len(df)), random_state=42)
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
    
    # Train with limited epochs for faster completion
    print("Starting training...")
    model.fit(X, y, epochs=2, batch_size=128, verbose=1)

    os.makedirs(MODEL_DIR, exist_ok=True)
    model.save(MODEL_PATH)
    with open(VOCAB_PATH, "w") as f:
        json.dump({"word_index": tokenizer.word_index, "max_len": MAX_LEN, "max_words": MAX_WORDS}, f)
    print("Email BiLSTM model trained and saved.")
    
    # Test the model
    print("\nTesting email model predictions:")
    test_emails = [
        ("urgent action required verify your account immediately click link update payment details", 1),
        ("team meeting scheduled for tomorrow please review attached agenda", 0),
    ]
    
    correct = 0
    total = len(test_emails)
    
    for email_text, expected_label in test_emails:
        seq = tokenizer.texts_to_sequences([email_text])
        padded_test = pad_sequences(seq, maxlen=MAX_LEN, padding="post", truncating="post")
        prob = float(model.predict(padded_test, verbose=0)[0][0])
        prediction = 1 if prob >= 0.5 else 0
        confidence = round(max(prob, 1 - prob) * 100, 2)
        
        is_correct = prediction == expected_label
        if is_correct:
            correct += 1
        
        status = "CORRECT" if is_correct else "WRONG"
        label_str = "PHISHING" if prediction == 1 else "SAFE"
        expected_str = "PHISHING" if expected_label == 1 else "SAFE"
        
        print(f"{status}: {email_text[:50]}...")
        print(f"  Expected: {expected_str}, Predicted: {label_str} (confidence: {confidence}%)")
    
    accuracy = (correct / total) * 100
    print(f"\nEmail Model Test Accuracy: {accuracy:.2f}%")
    
    return accuracy / 100  # Return as decimal for consistency


# ==========================
# VISHING MODEL TRAINING
# ==========================

def train_vishing_model():
    """Train Vishing detection model using TF-IDF + Logistic Regression."""
    print("\n" + "="*70)
    print(" TRAINING VISHING DETECTION MODEL")
    print("="*70)
    
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    
    def clean_text(text):
        """Clean and preprocess text."""
        if not isinstance(text, str):
            return ""
        
        text = text.lower()
        text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    # Load dataset
    dataset_path = "dataset_vishing.csv"
    
    if not os.path.exists(dataset_path):
        print(f"Dataset not found: {dataset_path}")
        print("Please create the dataset file first.")
        return 0
    
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
    
    print(f"\nVishing Model Accuracy: {accuracy:.2%}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Vishing']))
    
    # Create models directory if it doesn't exist
    os.makedirs("models", exist_ok=True)
    
    # Save model and vectorizer
    print("\nSaving model and vectorizer...")
    joblib.dump(model, "models/vishing_model.pkl")
    joblib.dump(vectorizer, "models/vishing_vectorizer.pkl")
    
    print("Vishing Model training completed successfully!")
    print("Saved to: models/vishing_model.pkl")
    print("Saved to: models/vishing_vectorizer.pkl")
    
    return accuracy


# ==========================
# MAIN TRAINING FUNCTION
# ==========================

def train_all_models():
    """Train all phishing detection models."""
    print("\n" + "="*70)
    print(" UNIFIED MODEL TRAINING")
    print("="*70)
    print("This will train all models: URL, SMS, Email, and Vishing")
    print("="*70)
    
    results = {}
    
    # Train URL model
    try:
        results['URL'] = train_url_model()
    except Exception as e:
        print(f"\n[ERROR] URL model training failed: {e}")
        results['URL'] = None
    
    # Train SMS model
    try:
        results['SMS'] = train_sms_model()
    except Exception as e:
        print(f"\n[ERROR] SMS model training failed: {e}")
        results['SMS'] = None
    
    # Train Email model
    try:
        results['Email'] = train_email_model()
    except Exception as e:
        print(f"\n[ERROR] Email model training failed: {e}")
        results['Email'] = None
    
    # Train Vishing model
    try:
        results['Vishing'] = train_vishing_model()
    except Exception as e:
        print(f"\n[ERROR] Vishing model training failed: {e}")
        results['Vishing'] = None
    
    # Summary
    print("\n" + "="*70)
    print(" TRAINING SUMMARY")
    print("="*70)
    for model_name, accuracy in results.items():
        if accuracy is not None:
            print(f"{model_name} Model: {accuracy:.4f}")
        else:
            print(f"{model_name} Model: FAILED")
    print("="*70)
    
    return results


# ==========================
# MAIN EXECUTION
# ==========================

if __name__ == "__main__":
    import sys
    
    # Check command line arguments
    if len(sys.argv) > 1:
        model_type = sys.argv[1].lower()
        
        if model_type == 'url':
            train_url_model()
        elif model_type == 'sms':
            train_sms_model()
        elif model_type == 'email':
            train_email_model()
        elif model_type == 'vishing':
            train_vishing_model()
        elif model_type == 'all':
            train_all_models()
        else:
            print("Usage: python train_model.py [url|sms|email|vishing|all]")
            print("  url      - Train URL phishing model only")
            print("  sms      - Train SMS phishing model only")
            print("  email    - Train Email phishing model only")
            print("  vishing  - Train Vishing detection model only")
            print("  all      - Train all models (default)")
    else:
        # Default: train all models
        train_all_models()