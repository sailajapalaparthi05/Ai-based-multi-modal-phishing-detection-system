"""
SMS Phishing Detection Model Training
Compares LightGBM, Random Forest, and XGBoost models and selects the best performer
"""

import pandas as pd
import numpy as np
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns

# ML Models
import lightgbm as lgb
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

# Import feature extractor
from modules.sms_features import SMSFeatureExtractor, create_feature_matrix


class SMSModelTrainer:
    """
    Train and compare multiple ML models for SMS phishing detection
    """
    
    def __init__(self):
        """Initialize model trainer"""
        self.feature_extractor = SMSFeatureExtractor()
        self.models = {}
        self.results = {}
        self.best_model = None
        self.best_model_name = None
        
    def load_dataset(self, dataset_path: str = None) -> pd.DataFrame:
        """
        Load SMS dataset
        
        Args:
            dataset_path: Path to dataset CSV file
            
        Returns:
            DataFrame with SMS messages and labels
        """
        # Default to new dataset if no path provided
        if dataset_path is None:
            dataset_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dataset_sms.csv')
        
        if os.path.exists(dataset_path):
            print(f"[+] Loading dataset from {dataset_path}")
            df = pd.read_csv(dataset_path)
            print(f"[+] Dataset loaded: {len(df)} messages")
            print(f"[+] Label distribution: {df['label'].value_counts().to_dict()}")
        elif os.path.exists('SMSSpamCollection'):
            print("[+] Loading UCI SMS Spam Collection dataset")
            # Load the UCI dataset (tab-separated format)
            df = pd.read_csv('SMSSpamCollection', sep='\t', header=None, names=['label', 'message'])
            # Convert labels: ham -> 0 (safe), spam -> 1 (phishing)
            df['label'] = df['label'].map({'ham': 0, 'spam': 1})
            print(f"[+] Dataset loaded: {len(df)} messages")
            print(f"[+] Label distribution: {df['label'].value_counts().to_dict()}")
        else:
            print("[+] Creating sample dataset for demonstration")
            df = self._create_sample_dataset()
        
        print(f"[+] Dataset loaded: {len(df)} messages")
        return df
    
    def _create_sample_dataset(self) -> pd.DataFrame:
        """
        Create sample dataset for demonstration purposes
        
        Returns:
            Sample DataFrame with SMS messages
        """
        # Phishing SMS examples
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
        
        # Safe SMS examples (including legitimate OTP messages)
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
            # Legitimate OTP messages (to reduce false positives)
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
        
        # Create DataFrame
        data = {
            'message': phishing_messages + safe_messages,
            'label': [1] * len(phishing_messages) + [0] * len(safe_messages)  # 1 = phishing, 0 = safe
        }
        
        return pd.DataFrame(data)
    
    def prepare_features(self, df: pd.DataFrame) -> tuple:
        """
        Prepare features for training
        
        Args:
            df: DataFrame with messages and labels
            
        Returns:
            Tuple of (feature matrix, labels, feature names)
        """
        print("[+] Extracting features...")
        texts = df['message'].tolist()
        labels = df['label'].tolist()
        
        feature_matrix, feature_names = create_feature_matrix(texts, self.feature_extractor)
        
        print(f"[+] Feature matrix shape: {feature_matrix.shape}")
        print(f"[+] Number of features: {len(feature_names)}")
        
        return feature_matrix, np.array(labels), feature_names
    
    def train_models(self, X_train, X_test, y_train, y_test):
        """
        Train and compare multiple models
        
        Args:
            X_train: Training features
            X_test: Testing features
            y_train: Training labels
            y_test: Testing labels
        """
        print("[+] Training models...")
        
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
            max_depth=6,
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
            n_jobs=-1,
            use_label_encoder=False,
            eval_metric='logloss'
        )
        xgb_model.fit(X_train, y_train)
        self.models['XGBoost'] = xgb_model
        
        print("[+] All models trained successfully")
    
    def evaluate_models(self, X_test, y_test):
        """
        Evaluate all trained models
        
        Args:
            X_test: Testing features
            y_test: Testing labels
        """
        print("[+] Evaluating models...")
        
        for name, model in self.models.items():
            print(f"[*] Evaluating {name}...")
            
            # Predictions
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
            
            # Metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='binary')
            recall = recall_score(y_test, y_pred, average='binary')
            f1 = f1_score(y_test, y_pred, average='binary')
            
            # ROC AUC
            if y_pred_proba is not None:
                roc_auc = roc_auc_score(y_test, y_pred_proba)
            else:
                roc_auc = 0.0
            
            # Cross-validation (skip for small datasets)
            if len(y_test) >= 10:
                cv_scores = cross_val_score(model, X_test, y_test, cv=5, scoring='f1')
            else:
                cv_scores = np.array([f1])  # Use single f1 score if too few samples
            
            self.results[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'roc_auc': roc_auc,
                'cv_f1_mean': cv_scores.mean(),
                'cv_f1_std': cv_scores.std() if len(cv_scores) > 1 else 0.0,
                'confusion_matrix': confusion_matrix(y_test, y_pred),
                'classification_report': classification_report(y_test, y_pred)
            }
            
            print(f"    Accuracy: {accuracy:.4f}")
            print(f"    Precision: {precision:.4f}")
            print(f"    Recall: {recall:.4f}")
            print(f"    F1 Score: {f1:.4f}")
            print(f"    ROC AUC: {roc_auc:.4f}")
            print(f"    CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    
    def select_best_model(self):
        """
        Select the best model based on F1 score and ROC AUC
        
        Returns:
            Best model name and model object
        """
        print("[+] Selecting best model...")
        
        # Calculate composite score (F1 + ROC AUC) / 2
        for name, metrics in self.results.items():
            composite_score = (metrics['f1_score'] + metrics['roc_auc']) / 2
            metrics['composite_score'] = composite_score
        
        # Select model with highest composite score
        best_name = max(self.results.keys(), key=lambda x: self.results[x]['composite_score'])
        self.best_model_name = best_name
        self.best_model = self.models[best_name]
        
        print(f"[+] Best model: {best_name}")
        print(f"    Composite Score: {self.results[best_name]['composite_score']:.4f}")
        print(f"    F1 Score: {self.results[best_name]['f1_score']:.4f}")
        print(f"    ROC AUC: {self.results[best_name]['roc_auc']:.4f}")
        
        return best_name, self.best_model
    
    def print_evaluation_results(self):
        """Print detailed evaluation results for all models"""
        print("\n" + "="*60)
        print("MODEL EVALUATION RESULTS")
        print("="*60)
        
        for name, metrics in self.results.items():
            print(f"\n{name}:")
            print("-" * 40)
            print(f"Accuracy:  {metrics['accuracy']:.4f}")
            print(f"Precision: {metrics['precision']:.4f}")
            print(f"Recall:    {metrics['recall']:.4f}")
            print(f"F1 Score:  {metrics['f1_score']:.4f}")
            print(f"ROC AUC:   {metrics['roc_auc']:.4f}")
            print(f"CV F1:     {metrics['cv_f1_mean']:.4f} (+/- {metrics['cv_f1_std']:.4f})")
            print(f"\nConfusion Matrix:")
            print(metrics['confusion_matrix'])
            print(f"\nClassification Report:")
            print(metrics['classification_report'])
    
    def save_best_model(self, model_path: str = "model/sms_model.pkl"):
        """
        Save the best model
        
        Args:
            model_path: Path to save the model
        """
        print(f"[+] Saving best model to {model_path}")
        
        # Create model directory if it doesn't exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # Save model and feature extractor
        model_data = {
            'model': self.best_model,
            'model_name': self.best_model_name,
            'feature_extractor': self.feature_extractor,
            'results': self.results
        }
        
        joblib.dump(model_data, model_path)
        print(f"[+] Model saved successfully")
    
    def plot_comparison(self):
        """Plot model comparison results"""
        models = list(self.results.keys())
        metrics = ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc']
        
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        axes = axes.flatten()
        
        for i, metric in enumerate(metrics):
            values = [self.results[model][metric] for model in models]
            axes[i].bar(models, values)
            axes[i].set_title(metric.upper())
            axes[i].set_ylabel('Score')
            axes[i].set_ylim(0, 1)
        
        # Remove empty subplot
        axes[-1].axis('off')
        
        plt.tight_layout()
        plt.savefig('model_comparison.png')
        print("[+] Model comparison plot saved as model_comparison.png")
        plt.close()


def main():
    """Main training function"""
    print("="*60)
    print("SMS PHISHING DETECTION MODEL TRAINING")
    print("="*60)
    
    # Initialize trainer
    trainer = SMSModelTrainer()
    
    # Load dataset
    df = trainer.load_dataset()
    
    # Prepare features
    X, y, feature_names = trainer.prepare_features(df)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"[+] Training set size: {X_train.shape[0]}")
    print(f"[+] Testing set size: {X_test.shape[0]}")
    
    # Train models
    trainer.train_models(X_train, X_test, y_train, y_test)
    
    # Evaluate models
    trainer.evaluate_models(X_test, y_test)
    
    # Print results
    trainer.print_evaluation_results()
    
    # Select best model
    best_name, best_model = trainer.select_best_model()
    
    # Plot comparison
    trainer.plot_comparison()
    
    # Save best model
    trainer.save_best_model()
    
    print("\n" + "="*60)
    print("TRAINING COMPLETED SUCCESSFULLY")
    print("="*60)


if __name__ == "__main__":
    main()