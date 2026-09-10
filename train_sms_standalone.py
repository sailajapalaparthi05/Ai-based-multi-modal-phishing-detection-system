"""
Standalone SMS model training script to avoid import conflicts.
"""

import sys
import os

# Add the project directory to the path
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

# Import SMS training module
from modules.train_sms_model import SMSModelTrainer

def main():
    """Main training function"""
    print("="*60)
    print("SMS PHISHING DETECTION MODEL TRAINING")
    print("="*60)
    
    # Initialize trainer
    trainer = SMSModelTrainer()
    
    # Load dataset (will use the new dataset_sms.csv by default)
    df = trainer.load_dataset()
    
    # Prepare features
    X, y, feature_names = trainer.prepare_features(df)
    
    # Split data
    from sklearn.model_selection import train_test_split
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
