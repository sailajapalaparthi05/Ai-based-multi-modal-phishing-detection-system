"""
Convert SMS smishing dataset from text format to CSV format.
"""

import pandas as pd
import os

# Input and output paths
INPUT_PATH = r"c:\Users\bharathi\Downloads\archive (2)\smssmishcollection\SMSSmishCollection.txt"
OUTPUT_PATH = r"D:\PHISHING_DETECTION\PHISHING-DETECTION\dataset_sms.csv"

def convert_sms_dataset():
    """Convert SMS dataset from tab-separated text to CSV format."""
    
    # Read the tab-separated file
    print(f"Reading SMS dataset from {INPUT_PATH}")
    df = pd.read_csv(INPUT_PATH, sep='\t', header=None, names=['label', 'message'])
    
    print(f"Loaded {len(df)} messages")
    print(f"Original label distribution: {df['label'].value_counts().to_dict()}")
    
    # Convert labels: ham -> 0 (safe), smish -> 1 (phishing)
    df['label'] = df['label'].map({'ham': 0, 'smish': 1})
    
    print(f"Converted label distribution: {df['label'].value_counts().to_dict()}")
    
    # Remove any rows with missing values
    df = df.dropna()
    
    print(f"After cleaning: {len(df)} messages")
    
    # Save as CSV
    df.to_csv(OUTPUT_PATH, index=False)
    print(f"Saved dataset to {OUTPUT_PATH}")
    
    return df

if __name__ == "__main__":
    convert_sms_dataset()
