"""
Merge multiple email phishing datasets into a single unified dataset.
"""

import pandas as pd
import os

# Paths to new dataset files
DATASET_DIR = r"c:\Users\bharathi\Downloads\archive (1)"
OUTPUT_PATH = r"D:\PHISHING_DETECTION\PHISHING-DETECTION\dataset_email.csv"

def read_and_normalize(filepath):
    """Read CSV and normalize to have text_combined and label columns."""
    try:
        df = pd.read_csv(filepath)
        print(f"Loaded {os.path.basename(filepath)}: {len(df)} rows, columns: {list(df.columns)}")
        
        # Handle different column structures
        if 'text_combined' in df.columns and 'label' in df.columns:
            # Already in correct format
            return df[['text_combined', 'label']]
        
        # Combine subject and body into text_combined
        if 'subject' in df.columns and 'body' in df.columns:
            df['text_combined'] = df['subject'].fillna('').astype(str) + ' ' + df['body'].fillna('').astype(str)
        elif 'body' in df.columns:
            df['text_combined'] = df['body'].fillna('').astype(str)
        elif 'subject' in df.columns:
            df['text_combined'] = df['subject'].fillna('').astype(str)
        else:
            print(f"Warning: No text columns found in {os.path.basename(filepath)}")
            return None
        
        # Ensure label column exists
        if 'label' not in df.columns:
            print(f"Warning: No label column in {os.path.basename(filepath)}")
            return None
        
        return df[['text_combined', 'label']]
    
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return None

def main():
    # List of all CSV files in the archive
    csv_files = [
        os.path.join(DATASET_DIR, 'phishing_email.csv'),
        os.path.join(DATASET_DIR, 'CEAS_08.csv'),
        os.path.join(DATASET_DIR, 'Enron.csv'),
        os.path.join(DATASET_DIR, 'Ling.csv'),
        os.path.join(DATASET_DIR, 'Nazario.csv'),
        os.path.join(DATASET_DIR, 'Nigerian_Fraud.csv'),
        os.path.join(DATASET_DIR, 'SpamAssasin.csv'),
    ]
    
    all_data = []
    
    for filepath in csv_files:
        if os.path.exists(filepath):
            df = read_and_normalize(filepath)
            if df is not None:
                all_data.append(df)
        else:
            print(f"File not found: {filepath}")
    
    if all_data:
        # Merge all datasets
        merged_df = pd.concat(all_data, ignore_index=True)
        
        # Clean up: remove empty text_combined, handle missing labels
        merged_df = merged_df[merged_df['text_combined'].str.strip() != '']
        merged_df = merged_df.dropna(subset=['label'])
        
        # Convert label to int
        merged_df['label'] = merged_df['label'].astype(int)
        
        print(f"\nMerged dataset: {len(merged_df)} total rows")
        print(f"Label distribution:\n{merged_df['label'].value_counts()}")
        
        # Save merged dataset
        merged_df.to_csv(OUTPUT_PATH, index=False)
        print(f"\nSaved merged dataset to: {OUTPUT_PATH}")
    else:
        print("No data to merge!")

if __name__ == "__main__":
    main()
