import pandas as pd

# Read scam texts
with open(r'c:\Users\bharathi\Downloads\archive\English_Scam.txt', 'r', encoding='utf-8') as f:
    scam_texts = f.read().split('\n\n')

# Read non-scam texts
with open(r'c:\Users\bharathi\Downloads\archive\English_NonScam.txt', 'r', encoding='utf-8') as f:
    non_scam_texts = f.read().split('\n\n')

# Clean up the texts (remove empty strings and strip whitespace)
scam_texts = [text.strip() for text in scam_texts if text.strip()]
non_scam_texts = [text.strip() for text in non_scam_texts if text.strip()]

print(f"Scam texts: {len(scam_texts)}")
print(f"Non-scam texts: {len(non_scam_texts)}")

# Create DataFrame
scam_data = pd.DataFrame({
    'text': scam_texts,
    'label': 'vishing'
})

non_scam_data = pd.DataFrame({
    'text': non_scam_texts,
    'label': 'safe'
})

# Combine datasets
combined_data = pd.concat([scam_data, non_scam_data], ignore_index=True)

# Shuffle the data
combined_data = combined_data.sample(frac=1, random_state=42).reset_index(drop=True)

# Save to CSV
combined_data.to_csv('dataset_vishing.csv', index=False)

print(f"Total samples: {len(combined_data)}")
print(f"Vishing samples: {len(combined_data[combined_data['label'] == 'vishing'])}")
print(f"Safe samples: {len(combined_data[combined_data['label'] == 'safe'])}")
print("Dataset saved to dataset_vishing.csv")
