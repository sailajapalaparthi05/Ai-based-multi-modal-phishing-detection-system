print("Testing imports...")
try:
    import flask
    print("✓ flask imported")
except Exception as e:
    print(f"✗ flask error: {e}")

try:
    import nltk
    print("✓ nltk imported")
except Exception as e:
    print(f"✗ nltk error: {e}")

try:
    import pandas
    print("✓ pandas imported")
except Exception as e:
    print(f"✗ pandas error: {e}")

try:
    import numpy
    print("✓ numpy imported")
except Exception as e:
    print(f"✗ numpy error: {e}")

try:
    import lightgbm
    print("✓ lightgbm imported")
except Exception as e:
    print(f"✗ lightgbm error: {e}")

try:
    import sklearn
    print("✓ sklearn imported")
except Exception as e:
    print(f"✗ sklearn error: {e}")

print("All basic imports tested")
