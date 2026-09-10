#!/usr/bin/env python
"""Simple test to verify risk score calculation"""
import sys
import os
sys.path.insert(0, os.getcwd())

from app import analyze_risk

# Test URLs
test_urls = [
    'https://www.google.com',
    'http://fake-login-verify.xyz',
    'http://bit.ly/test',
    'http://suspicious-site.tk',
]

print("Risk Score Calculation Test")
print("=" * 50)

for url in test_urls:
    print(f"\nURL: {url}")
    
    # Basic risk analysis only
    risks, risk_score = analyze_risk(url)
    print(f"Risks: {risks}")
    print(f"Risk Score: {risk_score}/100")
    print("-" * 30)
