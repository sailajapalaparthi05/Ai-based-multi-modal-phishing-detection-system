import requests
import time

# Test URLs
test_urls = [
    'https://www.google.com',
    'https://www.microsoft.com', 
    'https://www.wikipedia.org',
    'http://fake-login-verify.xyz',
    'http://suspicious-site.tk'
]

print("Testing Risk Score Functionality")
print("=" * 60)

for url in test_urls:
    try:
        response = requests.post('http://127.0.0.1:5000/predict', data={'url': url}, timeout=30)
        print(f"\nURL: {url}")
        print(f"Status: {response.status_code}")
        
        # Look for risk_score in the response
        if 'risk_score' in response.text:
            import re
            match = re.search(r'risk_score">(\d+)', response.text)
            if match:
                risk = match.group(1)
                print(f"Risk Score: {risk}/100")
            else:
                print("Risk Score: Not found in expected format")
        else:
            print("Risk Score: Variable not found in response")
            
        # Look for status
        if 'safe' in response.text.lower():
            print("Status: Safe")
        elif 'phishing' in response.text.lower():
            print("Status: Phishing")
        else:
            print("Status: Unknown")
            
    except Exception as e:
        print(f"\nURL: {url}")
        print(f"Error: {e}")
    
    time.sleep(2)  # Small delay between requests

print("\n" + "=" * 60)
print("Test Complete")
