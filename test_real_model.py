import sys
sys.path.insert(0, '.')
from modules.sms_service import SMSService

service = SMSService()

# Test messages
test_messages = [
    ('URGENT: Your bank account has been suspended. Click here to verify: http://fake-bank.com', 'phishing'),
    ('Hey, are we still meeting for dinner tonight?', 'safe'),
    ('Congratulations! You have won $1000000. Claim your prize now: http://lottery-scam.com', 'phishing'),
    ('Your OTP is 123456. Never share this with anyone. Verify your account: http://phishing-site.com', 'phishing'),
    ('Canara Bank: An amount of INR 13.00 has been CREDITED to your account XXXX7915 on 28/06/2026 towards interest. Total Avail.bal INR 2,045.00.', 'safe'),
    ('Enjoy up to Rs. 15,000 off at 70+ brands! Shop safely with your Airtel Payment Bank Safe Second Account. Open now https://i.airtel.in/CKYC_CLI_Shop', 'safe')
]

print('Testing SMS Detection with Real Dataset Model')
print('=' * 60)

for message, expected in test_messages:
    result = service.analyze_sms(message)
    status = 'PASS' if result['verdict'] == expected else 'FAIL'
    print(f'{status} - Expected: {expected}, Got: {result["verdict"]} ({result["confidence"]}% confidence)')
    print(f'   Risk Score: {result["risk_score"]}/100')
    print(f'   SMS Model: {result["model_used"]}')
    print()
