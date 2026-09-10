# AI-Based Multi-Platform Phishing Detection System - Module Documentation

## Overview
This document provides a comprehensive explanation of all modules in the AI-Based Multi-Platform Phishing Detection System, including their working mechanisms, ML models, datasets, and detection flows.

---

## 🔍 **1. WEBSITE/URL PHISHING DETECTION**

### Flask Route
- **Route:** `/predict`
- **Handler:** `app.py` → URL prediction function

### ML Model
- **Type:** Ensemble Learning (Random Forest + Extra Trees + XGBoost)
- **Dataset:** `dataset.csv`
- **Model File:** `model/phishing_model.pkl`

### Working Flow
```
USER INPUT (URL)
↓
URL FEATURE EXTRACTION
  - URL length
  - Domain age
  - SSL certificate status
  - DNS records
  - Special characters count
  - Subdomain count
  - TLD analysis
  - Keyword presence (login, secure, bank, etc.)
↓
ML MODEL PREDICTION (Ensemble)
  - Random Forest (500 trees)
  - Extra Trees (500 trees) 
  - XGBoost (300 trees)
  - Soft voting combination
↓
SECURITY CHECKS
  - SSL validation
  - DNS resolution
  - Domain reputation
↓
RISK SCORE CALCULATION
  - ML prediction (weighted)
  - SSL/DNS/Reputation (weighted)
↓
FINAL VERDICT
  - SAFE (if risk < 50)
  - PHISHING (if risk >= 50)
```

### Key Features
- 20+ URL-based features
- Ensemble voting for robustness
- Real-time SSL/DNS verification
- Domain reputation checking

---

## 📧 **2. EMAIL PHISHING DETECTION**

### Flask Route
- **Route:** `/predict_email`
- **Handler:** `app.py` → Email prediction function

### ML Model
- **Type:** BiLSTM Deep Learning (TensorFlow/Keras)
- **Dataset:** `dataset_email.csv` (164,971 rows)
- **Model File:** `model/email_bilstm.h5`
- **Tokenizer:** `model/email_vocab.json`

### Working Flow
```
USER INPUT (Email Subject + Body)
↓
TEXT PREPROCESSING
  - HTML tag removal
  - URL extraction
  - Email address parsing
↓
DEEP LEARNING ANALYSIS (BiLSTM)
  - Tokenization (max 5000 words)
  - Word embedding (128 dimensions)
  - Bidirectional LSTM layers
  - Context understanding (forward + backward)
↓
URL EXTRACTION & ANALYSIS
  - Extract all URLs from email
  - Run each URL through URL phishing model
  - Aggregate URL risks
↓
COMBINED SCORING
  - BiLSTM text analysis (65%)
  - URL phishing risk (35%)
↓
FINAL VERDICT
  - SAFE/PHISHING based on combined score
  - Confidence calculation
```

### Architecture
```
Input Text → Tokenizer → Embedding Layer → BiLSTM(64) → BiLSTM(32) → Dropout → Dense(64) → Dropout → Output(1)
```

### Key Features
- Deep learning for semantic understanding
- Bidirectional context (reads text forward & backward)
- URL integration for link-based phishing
- Handles HTML emails

---

## 📱 **3. SMS PHISHING DETECTION**

### Flask Route
- **Route:** `/predict_sms`
- **Handler:** `app.py` → SMS prediction function

### ML Model
- **Type:** LightGBM (best performer among LightGBM, RF, XGBoost)
- **Dataset:** `dataset_sms.csv` (5,572 messages)
- **Model File:** `model/sms_model.pkl`

### Working Flow
```
USER INPUT (SMS Message)
↓
TEXT PREPROCESSING
  - Lowercase conversion
  - Special character removal
  - Tokenization
  - Stopword removal
  - Lemmatization
↓
FEATURE EXTRACTION (1017 features)
  - Text length, word count
  - Urgency keywords (urgent, immediate, etc.)
  - Bank keywords (bank, account, etc.)
  - Authentication keywords (OTP, verify, login)
  - Reward keywords (prize, gift, winner)
  - Crypto keywords (bitcoin, wallet)
  - URL presence
  - Phone number patterns
  - TF-IDF vectorization (1000 features)
↓
ML MODEL PREDICTION (LightGBM)
  - Gradient boosting decision trees
  - 100 estimators
  - Max depth 6
↓
URL EXTRACTION (if present)
  - Extract URLs from SMS
  - Run through URL phishing model
  - Add URL risk to overall score
↓
RISK SCORE CALCULATION
  - SMS ML prediction (primary)
  - URL risk (secondary)
  - Threat reason generation
↓
FINAL VERDICT
  - SAFE/PHISHING
  - Confidence percentage
```

### Key Features
- 1017 total features (17 numerical + 1000 TF-IDF)
- Keyword categorization for different scam types
- URL integration for SMS with links
- Handles legitimate OTP messages

---

## 📞 **4. VISHING (VOICE PHISHING) DETECTION**

### Flask Route
- **Route:** `/predict_vishing`
- **Handler:** `app.py` → Vishing prediction function

### ML Model
- **Type:** Logistic Regression with TF-IDF
- **Dataset:** `dataset_vishing.csv`
- **Model File:** `models/vishing_model.pkl`
- **Vectorizer:** `models/vishing_vectorizer.pkl`

### Working Flow
```
USER INPUT (WAV Audio File)
↓
AUDIO TRANSCRIPTION
  - Google Speech Recognition (primary)
  - OpenAI Whisper (fallback)
  - Full text transcription
↓
TEXT PREPROCESSING
  - Lowercase conversion
  - Special character removal
  - Noise reduction
↓
FEATURE EXTRACTION (TF-IDF)
  - 1000 max features
  - N-gram range (1-2 words)
  - Stopword removal
↓
ML MODEL PREDICTION (Logistic Regression)
  - TF-IDF vectorized input
  - Class weight balanced
  - Probability output
↓
PATTERN MATCHING (Rule-based)
  - OTP request patterns
  - PIN request patterns  
  - Password request patterns
  - Urgent/threatening language
  - Bank impersonation
  - Remote access requests
↓
LEGITIMATE CALL DETECTION
  - Normal call patterns
  - Customer service phrases
  - Informational calls
↓
RISK SCORE CALCULATION
  - ML prediction (primary)
  - Pattern matches (secondary)
  - Legitimate indicators (reducing factor)
↓
FINAL VERDICT
  - SAFE/VISHING
  - Confidence percentage
  - Detailed threat reasons
```

### Key Features
- Dual transcription engine (Google + Whisper)
- Pattern-based vishing detection
- Legitimate call recognition
- Full transcription display

---

## 📷 **5. QR CODE PHISHING DETECTION**

### Flask Route
- **Route:** `/predict_qr`
- **Handler:** `app.py` → QR prediction function

### ML Model
- **Type:** Same URL phishing ensemble model
- **Dataset:** Same as URL module
- **Model File:** `model/phishing_model.pkl`

### Working Flow
```
USER INPUT (QR Image or Camera Scan)
↓
QR DECODING
  - Image upload: pyzbar library
  - Camera scan: zxingcpp library
  - QR code extraction
↓
URL EXTRACTION
  - Parse URL from QR data
  - Handle multiple URLs
  - Clean and validate URL
↓
URL PHISHING ANALYSIS
  - Run through URL phishing model
  - Extract URL features
  - ML ensemble prediction
↓
SECURITY CHECKS
  - SSL validation
  - DNS resolution
  - Domain reputation
  - Domain age
  - Brand spoofing detection
↓
RISK SCORE CALCULATION
  - ML prediction (primary)
  - Security checks (secondary)
  - Brand analysis
↓
FINAL VERDICT
  - SAFE/PHISHING
  - Risk score 0-100
  - Threat indicators
  - Extracted URL display
```

### Key Features
- Dual QR decoding (pyzbar + zxingcpp)
- Camera and file upload support
- URL extraction and validation
- Brand spoofing detection
- Navigation to extracted URL

---

## 🌐 **6. BROWSER THREAT DETECTION**

### Flask Route
- **Route:** `/predict_browser`
- **Handler:** `app.py` → Browser prediction function

### ML Models
- **URL Model:** URL phishing ensemble model
- **Visual Model:** MobileNetV2 Deep Learning
- **Dataset:** Synthetic images for MobileNetV2
- **Model Files:** 
  - `model/phishing_model.pkl` (URL)
  - `model/browser_mobilenet.h5` (Visual)

### Working Flow
```
CHROME EXTENSION DATA
  - Current URL
  - Redirect chain
  - Screenshot (base64)
  - Extension permissions
  - Popup messages
  - Login forms detected
  - Password fields
  - Form actions
  - Downloads
  - New tabs/popups
↓
URL ANALYSIS
  - Run current URL through URL phishing model
  - Domain reputation check
  - SSL/DNS validation
↓
VISUAL ANALYSIS (MobileNetV2)
  - Screenshot classification
  - 4 classes: Legitimate, Fake Login, Browser Scam, Fake Update
  - Deep learning image recognition
↓
BEHAVIORAL ANALYSIS
  - Redirect patterns
  - Popup/alert frequency
  - Download behavior
  - Form analysis (login/payment)
  - External form submissions
  - JavaScript patterns
  - Permission requests
↓
TRUSTED DOMAIN CHECK
  - Known legitimate domains (Google, Microsoft, etc.)
  - Login form context
  - Form action analysis
↓
WEIGHTED RISK CALCULATION
  - URL ML model (30%)
  - Visual DL model (20%)
  - Behavioral heuristics (50%)
  - Security bonus (up to -25%)
↓
MULTI-SIGNAL VERDICT
  - Requires multiple independent threats
  - Single weak signal ≠ phishing
  - Strong security signals reduce risk
↓
FINAL VERDICT
  - SAFE/PHISHING
  - Confidence percentage
  - Detailed threat reasons
```

### Key Features
- Multi-modal analysis (URL + Visual + Behavioral)
- Real browser behavior monitoring
- Chrome extension integration
- Trusted domain recognition
- Multi-signal verification (prevents false positives)

---

## 🎯 **COMMON ACROSS ALL MODULES**

### Shared Components
- **Database Logging:** All scans logged to database for history
- **Dashboard:** Centralized view of all scan history
- **Risk Score:** 0-100 scale for consistency
- **Confidence:** Percentage for prediction certainty
- **Threat Reasons:** Detailed explanation of detection

### Security Checks (Most Modules)
- SSL certificate validation
- DNS resolution verification
- Domain reputation analysis
- Brand spoofing detection

### ML Model Types
- **Ensemble Methods:** URL, QR (RF + ET + XGBoost)
- **Deep Learning:** Email (BiLSTM), Browser (MobileNetV2)
- **Gradient Boosting:** SMS (LightGBM)
- **Traditional ML:** Vishing (Logistic Regression)

### UI Integration
- All modules use consistent frontend design
- Progress circles for confidence display
- Risk meters for threat level
- Detailed analysis cards
- Responsive design

---

## 📊 **TRAINING DATASETS**

### URL/QR Dataset
- **File:** `dataset.csv`
- **Content:** URL features + phishing labels
- **Rows:** Combined from multiple sources
- **Usage:** URL and QR phishing detection

### Email Dataset
- **File:** `dataset_email.csv`
- **Content:** Email subject + body + labels
- **Rows:** 164,971 (merged from 7 sources)
- **Sources:** CEAS_08, Enron, Ling, Nazario, Nigerian_Fraud, SpamAssasin, phishing_email
- **Usage:** Email phishing detection

### SMS Dataset
- **File:** `dataset_sms.csv`
- **Content:** SMS messages + labels
- **Rows:** 5,572 messages
- **Labels:** ham (safe) / smish (phishing)
- **Usage:** SMS phishing detection

### Vishing Dataset
- **File:** `dataset_vishing.csv`
- **Content:** Transcribed call text + labels
- **Labels:** safe / vishing
- **Usage:** Voice phishing detection

### Browser Visual Dataset
- **Type:** Synthetic images (generated programmatically)
- **Classes:** 4 (Legitimate, Fake Login, Browser Scam, Fake Update)
- **Usage:** Browser screenshot classification

---

## 🔧 **TECHNICAL ARCHITECTURE**

### Backend Technologies
- **Framework:** Flask (Python)
- **ML Libraries:** scikit-learn, TensorFlow/Keras, LightGBM, XGBoost
- **Data Processing:** pandas, NumPy
- **Natural Language:** NLTK, BeautifulSoup
- **Image Processing:** OpenCV, PIL, pyzbar, zxingcpp
- **Audio Processing:** SpeechRecognition, OpenAI Whisper

### Frontend Technologies
- **Framework:** HTML/CSS/JavaScript with Jinja2 templating
- **Styling:** Custom CSS with glassmorphism design
- **Icons:** Font Awesome 6.7.2
- **Font:** Plus Jakarta Sans
- **Responsive:** Mobile-friendly design

### Chrome Extension
- **Manifest Version:** V3
- **Permissions:** tabs, storage, webNavigation, notifications, downloads
- **Components:** Background script, content script, popup
- **Functionality:** Real-time browser monitoring and threat detection

---

## 📈 **MODEL PERFORMANCE**

### URL/QR Model
- **Type:** Ensemble (RF + ET + XGBoost)
- **Accuracy:** ~98.7% (on merged dataset)
- **Features:** 20+ URL-based features
- **Validation:** Train/test split with cross-validation

### Email Model
- **Type:** BiLSTM Deep Learning
- **Architecture:** Embedding → BiLSTM(64) → BiLSTM(32) → Dense(64) → Output
- **Dataset:** 164,971 emails
- **Training:** 10 epochs, batch size 32

### SMS Model
- **Type:** LightGBM (selected as best among 3 models)
- **Accuracy:** 98.74% (test accuracy)
- **Features:** 1017 total features
- **Compared:** LightGBM vs Random Forest vs XGBoost

### Vishing Model
- **Type:** Logistic Regression with TF-IDF
- **Features:** 1000 TF-IDF features
- **Validation:** Train/test split
- **Pattern Matching:** Rule-based complement to ML

### Browser Visual Model
- **Type:** MobileNetV2 Transfer Learning
- **Architecture:** MobileNetV2 → GlobalAveragePooling → Dense(128) → Dense(4)
- **Classes:** 4 output classes
- **Training:** 8 epochs on synthetic images

---

## 🚀 **DEPLOYMENT & USAGE**

### Running the Application
```bash
# Install dependencies
pip install -r requirements.txt

# Run Flask application
python app.py

# Access at: http://localhost:5000
```

### Chrome Extension Setup
1. Load unpacked extension in Chrome
2. Grant necessary permissions
3. Extension monitors browser activity
4. Sends data to Flask backend via API

### Training Models
```bash
# Train all models
python train_model.py all

# Train specific model
python train_model.py url
python train_model.py sms
python train_model.py email
python train_model.py vishing
```

---

## 🎨 **UI/UX DESIGN**

### Design Principles
- Modern cybersecurity aesthetic
- Deep navy/midnight background
- Glassmorphism cards
- Professional typography
- Smooth animations
- Responsive layout

### Module Navigation
- Websites (URL phishing)
- Emails (Email phishing)
- SMS (SMS phishing)
- Vishing (Voice phishing)
- Browser (Browser threat detection)
- QR Code (QR phishing)
- History Logs (Dashboard)

### Result Display
- Circular progress for confidence
- Risk score meters
- Detailed threat indicators
- Security analysis cards
- Verdict with clear status

---

## 🔒 **SECURITY CONSIDERATIONS**

### Data Privacy
- No user data stored permanently
- Transcription processed in real-time
- Screenshots processed locally
- No external API calls for predictions

### Model Security
- Models trained on diverse datasets
- Regular validation and testing
- False positive minimization
- Multi-signal verification

### API Security
- CORS configuration
- Input validation
- Error handling
- Rate limiting consideration

---

## 📝 **MAINTENANCE & UPDATES**

### Model Retraining
- Periodic retraining with new data
- Performance monitoring
- False positive analysis
- Model versioning

### Dataset Updates
- New phishing patterns
- Legitimate site additions
- Threat intelligence integration
- Dataset balancing

### Feature Enhancements
- New threat vectors
- Improved detection accuracy
- Better user experience
- Enhanced reporting

---

## 🎯 **SUMMARY**

This AI-Based Multi-Platform Phishing Detection System provides comprehensive protection across multiple attack vectors:

1. **URL/QR Phishing:** Ensemble ML with 20+ features
2. **Email Phishing:** BiLSTM deep learning with URL integration
3. **SMS Phishing:** LightGBM with 1017 features
4. **Vishing:** Audio transcription with pattern matching
5. **Browser Threats:** Multi-modal analysis with real-time monitoring

Each module uses appropriate ML techniques for its specific domain while maintaining consistent UI/UX and centralized logging. The system is designed for accuracy, user-friendliness, and real-world deployment.

---

**Documentation Version:** 1.0  
**Last Updated:** 2026-08-23  
**Project:** AI-Based Multi-Platform Phishing Detection System
