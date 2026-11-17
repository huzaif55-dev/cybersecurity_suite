# CyberShield: Cybersecurity Intelligence & Habit Suite

A full-stack, modular cybersecurity suite built with **Python, Flask, SQLite, Scikit-Learn, and Cryptography**.

---

## 🛡️ The 5 Core Features

### 1. Security Checklist
* **Task Management**: Add custom cybersecurity tasks with descriptions, categories, and due dates.
* **Preloaded Templates**: Includes essential templates for Operating System & Security Patches, 3-2-1 Backups, 2FA Audits, Router Hardening, and Session Revocation.
* **Status Tracking**: Filter dynamically by **All**, **Pending**, **Overdue** (automated comparison with current date), and **Completed**.
* **Progress Reporting**: Real-time progress bar and completion rate calculation.

### 2. Suspicious Message and Link Checker
* **Multi-Vector Analysis**: Inspects SMS/email text and embedded URLs.
* **Suspicious Keyword Detection**: Analyzes urgency tactics ("immediate action required", "account suspended"), financial/crypto fraud, and brand impersonation (PayPal, Amazon, Bank of America, FedEx).
* **URL Syntax & Threat Patterns**: Flags raw IP hostnames, high-risk TLDs (`.xyz`, `.top`, `.tk`), `@` symbol redirection tricks, URL shortener masking (`bit.ly`, `tinyurl`), non-standard ports, and unencrypted HTTP.
* **Transparent Reasoning**: Displays *why* something was flagged with severity ratings and granular risk scores (0–100).
* **Safety Recommendations**: Provides actionable instructions tailored to the detected threats.

### 3. Security Habit Tracker
* **Daily Habit Tracking**: Logs core daily habits: 2FA/MFA usage, OS & browser software updates, avoiding password reuse, phishing vigilance, secure Wi-Fi/VPN, and screen lock / backup checks.
* **Weekly Progress**: Calculates 7-day compliance averages and active streak days.
* **Interactive Visualization**: Rendered via **Chart.js** with a 7-day adherence trend line chart and individual habit breakdown metrics.
* **Smart Recommendations**: Evaluates weakest habits and delivers targeted defense priorities.

### 4. ML Scam Message Classifier
* **Dataset**: Automated download and training on the **UCI SMS Spam Collection dataset** (5,572 real SMS messages).
* **NLP Pipeline**: Text normalization, URL/number/currency tokenization, punctuation/stopword removal, and **TF-IDF Vectorization** (1–2 n-grams, sublinear TF scaling).
* **Machine Learning Model**: Balanced **Logistic Regression** classifier with cached model persistence (`joblib`).
* **Evaluation Metrics**: Computes **Accuracy, Precision, Recall, and F1-score**.
* **Visual Confusion Matrix**: Interactive matrix breakdown (True Negatives, False Positives, False Negatives, True Positives).
* **Live Inference**: Real-time message classification with scam confidence probability and influential word feature weights.

### 5. Password Manager and Analyzer
* **Input-Based Suggestions**: Takes any custom phrase or keyword and derives 3 distinct cryptographic variants:
  1. *Hardened Leetspeak & Salt*
  2. *Cryptographic Hash-Derived Expansion*
  3. *Multi-Token Memorable Passphrase*
* **Encrypted Storage**: Credentials encrypted on disk using **AES-128 (Fernet)**.
* **Metadata Tracking**: Saves password with **Name**, **For (Website/App)**, **Username**, **Category**, and **Date Created & Updated**.
* **Real-time Password Analyzer**: Instant evaluation of Shannon entropy (bits), GPU brute-force crack time, character diversity checklist, and dictionary pattern detection.

---

## 🚀 Getting Started

### 1. Set the Workspace
Recommended workspace directory:
```
C:\Users\huzai\.gemini\antigravity\scratch\cybersecurity_suite
```

### 2. Run the Application
Open a terminal in the project directory and run:
```bash
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```
