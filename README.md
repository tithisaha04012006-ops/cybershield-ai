# 🛡️ CyberShield AI
### AI-Powered Web Threat Detection & Digital Trust Intelligence
**Official 48-Hour Hackathon Project for HackMatrix '26**

---

## 📌 Executive Summary

**CyberShield AI** is an intelligent web security scanner and digital trust intelligence platform engineered to safeguard users against zero-day phishing links, rogue IP hostnames, typosquatting homoglyphs, and deceptive web infrastructure.

Traditional reputation blacklists often react hours or days after an attack campaign has commenced. CyberShield AI solves this challenge by performing **wire-speed structural and heuristic inspections** on URL syntax, network protocols, lexical tokens, and Shannon entropy directly from local heuristics—delivering explainable risk assessments before sensitive credentials or payment data are submitted.

---

## ⚡ Core Features

- **Multi-Vector Threat Inspection:**
  - 🌐 **Protocol & TLS Verification:** Flags unencrypted plain HTTP connections vulnerable to Man-in-the-Middle (MitM) attacks.
  - 🖥️ **Direct IP Hostname Interception:** Detects bare IPv4, IPv6, and octal/hexadecimal obfuscated hostnames commonly deployed in phishing kits and botnet command-and-control (C2).
  - 🔡 **Typosquatting & Punycode Defense:** Detects lookalike homoglyphs (e.g., `paypa1`, `goog1e`) and Punycode (`xn--`) internationalized domain deception.
  - 🎣 **Credential & Social Engineering Radar:** Identifies authentication tokens (`verify`, `signin`, `password`) and urgency bait (`free-gift`, `account-suspended`, `bonus`) in suspicious contexts.
  - 🔀 **Open Redirect & Embedded Protocol Scans:** Flags nested URLs, double-slash redirection exploits, and credential injection `@` symbols.
  - 📊 **Shannon Entropy Anomaly Profiling:** Calculates domain character entropy to detect algorithmic domain generation (DGA) used by malware.
- **Explainable Digital Trust & Risk Score (0–100):**
  - Transparent mathematical breakdown showing exact risk points added and positive trust factors credited.
  - Tri-level classification: **Low Risk (Preliminary Safe)**, **Medium Risk (Suspicious)**, and **High Risk (Critical Threat)**.
- **Actionable User Guidance:** Context-aware protective recommendations tailored to specific detected vulnerabilities.
- **Clear Preliminary Assessment Disclaimer:** Transparently communicates that automated heuristics provide preliminary defense rather than absolute guarantees.
- **Security Operations Center (SOC) Dashboard:**
  - Real-time aggregate statistics (Total Scanned, Low/Med/High counts, HTTPS adoption %).
  - Interactive **Chart.js** risk distribution and threat volume visualization (with automatic offline CSS/SVG fallback).
  - Searchable, filterable audit history stored permanently in **SQLite**.
  - One-click **CSV Export** and **Clear History** options.
- **Zero-Day Threat Reporting:** Built-in form allowing researchers and users to submit suspicious URLs directly into the database triage queue.

---

## 🛠️ Technology Stack

| Layer | Technology | Description |
| :--- | :--- | :--- |
| **Frontend** | HTML5, CSS3, Modern JavaScript (ES6+) | Glassmorphism UI, cyber animations, responsive layout |
| **Data Viz** | Chart.js 4.4 + Inline Fallback Engine | Dark cyber aesthetic with full offline capability |
| **Backend** | Python Flask (v3+) | RESTful API, heuristic scoring engine, routing |
| **Database** | SQLite3 (Built-in Python standard library) | Zero-setup, portable, persistent audit history |
| **Platform** | Cross-platform (Windows, macOS, Linux) | Optimized for local execution in VS Code |

---

## 📁 Project Structure

```
cybershield-ai/
│
├── app.py                     # Main Flask application & RESTful routing
├── scanner_engine.py          # Multi-vector heuristic threat detection engine
├── database.py                # SQLite schema, data access layer & seed data
├── requirements.txt           # Minimal pip dependencies (Flask)
├── test_app.py                # End-to-end integration & API test suite
├── test_scanner.py            # Dedicated scanner heuristic unit tests
├── README.md                  # Comprehensive documentation & presentation guide
│
├── static/
│   ├── css/
│   │   ├── style.css          # Cyberpunk/glassmorphism dark UI theme
│   │   └── dashboard.css      # SOC dashboard & analytics styles
│   └── js/
│       ├── main.js            # Frontend scanner logic & cyber animations
│       └── dashboard.js       # Chart.js visualization, filters & modal handlers
│
└── templates/
    ├── index.html             # Main scanner & landing page
    └── dashboard.html         # Security Operations Center dashboard
```

---

## 🚀 Quick Start Guide (Run Locally in VS Code)

### 1. Prerequisites
- Python 3.9+ installed on your computer.
- VS Code (or your preferred terminal).

### 2. Open Project
Open the project directory in VS Code:
```bash
cd "c:\Users\tithi\Downloads\New folder"
```

### 3. Install Dependencies
Flask is the only external dependency. Install via terminal:
```bash
pip install -r requirements.txt
```
*(Or simply `pip install Flask`)*

### 4. Run the Application
Start the local development server:
```bash
python app.py
```

### 5. Access the Web Application
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```
- **Scanner & Landing Page:** `http://127.0.0.1:5000/`
- **Security Dashboard:** `http://127.0.0.1:5000/dashboard`

---

## 🧪 Demonstration & Test Presets

For hackathon judges and live presentations, quick 1-click test presets are built directly into the hero interface:

| Preset Name | Sample URL | Expected Result |
| :--- | :--- | :--- |
| 🔴 **Phishing IP Simulation** | `http://192.168.1.1/paypal-update-account/verify.php?token=xyz` | **High Risk** (Raw IP, Credential Tokens, No HTTPS) |
| 🟡 **Urgency Scam** | `http://free-crypto-giveaway-claim2026.xyz/login` | **High Risk** (Abuse TLD `.xyz`, Scam Bait, No HTTPS) |
| 🟣 **Brand Typosquatting** | `http://paypa1-secure-billing-service.top/auth` | **High Risk** (Leetspeak `paypa1`, Fake Billing, `.top`) |
| 🟢 **Reputable Authority** | `https://github.com` | **Low Risk** (Established Domain, HTTPS Encrypted) |

### Running Automated Verification Tests
You can verify all endpoints and heuristics with a single command:
```bash
python test_app.py
```
Output:
```
Ran 10 tests in 0.32s
OK
```

---

## 🔒 Threat Intelligence Notice & Disclosures

- **Honest Heuristic Engine:** CyberShield AI uses genuine local lexical, structural, and mathematical heuristics. It does not fabricate external threat intelligence API responses.
- **Extensibility:** The engine is modularly structured. If enterprise APIs (such as VirusTotal, Google Safe Browsing, or WhoisXML) are desired in future deployments, their responses can be cleanly combined into `scanner_engine.py` as additive vectors.
- **Preliminary Security Assessment:** Automated tools assist in early detection but should be paired with user vigilance, multi-factor authentication (MFA), and official domain verification before submitting confidential data.

---

## 👥 HackMatrix '26 Team Presentation Highlights

1. **48-Hour Innovation:** Full-stack cybersecurity web application built from scratch.
2. **Speed:** Sub-15ms heuristic response time with zero external API latency or rate limits.
3. **Usability:** Designed for non-technical users while providing detailed diagnostic telemetry for security analysts.
4. **Data Privacy:** Local scans do not transmit inspected URLs to third-party commercial data brokers.

---
*Built with ❤️ for HackMatrix '26.*
