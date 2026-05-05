# 🛡️ AI Phishing Link Scanner

A comprehensive Python-based phishing detection tool that combines **static analysis**, **VirusTotal reputation checks**, and **AI-powered semantic analysis** to identify malicious URLs.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

---

## 📋 Table of Contents

- [Features](#-features)
- [How It Works](#-how-it-works)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration Setup](#-configuration-setup)
- [Usage](#-usage)
- [Detection Methods](#-detection-methods)
- [Example Outputs](#-example-outputs)
- [API Rate Limits](#-api-rate-limits)
- [Troubleshooting](#-troubleshooting)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### Multi-Layered Detection System

- **🔍 Static Analysis**
  - URL structure validation using regex
  - Typosquatting detection (e.g., `amaz0n.com`, `g00gle.com`)
  - Suspicious keyword identification
  - IP address detection in URLs
  - TLD (Top-Level Domain) reputation checking
  - HTTP vs HTTPS protocol analysis

- **🌐 VirusTotal Integration**
  - Real-time reputation checks
  - Community-powered threat intelligence
  - 70+ antivirus engine results
  - Historical URL scanning data

- **🤖 AI Semantic Analysis**
  - GPT-4 or Google Gemini powered
  - Context-aware phishing pattern recognition
  - Natural language reasoning
  - Confidence scoring
  - Detailed threat explanation

- **📊 Comprehensive Reporting**
  - Color-coded risk indicators
  - Weighted risk scoring
  - Actionable recommendations
  - Detailed analysis breakdown

---

## 🔬 How It Works

```text
┌─────────────────┐
│   Input URL     │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│           STEP 1: URL Validation            │
│  → Regex pattern matching                   │
│  → Structure verification                   │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│           STEP 2: Static Analysis          │
│  → Typosquatting detection                  │
│  → Suspicious keyword scanning              │
│  → Domain/subdomain analysis                │
│  → Risk score calculation (0-100)           │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│       STEP 3: VirusTotal Reputation Check    │
│  → Submit URL to VT API                     │
│  → Wait for analysis completion             │
│  → Retrieve malicious/suspicious votes      │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│        STEP 4: LLM Semantic Analysis        │
│  → Send URL + static results to AI          │
│  → Contextual pattern recognition           │
│  → Generate phishing verdict                │
│  → Provide detailed reasoning               │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│              FINAL VERDICT                  │
│  → Weighted risk calculation                │
│      - Static: 30%                          │
│      - VirusTotal: 40%                      │
│      - LLM Analysis: 30%                    │
│  → Risk Level: LOW / MEDIUM / HIGH          │
│  → Recommendation                           │
└─────────────────────────────────────────────┘
````

-----

## 📦 Prerequisites

### Required Software

  - **Python 3.8+** ([Download](https://www.python.org/downloads/))
      - ⚠️ **Important**: Check "Add Python to PATH" during installation

### Required API Keys

| Service | Purpose | Cost | Get Key |
|---------|---------|------|---------|
| **VirusTotal** | URL reputation checking | Free (4 req/min) | [Sign Up](https://www.virustotal.com/gui/join-us) |
| **OpenAI** | GPT-4 AI analysis | \~$0.01-0.03/scan | [Get API Key](https://platform.openai.com/api-keys) |
| **Google Gemini** *(Alternative)* | Gemini Pro AI analysis | Free tier available | [Get API Key](https://makersuite.google.com/app/apikey) |

> 💡 **Note**: You need either OpenAI OR Google Gemini (not both)

-----

## 🚀 Installation

### Step 1: Download the Project

Option A: Clone from GitHub

```bash
git clone [https://github.com/Ak-cybe/AI-Phishing-Link-Scanner.git](https://github.com/Ak-cybe/AI-Phishing-Link-Scanner.git)
cd AI-Phishing-Link-Scanner
```

Option B: Create manually

```bash
mkdir AI-Phishing-Link-Scanner
cd AI-Phishing-Link-Scanner
```

### Step 2: Create Virtual Environment (Recommended)

Create virtual environment:

```bash
python -m venv venv
```

Activate virtual environment:

  * **Windows:**
    ```bash
    venv\Scripts\activate
    ```
  * **macOS/Linux:**
    ```bash
    source venv/bin/activate
    ```

### Step 3: Install Dependencies

If `requirements.txt` exists:

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install requests python-dotenv openai google-generativeai colorama
```

### Step 4: Verify Installation

```bash
pip list
```

You should see:

  - ✅ `requests`
  - ✅ `python-dotenv`
  - ✅ `openai`
  - ✅ `google-generativeai`
  - ✅ `colorama`

-----

## ⚙️ Configuration Setup

### Environment Variables (`.env` file)

To run the project, you need to set up your environment variables. Create a file named `.env` in the root directory of your project and add your necessary variables (like API keys, etc.).

Use one of the following commands to edit the file based on your operating system:

**For Windows:**

```bash
notepad .env
```

**For Linux/macOS:**

```bash
nano .env
```

### ✅ Verify Installation

#### 🐍 Python Version Check

Ensure you are using a supported Python version (3.8 to 3.12).

```bash
python --version
```

#### 📦 Check Installed Packages

Verify that all required packages are installed with the correct minimum versions.

```bash
pip list
```

**Expected Installed Dependencies:**

| Package | Expected Version | Status |
| :--- | :--- | :--- |
| `requests` | 2.31.0 | ✅ |
| `python-dotenv` | 1.0.0 | ✅ |
| `colorama` | 0.4.6 | ✅ |
| `openai` | 1.12.0 | ✅ |
| `google-generativeai` | 0.3.2 | ✅ |

### Step 2: Add Your API Keys

Open `.env` and add your keys:

```ini
# VirusTotal API Key (Required)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Choose ONE LLM Provider:

# Option 1: OpenAI (GPT-4)
OPENAI_API_KEY=your_openai_api_key_here
LLM_PROVIDER=openai

# Option 2: Google Gemini (Alternative)
GOOGLE_API_KEY=your_google_api_key_here
LLM_PROVIDER=gemini
```

### API Key Setup Guides

#### **VirusTotal API Key**

1.  Go to [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
2.  Sign up for free account
3.  Navigate to Profile → API Key
4.  Copy your API key

#### **OpenAI API Key**

1.  Go to [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)
2.  Sign in or create account
3.  Click "Create new secret key"
4.  Copy and save the key (shown only once\!)

#### **Google Gemini API Key** *(Alternative)*

1.  Go to [https://makersuite.google.com/app/apikey](https://makersuite.google.com/app/apikey)
2.  Sign in with Google account
3.  Click "Create API Key"
4.  Copy the key

-----

## 💻 Usage

### Interactive Mode

```bash
python phishing_scanner.py
```

Then enter URL when prompted:

```text
Enter URL to scan (or 'quit' to exit):
> [https://example.com](https://example.com)
```

### Command-Line Mode

```bash
python phishing_scanner.py "[https://example.com](https://example.com)"
```

-----

## 🔍 Detection Methods

### 1\. Static Analysis Indicators

| Indicator | Risk Weight | Example |
|-----------|-------------|---------|
| **IP Address in URL** | 30 points | `http://192.168.1.1/login` |
| **Typosquatting** | 30 points | `amaz0n.com`, `g00gle.com` |
| **Suspicious TLD** | 25 points | `.tk`, `.ml`, `.ga`, `.cf`, `.gq` |
| **Excessive Subdomains** | 20 points | `secure.login.verify.paypal-update.com` |
| **@ Symbol** | 20 points | `http://trusted.com@malicious.com` |
| **Excessive Length** | 15 points | URLs \> 75 characters |
| **HTTP (not HTTPS)** | 10 points | `http://` vs `https://` |
| **Suspicious Keywords** | 5 pts each | `login`, `verify`, `urgent`, `suspended` |

### 2\. VirusTotal Reputation

  - **Malicious Votes**: URL flagged by antivirus engines
  - **Suspicious Votes**: URL shows questionable patterns
  - **Harmless Votes**: URL verified as safe
  - **Total Engines**: 70+ security vendors

**Risk Calculation**:

```python
VT_Risk = ((Malicious + Suspicious * 0.5) / Total_Engines) * 100
```

### 3\. LLM Semantic Analysis

The AI analyzes:

  - **Brand Impersonation**: Fake Amazon, PayPal, etc.
  - **Urgency Tactics**: "Urgent", "Immediate action required"
  - **Credential Harvesting**: Login pages, password resets
  - **Social Engineering**: Psychological manipulation patterns
  - **Contextual Anomalies**: Unusual domain/path combinations

**Confidence Levels**:

  - **90-100%**: High confidence (strong indicators)
  - **70-89%**: Medium-high confidence
  - **50-69%**: Medium confidence
  - **\< 50%**: Low confidence (unclear/borderline)

-----

## 📊 Example Outputs

### Example 1: Safe URL

```text
$ python phishing_scanner.py "[https://www.google.com](https://www.google.com)"
======================================================================
🔍 PHISHING LINK SCANNER

[1/4] Validating URL structure...
✓ URL structure valid

[2/4] Performing static analysis...
✓ Static analysis complete (Risk Score: 0/100)

[3/4] Checking VirusTotal reputation...
✓ VirusTotal analysis complete

[4/4] Running LLM semantic analysis...
✓ LLM analysis complete
======================================================================
📊 SCAN REPORT

URL: [https://www.google.com](https://www.google.com)

▶ STATIC ANALYSIS
Risk Score: 0/100
IP Address in URL: ✓ No
Excessive Length: ✓ No
Suspicious TLD: ✓ No
Uses HTTP (not HTTPS): ✓ No

▶ VIRUSTOTAL REPUTATION
Status: completed
Malicious Detections: 0/89
Suspicious Detections: 0/89
Harmless: 89/89

▶ LLM SEMANTIC ANALYSIS (GPT-4)
Verdict: LEGITIMATE
Confidence: 99%
Red Flags: None
Reasoning: This is the official Google domain with HTTPS...
======================================================================
🎯 FINAL VERDICT

Status: ✅ APPEARS SAFE - LOW RISK
Overall Risk: 2/100
Recommendation: URL appears legitimate, but always verify sender authenticity.
```

### Example 2: Phishing URL

```text
$ python phishing_scanner.py "[http://amaz0n-security-update.com/verify-account](http://amaz0n-security-update.com/verify-account)"
======================================================================
🔍 PHISHING LINK SCANNER

[1/4] Validating URL structure...
✓ URL structure valid

[2/4] Performing static analysis...
✓ Static analysis complete (Risk Score: 75/100)

[3/4] Checking VirusTotal reputation...
✓ VirusTotal analysis complete

[4/4] Running LLM semantic analysis...
✓ LLM analysis complete
======================================================================
📊 SCAN REPORT

URL: [http://amaz0n-security-update.com/verify-account](http://amaz0n-security-update.com/verify-account)

▶ STATIC ANALYSIS
Risk Score: 75/100
IP Address in URL: ✓ No
Excessive Length: ✓ No
Suspicious TLD: ✓ No
Uses HTTP (not HTTPS): ⚠ Yes
Suspicious Keywords: security, update, verify, account
Typosquatting Patterns: amaz[o0]n

▶ VIRUSTOTAL REPUTATION
Status: completed
Malicious Detections: 12/89
Suspicious Detections: 8/89
Harmless: 69/89

▶ LLM SEMANTIC ANALYSIS (GPT-4)
Verdict: PHISHING
Confidence: 95%
Red Flags: Typosquatting (amaz0n), urgency keywords, HTTP protocol
Reasoning: This URL exhibits classic phishing indicators including
typosquatting of the Amazon brand (using '0' instead of 'o'),
urgency-inducing keywords like 'security-update', and requests
account verification...
======================================================================
🎯 FINAL VERDICT

Status: 🚨 MALICIOUS - HIGH RISK
Overall Risk: 87/100
Recommendation: DO NOT VISIT. This URL shows strong phishing indicators.
```

-----

## ⏱️ API Rate Limits

### VirusTotal (Free Tier)

| Limit | Value |
|-------|-------|
| Requests per minute | 4 |
| Requests per day | 500 |
| Requests per month | 15,500 |

**Scanner automatically waits 15 seconds** between request and analysis retrieval to respect rate limits.

### OpenAI

| Tier | RPM | TPM | Cost |
|------|-----|-----|------|
| Free Trial | 3 | 40,000 | $5 credit |
| Tier 1 | 500 | 60,000 | Pay-as-you-go |
| Tier 2+ | Higher | Higher | Volume discounts |

**Typical scan cost**: $0.01 - $0.03 per URL

### Google Gemini

| Model | Free Tier | Paid Tier |
|-------|-----------|-----------|
| Gemini Pro | 60 req/min | Pay-as-you-go |
| Cost | Free | Much cheaper than GPT-4 |

-----

## 🐛 Troubleshooting

### Issue: `pip is not recognized`

**Solution**:
Use this instead:

```bash
python -m pip install -r requirements.txt
```

Or:

```bash
py -m pip install -r requirements.txt
```

### Issue: `VIRUSTOTAL_API_KEY not found`

**Solution**:

1.  Ensure `.env` file exists in project directory
2.  Check API key is correctly pasted (no spaces)
3.  Restart command prompt after creating `.env`

### Issue: `Rate limit exceeded`

**Solution**:

  - VirusTotal free tier: Wait 1 minute, then retry
  - Consider upgrading to premium tier for higher limits

### Issue: `OpenAI API error: 429`

**Solution**: Rate limit or quota exceeded

  - Check usage at [https://platform.openai.com/usage](https://platform.openai.com/usage)
  - Add credits or wait for quota reset
  - Switch to `LLM_PROVIDER=gemini` as alternative

-----

## 🔐 Security Considerations

### Safe Analysis

✅ **The scanner NEVER visits the actual URL**

  - All analysis is performed on URL strings only
  - No HTTP requests are made to suspicious domains
  - Safe to scan even the most dangerous phishing links

### Data Privacy

  - URLs are sent to:
      - VirusTotal (for reputation checking)
      - OpenAI/Google (for AI analysis)
  - Consider privacy implications for sensitive internal URLs
  - Do NOT scan confidential or private URLs

### API Key Security

⚠️ **NEVER commit `.env` to version control**

Add to `.gitignore`:

```text
.env
*.pyc
__pycache__/
venv/
```

-----

## 🤝 Contributing

Contributions welcome\! Please follow these steps:

1.  Fork the repository
2.  Create feature branch (`git checkout -b feature/AmazingFeature`)
3.  Commit changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to branch (`git push origin feature/AmazingFeature`)
5.  Open Pull Request

-----

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

-----

## 🙏 Acknowledgments

  - **VirusTotal** for providing free URL reputation API
  - **OpenAI** for GPT-4 AI capabilities
  - **Google** for Gemini AI alternative
  - Research papers on phishing detection methodologies

-----

## 📞 Support

For issues, questions, or suggestions:

  - 🐛 **Report bugs**: [GitHub Issues](https://www.google.com/search?q=https://github.com/Ak-cybe/AI-Phishing-Link-Scanner/issues)
  - 💬 **Discussions**: [GitHub Discussions](https://www.google.com/search?q=https://github.com/Ak-cybe/AI-Phishing-Link-Scanner/discussions)


-----

Made with ❤️ for cybersecurity awareness

```
