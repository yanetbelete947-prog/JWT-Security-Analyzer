
# 🔐 JWT Security Analyzer

A Python-based defensive security tool for analyzing **JSON Web Tokens (JWTs)**.

JWT Security Analyzer inspects a JWT's structure, header, payload, claims, timestamps, signing algorithm, and optional cryptographic signature. It identifies potentially risky configurations and generates a security score and detailed reports.

> **For educational and authorized security testing only.**

---

## ✨ Features

* 🔎 JWT structure validation
* 🔓 Base64URL header and payload decoding
* 🧩 JWT header analysis
* 🔐 Signing algorithm analysis
* ⏰ `exp` expiration analysis
* 🕐 `iat` issued-at analysis
* ⏳ `nbf` not-before analysis
* 🎯 `aud` audience analysis
* 🏢 `iss` issuer analysis
* 🔑 Optional cryptographic signature verification
* ⚠️ Sensitive claim detection
* 📊 Security risk scoring
* 🖥️ Rich terminal interface
* 📄 JSON report generation
* 🌐 HTML report generation
* 🐍 Written entirely in Python

---

## 🛠️ Technologies

* Python 3
* PyJWT
* Cryptography
* Rich
* JSON
* HTML/CSS

---

## 📁 Project Structure

```text
jwt-security-analyzer/
│
├── jwt_analyzer.py
├── requirements.txt
├── README.md

```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/beleteyanet704-prog/jwt-security-analyzer.git
cd jwt-security-analyzer
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it:

### Linux/macOS

```bash
source venv/bin/activate
```

### Windows

```powershell
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### Analyze a JWT directly

```bash
python3 jwt_analyzer.py "YOUR_JWT_HERE"
```

### Analyze a JWT stored in a file

```bash
python3 jwt_analyzer.py token.txt
```

---

## 📊 Example Output

```text
╔══════════════════════════════════╗
║       JWT SECURITY ANALYZER      ║
╚══════════════════════════════════╝

Token Information

Algorithm : HS256
Type      : JWT
Score     : 87/100
Risk      : MEDIUM


Claims

Claim     Value
────────────────────────────
sub       12345
role      user
iat       2026-10-04 14:20 UTC
exp       2026-10-04 15:20 UTC


Security Findings

Severity   Finding
────────────────────────────────────
LOW        Missing audience
LOW        Missing issuer
```

---

## 🔐 Signature Verification

The analyzer can optionally verify a JWT signature using a key you provide.

For example:

```bash
python3 jwt_analyzer.py token.txt --key public.pem
```

The tool will report whether the supplied key successfully verifies the token's signature.

### HMAC

For HMAC-signed tokens such as HS256, provide the appropriate secret:

```bash
python3 jwt_analyzer.py token.txt --key secret.txt
```

### RSA / EC

For asymmetric algorithms such as RS256 or ES256, provide the appropriate public key:

```bash
python3 jwt_analyzer.py token.txt --key public.pem
```

Only use keys and tokens that you are authorized to test.

---

## 📄 JSON Reports

Generate a machine-readable report:

```bash
python3 jwt_analyzer.py token.txt --json report.json
```

Example:

```json
{
    "algorithm": "HS256",
    "score": 87,
    "risk": "MEDIUM",
    "findings": [
        {
            "severity": "LOW",
            "title": "Missing audience",
            "description": "The token does not contain an aud claim."
        }
    ]
}
```

---

## 🌐 HTML Reports

Generate a browser-readable security report:

```bash
python3 jwt_analyzer.py token.txt --html report.html
```

Then open:

```text
report.html
```

in your browser.

The report contains:

* Token information
* Algorithm
* Claims
* Security findings
* Risk score
* Descriptions of detected issues

---

## 🧪 Security Checks

The analyzer currently checks several JWT properties.

### Algorithm

Checks whether:

* An algorithm is present
* The algorithm is recognized
* The token uses the `none` algorithm

### Expiration

Checks:

* Missing `exp`
* Invalid expiration timestamps
* Expired tokens
* Excessively long token lifetimes

### Issued At

Checks:

* Invalid `iat`
* `iat` values in the future

### Not Before

Checks:

* Invalid `nbf` values

### Audience

Checks whether the JWT contains an `aud` claim.

### Issuer

Checks whether the JWT contains an `iss` claim.

### Sensitive Claims

Looks for potentially sensitive claim names such as:

```text
password
secret
api_key
access_token
refresh_token
private_key
```

---

## 📊 Risk Scoring

The analyzer starts with a score of **100**.

Detected findings reduce the score according to severity.

| Severity | Example deduction |
| -------- | ----------------: |
| CRITICAL |               -40 |
| HIGH     |               -20 |
| MEDIUM   |               -10 |
| LOW      |                -3 |

The final score is categorized as:

```text
90-100  → LOW
70-89   → MEDIUM
40-69   → HIGH
0-39    → CRITICAL
```

The score is an **informational assessment**, not a replacement for a professional security review.

---

## ⚠️ Important Security Notes

JWTs often contain sensitive information.

This tool is designed to analyze tokens **locally**.

It does not require sending JWTs to an external server.

Do not paste production credentials or authentication tokens into third-party JWT tools.

Only analyze tokens that you own or are explicitly authorized to test.

---

## 🎯 Project Goals

This project was created to explore:

* JWT internals
* Authentication security
* Cryptographic signatures
* Secure API design
* Python development
* Security automation
* CLI application development
* Security reporting

---

## 🔮 Future Improvements

Planned improvements include:

* [ ] React web interface
* [ ] FastAPI backend
* [ ] Interactive security dashboard
* [ ] JWT comparison
* [ ] More comprehensive claim validation
* [ ] Configurable security rules
* [ ] Unit test suite
* [ ] Docker support
* [ ] Export to PDF
* [ ] Custom report templates
* [ ] API mode
* [ ] Improved algorithm/key validation

---

## 🧪 Testing

Run the test suite:

```bash
pytest
```

Future versions will include automated tests covering:

* JWT parsing
* Invalid tokens
* Expired tokens
* Invalid claims
* Algorithm detection
* Signature verification
* Report generation

---

## 📚 Learning Resources

Useful concepts to understand while working on this project:

* JSON Web Tokens
* Base64URL encoding
* HMAC
* RSA
* ECDSA
* Authentication vs authorization
* HTTP authentication
* API security
* Cryptographic signatures

---

## 👨‍💻 Author

Yanet Belete

Cybersecurity & Web Development Student

GitHub: `https://github.com/beleteyanet704-prog`

---

## ⚖️ Disclaimer

This project is intended for **educational purposes, defensive security research, and authorized security testing**.

Do not use this tool to inspect, attack, or manipulate authentication tokens belonging to systems or users without permission.

The author is not responsible for misuse of this software.

---

## ⭐ Contributing

Contributions, bug reports, and feature requests are welcome.

1. Fork the repository
2. Create a feature branch

```bash
git checkout -b feature/my-feature
```

3. Commit your changes

```bash
git commit -m "Add my feature"
```

4. Push the branch

```bash
git push origin feature/my-feature
```

5. Open a Pull Request

---


This project is released under the MIT License.
