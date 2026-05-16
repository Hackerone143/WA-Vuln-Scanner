# AutoVulnX

**Automated OWASP Top 10 Vulnerability Scanner — Python 3.12+**

AutoVulnX is a lightweight and modular Python-based web vulnerability scanner designed for security learners, bug bounty hunters, and portfolio projects.

It automatically crawls a target website and detects common vulnerabilities from the OWASP Top 10.

---

## ⚠️ Legal Disclaimer

This tool is intended **only for authorised security testing and educational purposes**.

Do not scan systems without proper permission. The developer is not responsible for misuse.

Only test:

* Targets you own
* Labs
* Bug bounty / VDP programs that explicitly allow scanning

---

# Features

* Web crawler
* Reflected XSS detection
* SQL Injection detection
* Open Redirect detection
* Security headers analysis
* Sensitive file discovery
* CSRF checks
* HTML & JSON reports
* Burp Suite proxy support
* Lightweight and low-resource friendly

---

# Supported Vulnerability Modules

| Module          | Description                                       |
| --------------- | ------------------------------------------------- |
| Headers         | Missing security headers & information disclosure |
| XSS             | Reflected XSS detection                           |
| SQLi            | Error-based & time-based SQL injection            |
| Open Redirect   | Redirect parameter testing                        |
| Sensitive Files | `.env`, `.git`, backups, debug endpoints          |
| CSRF            | Missing CSRF token detection                      |

---

# Requirements

* Python 3.12+
* Windows / Kali Linux / Ubuntu
* Internet connection

Check Python version:

```bash
python --version
```

---

# Installation

## Windows / Linux / Kali

Clone the repository:

```bash
git clone https://github.com/yourusername/AutoVulnX.git
cd AutoVulnX
```

Create virtual environment:

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / Kali

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run help menu:

```bash
python main.py --help
```

---

# Usage

Basic scan:

```bash
python main.py -u https://example.com
```

Run specific modules:

```bash
python main.py -u https://example.com --xss --sqli
```

Generate reports:

```bash
python main.py -u https://example.com --report html json
```

Use with Burp Suite:

```bash
python main.py -u https://example.com --proxy http://127.0.0.1:8080 --no-verify
```

---

# Project Structure

```text
AutoVulnX/
│
├── core/
├── modules/
├── payloads/
├── reports/
├── utils/
├── main.py
├── requirements.txt
└── README.md
```

---

# Output

AutoVulnX supports:

* Terminal output
* HTML reports
* JSON reports

Reports are saved inside:

```text
reports/
```

---

# Current Limitations

* No authenticated scanning
* No JavaScript rendering
* No DOM XSS detection
* No WAF bypass
* No internal/private IP scanning

---

# Roadmap

* Async scanning
* SSRF module
* JWT analysis
* GraphQL testing
* WAF detection
* PDF reports
* Subdomain enumeration

---

# Dependencies

* requests
* httpx
* beautifulsoup4
* lxml
* rich

Install manually:

```bash
pip install -r requirements.txt
```

---

# Tools & Inspiration

Inspired by:

* [OWASP ZAP](https://www.zaproxy.org?utm_source=chatgpt.com)
* [sqlmap](https://sqlmap.org?utm_source=chatgpt.com)
* [Dalfox](https://github.com/hahwul/dalfox?utm_source=chatgpt.com)
* [Nuclei](https://github.com/projectdiscovery/nuclei?utm_source=chatgpt.com)

---


Developed for learning, research, and authorised security testing.

**AutoVulnX — Lightweight OWASP Vulnerability Scanner**
