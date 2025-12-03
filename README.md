# 🛡️ OWASP Top 10 Automated Security Scanner

![OWASP Security Scanner](https://img.shields.io/badge/OWASP-Top%2010%20Scanner-blue)
![OWASP 2025](https://img.shields.io/badge/OWASP-2025%20Ready-brightgreen)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-gold)
![Python 3.7+](https://img.shields.io/badge/Python-3.7%2B-green)
![Version](https://img.shields.io/badge/Version-3.0-orange)
![License](https://img.shields.io/badge/License-Open%20Source-yellow)

A **comprehensive, production-ready web application security scanner** supporting **OWASP Top 10:2025** (latest) and OWASP Top 10:2021. This professional-grade tool identifies critical security vulnerabilities in web applications with detailed reporting and remediation guidance.

---

## 🚀 Quick Start (5 Minutes)

```bash
# 1. Clone the repository
git clone https://github.com/anubhavmohandas/owasp_scanner.git
cd owasp_scanner

# 2. Install dependencies
pip3 install -r requirements.txt

# 3. Run your first scan (OWASP 2025)
python3 scanner2025.py https://example.com

# 4. View the generated HTML report
# Report saved as: scan_report_example.com_YYYYMMDD_HHMMSS.html
```

---

## 📋 Table of Contents

- [Features](#-key-features)
- [OWASP Coverage](#-owasp-top-10-coverage)
- [Installation](#-installation)
- [Usage](#-usage)
- [What This Scanner Actually Does](#-what-this-scanner-actually-does)
- [Limitations](#%EF%B8%8F-important-limitations)
- [Bug Bounty Mode](#-bug-bounty-hunter-mode)
- [Command Reference](#-command-line-options)
- [CI/CD Integration](#-cicd-integration)
- [Contributing](#-contributing)
- [Legal & Ethics](#-security--legal)

---

## ✨ Key Features

### 🎯 Comprehensive Vulnerability Detection

**OWASP Top 10:2025 (Latest)**
- ✅ **A01** - Broken Access Control (IDOR, forced browsing, privilege escalation)
- ✅ **A02** - Security Misconfiguration (headers, exposed files, directory listing)
- ✅ **A03** - Software Supply Chain Failures (exposed manifests, missing SRI, vulnerable libraries)
- ✅ **A04** - Cryptographic Failures (HTTPS issues, weak SSL/TLS, insecure cookies)
- ✅ **A05** - Injection (SQL, NoSQL, Command, XSS detection)
- ✅ **A06** - Insecure Design (rate limiting, CAPTCHA, business logic flaws)
- ✅ **A07** - Authentication Failures (weak passwords, missing MFA, session issues)
- ✅ **A08** - Software/Data Integrity Failures (deserialization, missing integrity checks)
- ✅ **A09** - Logging & Alerting Failures (verbose errors, missing monitoring)
- ✅ **A10** - Mishandling of Exceptional Conditions (stack traces, error disclosure)

**OWASP Top 10:2021 (Legacy Support)**
- Full backward compatibility with 2021 categories
- Includes SSRF (Server-Side Request Forgery) detection

### 📊 Professional Reporting

- **HTML Reports** - Beautiful, interactive web-based reports with color-coded severity
- **JSON Reports** - Machine-readable for CI/CD integration and automation
- **Text Reports** - Plain text for quick review and terminal display
- **CVSS-like Scoring** - Prioritized vulnerabilities with risk assessment
- **Remediation Guidance** - Specific fix recommendations for each finding

### 🚀 Advanced Capabilities

- ⚡ **Real-time Progress Tracking** - See scan progress with status updates
- 🔍 **Deep Vulnerability Analysis** - Detailed findings with evidence and context
- 🧵 **Parallel Scanning** - Multi-threaded for optimal performance
- 🌐 **Subdomain Discovery** - Automatic subdomain enumeration and scanning
- 🔧 **Modular Architecture** - Easy to extend and customize
- 💰 **Bug Bounty Mode** - Automated reconnaissance and ready-to-submit reports

---

## 📊 OWASP Top 10:2025 Coverage

| # | Vulnerability Category | Status | Key Detections |
|---|------------------------|--------|----------------|
| **A01** | Broken Access Control | ✅ Full | IDOR, forced browsing, exposed admin panels, auth bypass |
| **A02** | Security Misconfiguration | ✅ Full | Missing headers, directory listing, exposed files (.env, .git) |
| **A03** | Software Supply Chain Failures | ✅ Full | Exposed manifests, missing SRI, vulnerable libraries, CDN risks |
| **A04** | Cryptographic Failures | ✅ Full | HTTP usage, weak TLS, mixed content, insecure cookies |
| **A05** | Injection | ✅ Full | SQL injection (error-based), XSS indicators, command injection |
| **A06** | Insecure Design | ✅ Full | Missing rate limiting, CAPTCHA, price manipulation, business logic |
| **A07** | Authentication Failures | ✅ Full | Weak passwords, missing MFA, account lockout, session fixation |
| **A08** | Software/Data Integrity Failures | ✅ Full | Insecure deserialization, missing SRI, JWT issues, ViewState |
| **A09** | Logging & Alerting Failures | ✅ Full | Verbose errors, exposed logs, debug mode, missing monitoring |
| **A10** | Exceptional Conditions | ✅ Full | Stack traces, framework errors, path disclosure, error handling |

### 🆕 What's New in OWASP 2025?

- **A03:2025** - Software Supply Chain Failures (NEW)
- **A10:2025** - Mishandling of Exceptional Conditions (NEW)
- **A02:2025** - Security Misconfiguration moved to #2 (increased priority)
- Updated risk prioritization based on real-world threat landscape

---

## 🔧 Installation

### Prerequisites

- **Python 3.7+** (Python 3.8+ recommended)
- **pip3** (Python package manager)
- **Internet connection** (for scanning and updates)
- **Optional**: Go 1.16+ (for enhanced subdomain discovery)

### Method 1: Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/anubhavmohandas/owasp_scanner.git
cd owasp_scanner

# Run the automatic installer
chmod +x install.sh
./install.sh

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Method 2: Manual Installation

```bash
# Clone the repository
git clone https://github.com/anubhavmohandas/owasp_scanner.git
cd owasp_scanner

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 scanner2025.py --help
```

### Method 3: Docker Installation (Coming Soon)

```bash
docker pull anubhavmohandas/owasp_scanner:latest
docker run -v $(pwd)/reports:/reports owasp_scanner https://example.com
```

---

## 💻 Usage

### Basic Scans

#### 1. Scan with OWASP 2025 (Recommended)

```bash
# Basic scan
python3 scanner2025.py https://example.com

# Generate HTML report (default)
python3 scanner2025.py https://example.com -o my_report.html

# Verbose mode (see detailed scan progress)
python3 scanner2025.py https://example.com -v
```

#### 2. Scan with OWASP 2021 (Legacy)

```bash
# Basic scan with 2021 categories
python3 scanner.py https://example.com

# Include SSRF detection (2021-specific)
python3 scanner.py https://example.com -v
```

### Advanced Scans

#### Multiple Report Formats

```bash
# Generate all formats (HTML, JSON, Text)
python3 scanner2025.py https://example.com --all-formats

# JSON output for CI/CD
python3 scanner2025.py https://example.com -f json -o results.json

# Text output for quick review
python3 scanner2025.py https://example.com -f text -o report.txt
```

#### Subdomain Scanning

```bash
# Discover and scan subdomains
python3 scanner2025.py https://example.com -s

# Limit subdomain count
python3 scanner2025.py https://example.com -s --max-subdomains 20

# Faster scanning with more threads
python3 scanner2025.py https://example.com -s -t 10
```

#### Performance Tuning

```bash
# Use more threads (faster but more aggressive)
python3 scanner2025.py https://example.com -t 10

# Reduce threads (slower but gentler)
python3 scanner2025.py https://example.com -t 2

# Silent mode (no banner, minimal output)
python3 scanner2025.py https://example.com --no-banner
```

---

## 🎯 What This Scanner Actually Does

### ✅ **REAL Vulnerabilities It WILL Find:**

1. **Exposed Sensitive Files**
   - `.env` files with credentials
   - `.git` directories
   - `package.json`, `composer.json`, `requirements.txt`
   - Configuration files (`web.config`, `config.php`)
   - Backup files (`.bak`, `.old`)

2. **Security Misconfigurations**
   - Missing security headers (HSTS, CSP, X-Frame-Options)
   - Directory listing enabled
   - Server version disclosure
   - Debug mode enabled in production
   - Default error pages

3. **Cryptographic Issues**
   - HTTP instead of HTTPS
   - Outdated SSL/TLS protocols (TLS 1.0, TLS 1.1)
   - Mixed content (HTTP resources on HTTPS pages)
   - Cookies without Secure/HttpOnly/SameSite flags

4. **Supply Chain Vulnerabilities**
   - Exposed package manifests
   - Missing Subresource Integrity (SRI) on CDN resources
   - Vulnerable/outdated JavaScript libraries (jQuery 1.x, AngularJS)
   - Insecure CDN usage

5. **Authentication Issues**
   - Session tokens in URLs
   - Missing account lockout mechanisms
   - No MFA/2FA indicators
   - Weak session management

6. **Information Disclosure**
   - Stack traces exposed to users
   - Database error messages
   - Framework-specific errors (Django, Laravel, ASP.NET)
   - File paths and internal IPs disclosed

7. **Access Control Issues**
   - Accessible admin panels without authentication
   - IDOR (Insecure Direct Object Reference) indicators
   - Dangerous HTTP methods enabled (PUT, DELETE)

8. **Design Flaws**
   - Missing rate limiting
   - No CAPTCHA on sensitive forms
   - Price values in hidden form fields
   - GET requests on state-changing operations

---

## ⚠️ Important Limitations

### What This Scanner CANNOT Do:

❌ **Complex Exploitation** - Only detects indicators, doesn't exploit vulnerabilities
❌ **Authenticated Scanning** - Cannot test areas requiring login (without credentials)
❌ **Deep Logic Flaws** - Cannot find complex business logic vulnerabilities
❌ **Zero-Day Discovery** - Not designed for finding unknown vulnerabilities
❌ **WAF Bypass** - May be blocked by Web Application Firewalls
❌ **JavaScript Execution** - No browser rendering or JavaScript analysis

### False Positives

The scanner uses **pattern matching and heuristics**, which may produce false positives:
- ✅ **Always verify findings manually**
- ✅ **Check context before reporting**
- ✅ **Use as a starting point, not final proof**

### Ethical Use Only

⚠️ **Legal Warning:** Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal and unethical.

---

## 💰 Bug Bounty Hunter Mode

### Features

- 🔍 **Automated Reconnaissance** - Technology detection, endpoint discovery
- 📂 **Directory Enumeration** - Dirbuster-style path discovery
- 🛡️ **OWASP Top 10:2025** - Complete vulnerability scanning
- 💰 **Bounty Estimation** - CVSS scoring aligned with program tiers
- 📊 **Professional Reports** - Ready-to-submit to Intigriti, HackerOne, BugCrowd

### Quick Start

```bash
# Full bug bounty scan
python3 bounty_hunter.py https://target.com --full --bounty-report

# Reconnaissance only
python3 bounty_hunter.py https://target.com --recon

# Directory enumeration
python3 bounty_hunter.py https://target.com --enum

# OWASP scan only
python3 bounty_hunter.py https://target.com --owasp

# Parse bug bounty program scope
python3 program_parser.py --file program.txt --output scope.json
```

### Sample Output

```
🎯 Bug Bounty Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL [Estimated: $500-$1,500]
   [SQL Injection] Database error exposed at /api/users?id=1'
   CVSS: 9.8 | Tier: P1

🟠 HIGH [Estimated: $200-$800]
   [Exposed .env file] Credentials at https://target.com/.env
   CVSS: 8.2 | Tier: P2

📊 Summary: 2 Critical, 5 High, 8 Medium, 3 Low
💰 Estimated Bounty Range: $1,200 - $3,500
```

[📖 Complete Bug Bounty Guide](BUG_BOUNTY_GUIDE.md)

---

## 📖 Command Line Options

### OWASP 2025 Scanner (`scanner2025.py`)

```
usage: scanner2025.py [-h] [-o OUTPUT] [-f {html,json,text}] [-s]
                     [-m MAX_SUBDOMAINS] [-t THREADS] [--all-formats]
                     [-v] [--no-banner] url

positional arguments:
  url                   Target URL to scan (e.g., https://example.com)

optional arguments:
  -h, --help            Show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file for the report (default: auto-generated)
  -f {html,json,text}, --format {html,json,text}
                        Report format (default: html)
  -s, --subdomains      Discover and scan subdomains
  -m MAX_SUBDOMAINS, --max-subdomains MAX_SUBDOMAINS
                        Maximum number of subdomains to scan (default: 50)
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 5)
  --all-formats         Generate reports in all formats (HTML, JSON, Text)
  -v, --verbose         Enable verbose output (detailed scan progress)
  --no-banner           Disable ASCII banner display
```

### Bug Bounty Hunter (`bounty_hunter.py`)

```
usage: bounty_hunter.py [-h] [--full] [--recon] [--enum] [--owasp]
                       [--bounty-report] [--program PROGRAM]
                       [-o OUTPUT] [-v] url

positional arguments:
  url                   Target URL to scan

optional arguments:
  -h, --help            Show this help message and exit
  --full                Full scan (recon + enum + OWASP)
  --recon               Reconnaissance only
  --enum                Directory enumeration only
  --owasp               OWASP vulnerability scan only
  --bounty-report       Generate bug bounty report with CVSS + estimates
  --program PROGRAM     Bug bounty program name
  -o OUTPUT, --output OUTPUT
                        Output file for report
  -v, --verbose         Enable verbose output
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: |
          cd owasp_scanner
          pip install -r requirements.txt

      - name: Run OWASP 2025 security scan
        run: |
          cd owasp_scanner
          python3 scanner2025.py ${{ secrets.TARGET_URL }} \
            --format json -o scan-results.json

      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: security-scan-results
          path: owasp_scanner/scan-results.json

      - name: Fail on critical issues
        run: |
          cd owasp_scanner
          python3 -c "
          import json
          with open('scan-results.json') as f:
              data = json.load(f)
              if data.get('critical_count', 0) > 0:
                  exit(1)
          "
```

### GitLab CI

```yaml
security_scan:
  image: python:3.9
  script:
    - cd owasp_scanner
    - pip install -r requirements.txt
    - python3 scanner2025.py https://staging.example.com \
        --format json -o results.json
  artifacts:
    paths:
      - owasp_scanner/results.json
    expire_in: 1 week
  only:
    - schedules
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    cd owasp_scanner
                    pip3 install -r requirements.txt
                    python3 scanner2025.py ${TARGET_URL} \
                        --format json -o results.json
                '''
            }
        }

        stage('Publish Results') {
            steps {
                archiveArtifacts artifacts: 'owasp_scanner/results.json'
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'owasp_scanner',
                    reportFiles: 'scan_report_*.html',
                    reportName: 'Security Scan Report'
                ])
            }
        }
    }
}
```

---

## 📊 Sample Report Output

### Console Output

```
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ███╗   ██╗██╗    ██╗ █████╗ ███████╗██████╗                       ║
║   ████╗  ██║██║    ██║██╔══██╗██╔════╝██╔══██╗                      ║
║   ██╔██╗ ██║██║ █╗ ██║███████║███████╗██████╔╝                      ║
║   ██║╚██╗██║██║███╗██║██╔══██║╚════██║██╔═══╝                       ║
║   ██║ ╚████║╚███╔███╔╝██║  ██║███████║██║                           ║
║   ╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝                           ║
║                                                                      ║
║         ⚡ AUTOMATED SECURITY SCANNER v3.0 ⚡                        ║
║         🛡️  OWASP Top 10:2025 Vulnerability Detection              ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

======================================================================
🎯 Target: https://example.com
🔍 Subdomain Discovery: Disabled
🧵 Threads: 5
📊 Report Format: HTML
======================================================================

🚀 Starting comprehensive OWASP Top 10:2025 security scan...

[████████████████████████████████████████] 100.0% | Scanning complete...

✅ Scan completed in 45.23 seconds!

📝 Generating reports...
✅ Report saved: scan_report_example.com_20251203_142530.html

======================================================================
📊 SCAN SUMMARY
======================================================================
🔴 Critical Issues: 2
🟠 High Issues: 5
🟡 Medium Issues: 8
🟢 Low Issues: 3
======================================================================
```

### HTML Report Preview

The HTML report includes:
- **Executive Summary** with risk breakdown
- **Color-coded vulnerability cards** (Critical = Red, High = Orange, Medium = Yellow, Low = Green)
- **Detailed findings** for each OWASP category
- **CVSS-like vulnerability scoring** and prioritization
- **Specific evidence** (URLs, headers, error messages)
- **Remediation recommendations** with code examples
- **Professional design** suitable for client presentations

---

## 🏗️ Project Architecture

### Directory Structure

```
owasp_scanner/
├── scanner2025.py              # Main OWASP 2025 scanner (USE THIS)
├── scanner.py                  # OWASP 2021 scanner (legacy)
├── owasp_scanner.py           # Core scanning engine
├── bounty_hunter.py           # Bug bounty hunting tool
├── program_parser.py          # Parse bounty program scope
├── modules/                   # Individual vulnerability scanners
│   ├── __init__.py
│   ├── broken_access_control.py
│   ├── security_misconfiguration.py
│   ├── supply_chain_failures.py        # NEW in 2025
│   ├── cryptographic_failures.py
│   ├── injection.py
│   ├── insecure_design.py
│   ├── authentication_failures.py
│   ├── data_integrity_failures.py
│   ├── logging_monitoring_failures.py
│   └── exceptional_conditions.py        # NEW in 2025
├── requirements.txt           # Python dependencies
├── install.sh                # Automated installer
├── README.md                 # This file
├── OWASP_ATTACKS_EXPLAINED.md # Educational guide
├── OWASP_2025.md             # OWASP 2025 changes
├── BUG_BOUNTY_GUIDE.md       # Bug bounty documentation
└── examples/                 # Usage examples
    ├── generic_program.txt
    └── scan_example.sh
```

### Modular Design Benefits

- ✅ **Easy to Extend** - Add new vulnerability checks
- ✅ **Independent Updates** - Update modules without breaking others
- ✅ **Customizable** - Enable/disable specific checks
- ✅ **Maintainable** - Clear separation of concerns
- ✅ **Testable** - Each module can be tested independently

---

## 🛠️ Troubleshooting

### Common Issues and Solutions

#### Issue: `ModuleNotFoundError: No module named 'requests'`

**Solution:**
```bash
pip3 install -r requirements.txt

# If that fails, install individually:
pip3 install requests beautifulsoup4 colorama tqdm
```

#### Issue: `Permission denied: ./scanner2025.py`

**Solution:**
```bash
chmod +x scanner2025.py
# Or run with python3 directly:
python3 scanner2025.py https://example.com
```

#### Issue: SSL Certificate Errors

**Solution:**
```bash
# The scanner handles SSL automatically
# If DNS issues occur:
nslookup example.com

# Try with explicit HTTPS:
python3 scanner2025.py https://example.com
```

#### Issue: Connection Timeouts

**Solution:**
```bash
# Reduce thread count to be less aggressive:
python3 scanner2025.py https://example.com -t 2

# Check if site is accessible:
curl -I https://example.com
```

#### Issue: No Vulnerabilities Found

**Possible reasons:**
- ✅ **Good news!** Site might be well-configured
- 🔍 Try verbose mode: `python3 scanner2025.py https://example.com -v`
- 🌐 Scanner can only test public endpoints (no authentication)
- 🛡️ Site might have WAF (Web Application Firewall) blocking scans
- 📋 Check generated report for "Low" severity findings

---

## 🤝 Contributing

We welcome contributions! Here's how to contribute:

### How to Contribute

1. **Fork the repository**
   ```bash
   git clone https://github.com/anubhavmohandas/owasp_scanner.git
   cd owasp_scanner
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/AmazingFeature
   ```

3. **Make your changes**
   - Add new vulnerability checks
   - Improve detection accuracy
   - Fix bugs
   - Enhance documentation

4. **Test your changes**
   ```bash
   python3 scanner2025.py https://testsite.com -v
   ```

5. **Commit with clear messages**
   ```bash
   git commit -m 'feat: Add XYZ vulnerability detection'
   ```

6. **Push and create Pull Request**
   ```bash
   git push origin feature/AmazingFeature
   ```

### Development Guidelines

- ✅ Follow PEP 8 style guide
- ✅ Add comments for complex logic
- ✅ Include detection examples
- ✅ Update documentation
- ✅ Test against multiple targets
- ✅ Avoid false positives

### Ideas for Contributions

- 🆕 Add new vulnerability checks
- 🎯 Improve detection accuracy
- 📊 Enhance report formatting
- 🌐 Add multi-language support
- 🔧 Create additional integrations
- 📚 Improve documentation

---

## 🔒 Security & Legal

### ⚠️ IMPORTANT DISCLAIMER

This tool is designed for **AUTHORIZED SECURITY TESTING ONLY**:

✅ **Legal Uses:**
- Your own systems and applications
- Client systems with written authorization
- Bug bounty programs (within scope)
- Educational and research purposes
- Penetration testing engagements
- Security audits with permission

❌ **Illegal Uses:**
- Scanning systems without permission
- Unauthorized vulnerability testing
- Violating terms of service
- Exceeding authorized scope
- Malicious intent

### Legal Warning

**Unauthorized scanning is illegal under laws including:**
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in most countries

**You could face:**
- Criminal charges
- Lawsuits and damages
- Fines and penalties
- Imprisonment

### Ethical Use Best Practices

1. ✅ **Always get written authorization** before scanning
2. ✅ **Stay within authorized scope** defined in agreements
3. ✅ **Start with low thread counts** to avoid DoS
4. ✅ **Review results manually** for false positives
5. ✅ **Store reports securely** - they contain sensitive data
6. ✅ **Report responsibly** - follow disclosure policies
7. ✅ **Respect rate limits** and robots.txt
8. ✅ **Document your testing** - timestamp and scope

### Responsible Disclosure

If you find vulnerabilities using this tool:
- 📧 Report to the organization's security team
- ⏰ Give reasonable time to fix (typically 90 days)
- 🤝 Coordinate disclosure timing
- 📝 Provide clear reproduction steps
- 💰 Follow bug bounty program rules

---

## 📚 Documentation

- [📖 OWASP Attacks Explained](OWASP_ATTACKS_EXPLAINED.md) - Educational guide for students
- [🆕 OWASP 2025 Changes](OWASP_2025.md) - What's new in 2025
- [💰 Bug Bounty Guide](BUG_BOUNTY_GUIDE.md) - Complete bounty hunting guide
- [🚀 Quick Start Guide](QUICK_START.md) - Get started in 5 minutes
- [🔧 API Documentation](docs/API.md) - For developers extending the scanner

---

## 🔄 Changelog

### Version 3.0 (Current - OWASP 2025)
- ✨ Full OWASP Top 10:2025 support
- ✨ New Supply Chain Failures scanner
- ✨ New Exceptional Conditions scanner
- ✨ Enhanced reporting with CVSS scoring
- ✨ Bug bounty hunting mode
- ✨ Improved vulnerability detection accuracy
- ✨ Better false positive reduction

### Version 2.0 (OWASP 2021)
- ✨ Complete OWASP Top 10:2021 coverage
- ✨ HTML/JSON/Text reporting
- ✨ Subdomain discovery
- ✨ Modular architecture
- ✨ Progress tracking

### Version 1.0 (Initial Release)
- Basic OWASP scanning
- Command-line interface
- Simple text output

---

## 📞 Support & Contact

### Getting Help

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/anubhavmohandas/owasp_scanner/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/anubhavmohandas/owasp_scanner/discussions)
- 📧 **Email**: security@anubhavmohandas.com
- 📖 **Documentation**: Check the `docs/` folder

### Community

- ⭐ Star this repository if you find it helpful!
- 🍴 Fork and contribute
- 📢 Share with security community
- 💬 Join discussions

---

## 🌟 Acknowledgments

- **OWASP Foundation** for security guidelines and research
- **Security researchers** and contributors worldwide
- **Open source community** for libraries and tools
- **Bug bounty hunters** for feedback and suggestions

### Built With

- [Python](https://www.python.org/) - Core language
- [Requests](https://requests.readthedocs.io/) - HTTP library
- [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing
- [Colorama](https://pypi.org/project/colorama/) - Terminal colors
- [TQDM](https://github.com/tqdm/tqdm) - Progress bars

---

## 📜 License

This project is open source and available for educational and authorized security testing purposes.

**License**: MIT License (See LICENSE file)

**Attribution**: If you use this tool in your research or publications, please cite:
```
Anubhav Mohandas (2024). OWASP Top 10 Automated Security Scanner.
https://github.com/anubhavmohandas/owasp_scanner
```

---

<div align="center">

**Made with ❤️ by [Anubhav Mohandas](https://github.com/anubhavmohandas)**

⭐ **Star this repository if you find it helpful!** ⭐

[Report Bug](https://github.com/anubhavmohandas/owasp_scanner/issues) ·
[Request Feature](https://github.com/anubhavmohandas/owasp_scanner/issues) ·
[Documentation](docs/)

---

### 🚨 Remember: With great power comes great responsibility 🚨

**Only scan systems you own or have explicit permission to test.**

</div>

---

## 📈 Statistics

- **Lines of Code**: 5,000+
- **Vulnerability Checks**: 150+
- **OWASP Categories**: 10 (2025) + 10 (2021)
- **Report Formats**: 3 (HTML, JSON, Text)
- **Active Contributors**: Growing community

---

## 🎯 Roadmap

### Planned Features

- [ ] **GUI Interface** - Web-based dashboard
- [ ] **Docker Support** - Containerized deployment
- [ ] **API Endpoints** - RESTful API for integration
- [ ] **Database Support** - Store scan history
- [ ] **Scheduled Scans** - Automated periodic scanning
- [ ] **Email Alerts** - Notification on critical findings
- [ ] **Custom Plugins** - User-defined vulnerability checks
- [ ] **Authenticated Scanning** - Login and scan protected areas
- [ ] **OWASP ASVS** - Application Security Verification Standard
- [ ] **CWE Mapping** - Common Weakness Enumeration

### Future Enhancements

- 🌐 Multi-language support (Spanish, French, German, Chinese)
- 📱 Mobile app for iOS/Android
- 🔌 Browser extension
- 🤖 AI-powered vulnerability detection
- 📊 Advanced analytics and trends
- 🔗 Integration with SIEM tools

---

**Last Updated**: 2025-12-03
**Version**: 3.0
**OWASP Version**: 2025

