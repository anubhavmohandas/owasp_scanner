# OWASP Security Scanner

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-blue.svg"/>
  <img src="https://img.shields.io/badge/License-MIT-green.svg"/>
  <img src="https://img.shields.io/badge/OWASP-2021-orange.svg"/>
</div>

## 🛡️ Overview

OWASP Security Scanner is a comprehensive web vulnerability scanner designed to detect and report security issues based on the OWASP Top 10 (2021). This tool helps security professionals and developers identify potential vulnerabilities in web applications through automated scanning.

<p align="center">
  <img width="700" src="/api/placeholder/800/400" alt="OWASP Scanner Banner">
</p>

## ✨ Features

- **OWASP Top 10 Coverage**: Scans for vulnerabilities based on OWASP Top 10 (2021)
- **Subdomain Discovery**: Identifies and scans subdomains of the target
- **Multi-threaded Scanning**: Parallel scanning for improved performance
- **Detailed Reporting**: Comprehensive JSON reports and console summaries
- **Low False Positive Rate**: Designed to minimize false positives through validation checks

## 🔎 Security Checks

The scanner performs comprehensive checks for:

- **Authentication Failures**: Login security, brute force protection, account enumeration
- **Cryptographic Failures**: SSL/TLS issues, insecure cookies, missing security headers
- **Injection Vulnerabilities**: SQL, XSS, and command injection points
- **Insecure Design**: User enumeration, rate limiting, default credentials
- **Security Misconfigurations**: Information leakage, dangerous HTTP methods
- **Vulnerable Components**: Outdated libraries, exposed server information
- **Data Integrity Issues**: Missing CSP, SRI checks, cache poisoning vectors
- **Logging & Monitoring**: Exposed logs, monitoring endpoints, log injection
- **SSRF Vulnerabilities**: URL parameters, form fields, and header-based vectors

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/owasp-security-scanner.git
cd owasp-security-scanner

# Install dependencies
pip install -r requirements.txt

# For subdomain discovery (optional)
go install github.com/tomnomnom/assetfinder@latest
```

### Requirements

- Python 3.7+
- Required Python packages:
  - requests
  - beautifulsoup4
  - dnspython
  - colorama
- Optional: Go and assetfinder (for subdomain discovery)

## 💻 Usage

```bash
python scanner.py https://example.com [-o output.json] [-s] [-t THREADS] [-m MAX_SUBDOMAINS]
```

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| `url` | Target URL to scan |
| `-o, --output` | Output JSON file for detailed results |
| `-s, --subdomains` | Discover and scan subdomains |
| `-m, --max-subdomains` | Maximum number of subdomains to scan (default: 50) |
| `-t, --threads` | Number of concurrent threads (default: 5) |

### Example

```bash
# Basic scan
python scanner.py https://example.com

# Comprehensive scan with subdomain discovery and output file
python scanner.py https://example.com -s -o results.json -t 10 -m 100
```

## 📊 Sample Output

```
===== SCAN SUMMARY =====

Target: https://example.com
-------------------
Risk summary:
- Critical: 1
- High: 3
- Medium: 7
- Low: 12
- Unknown: 2

Top issues:
- Cryptographic Failures: 4 finding(s), Risk: High
- Authentication Failures: 3 finding(s), Risk: High
- Security Misconfiguration: 5 finding(s), Risk: Medium
- Insecure Design: 3 finding(s), Risk: Medium
- Vulnerable Components: 2 finding(s), Risk: Medium

Use the JSON output for full details.
```

## ⚠️ Legal Disclaimer

This tool is provided for educational and ethical security testing purposes only. Always obtain proper authorization before scanning any systems you don't own. Unauthorized scanning may violate laws or terms of service.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- OWASP for their security guidelines and resources
- The security community for techniques and best practices
- Contributors who have helped improve this tool