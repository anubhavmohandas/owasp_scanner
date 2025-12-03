# 🛡️ OWASP Top 10 Automated Security Scanner

![OWASP Security Scanner](https://img.shields.io/badge/OWASP-Top%2010%20Scanner-blue)
![OWASP 2025](https://img.shields.io/badge/OWASP-2025%20Ready-brightgreen)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-gold)
![Python 3.7+](https://img.shields.io/badge/Python-3.7%2B-green)
![Version](https://img.shields.io/badge/Version-3.0-orange)
![License](https://img.shields.io/badge/License-Open%20Source-yellow)

A **comprehensive, automated web application security scanner** supporting **OWASP Top 10:2025** (latest) and OWASP Top 10:2021. This professional-grade tool helps identify critical security vulnerabilities in web applications with detailed reporting and remediation guidance.

## 🎯 NEW: Bug Bounty Hunter Mode!

**Automated bug bounty hunting platform** that combines OWASP scanning with reconnaissance, directory enumeration, and ready-to-submit vulnerability reports!

```bash
# Full bug bounty scan with automated reporting
python bounty_hunter.py https://target.com --full --bounty-report
```

Features:
- 🔍 **Automated Reconnaissance** - Tech detection, endpoint discovery
- 📂 **Directory Enumeration** - Dirbuster-style path discovery
- 🛡️ **OWASP Top 10:2025** - Complete vulnerability scanning
- 💰 **Bounty Estimation** - CVSS scoring aligned with program tiers
- 📊 **Professional Reports** - Ready-to-submit to Intigriti, HackerOne, etc.

[📖 Bug Bounty Hunter Guide](BUG_BOUNTY_GUIDE.md) | [🎯 Quick Start](#bug-bounty-quick-start)

## 🎉 Now Supporting OWASP Top 10:2025!

✨ **NEW**: Full support for OWASP Top 10:2025 categories including:
- **A03:2025** - Software Supply Chain Failures (NEW)
- **A10:2025** - Mishandling of Exceptional Conditions (NEW)
- Updated prioritization with Security Misconfiguration at #2

[📖 Read about OWASP 2025 Changes](OWASP_2025.md)

## ✨ Key Features

### 🎯 Comprehensive Coverage
- ✅ **Complete OWASP Top 10 2021** vulnerability detection
- ✅ **Automated subdomain discovery** and scanning
- ✅ **Parallel scanning** for optimal performance
- ✅ **Smart vulnerability prioritization** with CVSS-like scoring

### 📊 Professional Reporting
- 📄 **HTML Reports** - Beautiful, interactive web-based reports
- 📋 **JSON Reports** - Machine-readable for CI/CD integration
- 📝 **Text Reports** - Plain text for quick review
- 🎨 **Color-coded severity** levels (Critical, High, Medium, Low)

### 🚀 Advanced Capabilities
- ⚡ **Progress tracking** with real-time status updates
- 🔍 **Deep vulnerability analysis** with detailed findings
- 💡 **Remediation guidance** for each vulnerability
- 🔧 **Modular architecture** for easy extension

## 📋 OWASP Top 10 2021 Coverage

| # | Vulnerability Category | Status |
|---|------------------------|--------|
| A01 | Broken Access Control | ✅ Full |
| A02 | Cryptographic Failures | ✅ Full |
| A03 | Injection | ✅ Full |
| A04 | Insecure Design | ✅ Full |
| A05 | Security Misconfiguration | ✅ Full |
| A06 | Vulnerable and Outdated Components | ✅ Full |
| A07 | Identification and Authentication Failures | ✅ Full |
| A08 | Software and Data Integrity Failures | ✅ Full |
| A09 | Security Logging and Monitoring Failures | ✅ Full |
| A10 | Server-Side Request Forgery (SSRF) | ✅ Full |

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- pip3 (Python package manager)
- Optional: Go 1.16+ (for enhanced subdomain discovery with assetfinder)

### Installation

#### Option 1: Quick Install (Recommended)
```bash
# Clone the repository
git clone https://github.com/anubhavmohandas/owasp_scanner.git
cd owasp_scanner

# Run the automatic installer
chmod +x install.sh
./install.sh
```

#### Option 2: Manual Installation
```bash
# Clone the repository
git clone https://github.com/anubhavmohandas/owasp_scanner.git
cd owasp_scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Make scanners executable
chmod +x scanner.py scanner2025.py
```

### Scanner Selection

**Choose the right scanner for your needs:**

#### OWASP Top 10:2025 (Recommended)
```bash
python scanner2025.py https://example.com
```
- Latest OWASP categories
- Includes Supply Chain Failures detection
- Includes Exception Handling analysis
- Updated priority ordering

#### OWASP Top 10:2021 (Legacy)
```bash
python scanner.py https://example.com
```
- Original 2021 categories
- Includes SSRF detection
- Stable and well-tested

### First Scan
```bash
# Activate virtual environment (if not already activated)
source venv/bin/activate

# Run your first scan with OWASP 2025 (recommended)
python scanner2025.py https://example.com

# Or use OWASP 2021
python scanner.py https://example.com
```

### Bug Bounty Quick Start

```bash
# 1. Parse bug bounty program (e.g., Ubisoft)
python program_parser.py --file examples/ubisoft_program.txt --output program.json

# 2. Run comprehensive bug bounty scan
python bounty_hunter.py https://target.com \
  --full \
  --program "Ubisoft Game Security" \
  --bounty-report \
  -o bounty_report.txt

# 3. Review findings
cat bounty_report.txt

# Report includes:
# - Severity levels mapped to program tiers
# - CVSS scores and bounty estimates
# - Reproduction steps
# - Impact descriptions
# - Ready for submission to Intigriti/HackerOne
```

**Available Modes:**
- `--full` - Complete scan (recon + enum + OWASP)
- `--recon` - Reconnaissance only
- `--enum` - Directory enumeration only
- `--owasp` - OWASP vulnerability scan only

[📖 Complete Bug Bounty Guide](BUG_BOUNTY_GUIDE.md)

## 💻 Usage Examples

### Basic Scan
```bash
python scanner.py https://example.com
```
Performs comprehensive OWASP Top 10 scan and generates HTML report.

### Scan with JSON Output
```bash
python scanner.py https://example.com -o report.json --format json
```
Perfect for CI/CD integration and automated processing.

### Comprehensive Scan with Subdomains
```bash
python scanner.py https://example.com -s --max-subdomains 20 -t 10
```
Discovers and scans up to 20 subdomains using 10 concurrent threads.

### Generate All Report Formats
```bash
python scanner.py https://example.com --all-formats
```
Creates HTML, JSON, and text reports simultaneously.

### Verbose Mode for Debugging
```bash
python scanner.py https://example.com -v
```
Shows detailed debug information during the scan.

## 📖 Command Line Options

```
usage: scanner.py [-h] [-o OUTPUT] [-f {html,json,text}] [-s]
                  [-m MAX_SUBDOMAINS] [-t THREADS] [--all-formats]
                  [-v] [--no-banner] url

OWASP Top 10 Automated Web Vulnerability Scanner

positional arguments:
  url                   Target URL to scan (e.g., https://example.com)

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file for the report
  -f {html,json,text}, --format {html,json,text}
                        Report format (default: html)
  -s, --subdomains      Discover and scan subdomains
  -m MAX_SUBDOMAINS, --max-subdomains MAX_SUBDOMAINS
                        Maximum number of subdomains to scan (default: 50)
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 5)
  --all-formats         Generate reports in all formats
  -v, --verbose         Enable verbose output
  --no-banner           Disable banner display
```

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
║         ⚡ AUTOMATED SECURITY SCANNER v2.0 ⚡                        ║
║         🛡️  OWASP Top 10 2021 Vulnerability Detection               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

======================================================================
🎯 Target: https://example.com
🔍 Subdomain Discovery: Disabled
🧵 Threads: 5
📊 Report Format: HTML
======================================================================

🚀 Starting comprehensive OWASP Top 10 security scan...

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
- Executive summary with risk breakdown
- Color-coded vulnerability cards
- Detailed findings for each OWASP category
- Vulnerability scoring and prioritization
- Specific remediation recommendations
- Beautiful, professional design

## 🏗️ Architecture

### Project Structure
```
owasp_scanner/
├── scanner.py                 # Main enhanced scanner with reporting
├── owasp_scanner.py          # Core OWASP Top 10 scanning engine
├── main.py                   # Modular scanner entry point
├── modules/                  # Individual vulnerability scanners
│   ├── __init__.py
│   ├── broken_access_control.py
│   ├── cryptographic_failures.py
│   ├── injection.py
│   └── security_misconfiguration.py
├── examples/                 # Usage examples
│   └── scan_example.sh
├── requirements.txt          # Python dependencies
├── install.sh               # Automated installation script
├── README.md               # This file
└── USAGE.md               # Detailed usage guide
```

### Modular Design
Each OWASP Top 10 category has its own dedicated scanner module, making it easy to:
- Extend functionality
- Add new vulnerability checks
- Customize for specific needs
- Maintain and update independently

## 🔧 Advanced Usage

### CI/CD Integration

#### GitHub Actions
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
          pip install -r requirements.txt

      - name: Run security scan
        run: |
          python scanner.py ${{ secrets.TARGET_URL }} \
            --format json -o scan-results.json

      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: security-scan-results
          path: scan-results.json
```

#### GitLab CI
```yaml
security_scan:
  image: python:3.9
  script:
    - pip install -r requirements.txt
    - python scanner.py https://staging.example.com \
        --format json -o results.json
  artifacts:
    paths:
      - results.json
    expire_in: 1 week
  only:
    - schedules
```

### Automated Periodic Scanning
```bash
#!/bin/bash
# Add to cron: 0 2 * * * /path/to/weekly-scan.sh

cd /path/to/owasp_scanner
source venv/bin/activate

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
python scanner.py https://production.example.com \
  --all-formats \
  -o "reports/scan_${TIMESTAMP}"

# Email report (optional)
mail -s "Security Scan Report" security@example.com < "reports/scan_${TIMESTAMP}.txt"
```

## 🛠️ Troubleshooting

### Common Issues

#### Issue: Module Not Found
```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

#### Issue: Permission Denied
```bash
# Solution: Make scripts executable
chmod +x scanner.py install.sh
```

#### Issue: SSL Certificate Errors
```bash
# The scanner handles SSL certificates automatically
# Check DNS resolution: nslookup example.com
```

#### Issue: Connection Timeouts
```bash
# Solution: Reduce thread count
python scanner.py https://example.com -t 3
```

## 🔒 Security & Legal

### ⚠️ Important Disclaimer
This tool is designed for:
- ✅ Security professionals assessing their own systems
- ✅ Authorized penetration testing engagements
- ✅ Educational and research purposes
- ✅ Bug bounty programs

**Unauthorized scanning is illegal and unethical.**

### Best Practices
1. **Always get written authorization** before scanning
2. **Start with low thread counts** to avoid DoS conditions
3. **Review automated results** for false positives
4. **Store reports securely** - they may contain sensitive data
5. **Complement with manual testing** for comprehensive assessment

## 🤝 Contributing

We welcome contributions! Here's how:

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add some AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/anubhavmohandas/owasp_scanner.git
cd owasp_scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 📚 Documentation

- [Usage Guide](USAGE.md) - Comprehensive usage documentation
- [Examples](examples/) - Example scripts and use cases
- [API Documentation](docs/API.md) - For developers extending the scanner

## 🔄 Changelog

### Version 2.0 (Current)
- ✨ Complete OWASP Top 10 2021 coverage
- ✨ Enhanced HTML reporting with beautiful UI
- ✨ Vulnerability scoring and prioritization
- ✨ Progress tracking
- ✨ Multiple output formats (HTML, JSON, Text)
- ✨ Improved subdomain discovery
- ✨ Modular architecture

### Version 1.0
- Initial release with basic scanning capabilities

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/anubhavmohandas/owasp_scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/anubhavmohandas/owasp_scanner/discussions)
- **Security**: For security concerns, please email security@anubhavmohandas.com

## 🌟 Acknowledgments

- OWASP Foundation for security guidelines
- Security researchers and contributors
- Open source security community

## 📜 License

This project is open source and available for educational and authorized security testing purposes.

---

<div align="center">

**Made with ❤️ by [Anubhav Mohandas](https://github.com/anubhavmohandas)**

⭐ Star this repository if you find it helpful!

[Report Bug](https://github.com/anubhavmohandas/owasp_scanner/issues) ·
[Request Feature](https://github.com/anubhavmohandas/owasp_scanner/issues) ·
[Documentation](USAGE.md)

</div>
