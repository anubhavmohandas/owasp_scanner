# OWASP Security Scanner

![OWASP Security Scanner](https://img.shields.io/badge/OWASP-Security%20Scanner-blue)
![Python 3.7+](https://img.shields.io/badge/Python-3.7%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

A comprehensive web application security scanner based on OWASP security guidelines. This tool helps identify common security vulnerabilities in web applications.

## 🛡️ Features

- Subdomain discovery
- Common vulnerability scanning
- SSL/TLS configuration checks
- Header security analysis
- Input validation testing
- Output reporting in multiple formats

## 📋 Prerequisites

- Python 3.7 or higher
- pip3 (Python package manager)
- Optional: Go 1.16+ (for enhanced subdomain discovery)

## 🚀 Installation

### Automatic Installation

Use our installation script to set up everything automatically:

```bash
# Download the install script
curl -O https://raw.githubusercontent.com/your-username/owasp-scanner/main/install.sh

# Make it executable
chmod +x install.sh

# Run the installer
./install.sh
```

### Manual Installation

If you prefer manual installation:

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/owasp-scanner.git
   cd owasp-scanner
   ```

2. Create and activate a virtual environment:
   ```bash
   virtualenv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Make the scanner executable:
   ```bash
   chmod +x scanner.py
   ```

5. (Optional) Install assetfinder for subdomain discovery:
   ```bash
   go install github.com/tomnomnom/assetfinder@latest
   ```

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| `url` | Target URL to scan |
| `-o, --output` | Output JSON file for detailed results |
| `-s, --subdomains` | Discover and scan subdomains |
| `-m, --max-subdomains` | Maximum number of subdomains to scan (default: 50) |
| `-t, --threads` | Number of concurrent threads (default: 5) |

## 💻 Usage

### Basic Usage

```bash
# Activate the virtual environment
source venv/bin/activate

# Run a basic scan
./scanner.py https://example.com
```

### Advanced Options

```bash
# Full scan with all modules
./scanner.py --full https://example.com

# Scan with specific modules
./scanner.py --headers --ssl --xss https://example.com

# Save results to a file
./scanner.py https://example.com --output report.txt

# Export results as JSON
./scanner.py https://example.com --format json --output report.json

# Specify custom user agent
./scanner.py https://example.com --user-agent "Custom Scanner"

# Set request timeout
./scanner.py https://example.com --timeout 30
```

Run `./scanner.py --help` to see all available options.

## 📊 Sample Output

```
====================================================================
       OWASP SECURITY SCANNER RESULTS
====================================================================

Target: https://example.com
Scan Date: 2025-02-21 15:30:45
Scan Duration: 00:05:23

[+] SSL/TLS Analysis
  [-] Certificate Valid: ✓
  [-] TLS Version: TLSv1.3
  [-] Cipher Suite: TLS_AES_256_GCM_SHA384
  [-] Forward Secrecy: ✓

[+] HTTP Headers
  [-] X-XSS-Protection: Missing ⚠️
  [-] Content-Security-Policy: Present ✓
  [-] X-Frame-Options: DENY ✓
  [-] X-Content-Type-Options: nosniff ✓

[+] Discovered Subdomains: 3
  [-] api.example.com
  [-] blog.example.com
  [-] dev.example.com (Potentially sensitive ⚠️)

[+] Vulnerability Summary
  [-] Open Ports: 2 (80, 443)
  [-] XSS Vulnerabilities: 0
  [-] SQL Injection Points: 0
  [-] CSRF Issues: 1 (Medium)
  [-] Information Disclosure: 2 (Low)
```

## 🛠️ Troubleshooting

### Common Issues

1. **Permission Denied**: Run the installation script with sudo or ensure you have appropriate permissions.
2. **Python Version Error**: Make sure you have Python 3.7 or higher installed.
3. **Module Not Found**: Ensure your virtual environment is activated and all dependencies are installed.

### Debug Mode

Run the scanner with increased verbosity for debugging:

```bash
./scanner.py https://example.com --verbose
```

## 🔄 Updating

To update to the latest version:

```bash
git pull origin main
./install.sh --update
```

## ⚠️ Disclaimer

This tool is designed for security professionals to assess their own systems or systems they have permission to test. Always obtain proper authorization before scanning any systems. Unauthorized scanning may be illegal.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Contact

For questions, issues, or collaboration, please open an issue on GitHub.

---
💡 Made with ❤️ for Cybersecurity Professionals