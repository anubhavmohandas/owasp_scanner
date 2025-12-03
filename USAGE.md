# OWASP Security Scanner - Usage Guide

## Quick Start

### Basic Scan
```bash
python scanner.py https://example.com
```

### Scan with HTML Report
```bash
python scanner.py https://example.com -o report.html --format html
```

### Full Scan with Subdomain Discovery
```bash
python scanner.py https://example.com -s --max-subdomains 20
```

## Command Line Options

### Required Arguments
- `url` - Target URL to scan (e.g., https://example.com)

### Optional Arguments

#### Output Options
- `-o, --output <file>` - Specify output file for the report
- `-f, --format <format>` - Report format: html, json, or text (default: html)
- `--all-formats` - Generate reports in all formats

#### Scanning Options
- `-s, --subdomains` - Enable subdomain discovery and scanning
- `-m, --max-subdomains <number>` - Maximum subdomains to scan (default: 50)
- `-t, --threads <number>` - Number of concurrent threads (default: 5)

#### Display Options
- `-v, --verbose` - Enable verbose output
- `--no-banner` - Disable banner display

## Examples

### 1. Basic Security Scan
```bash
python scanner.py https://example.com
```
Performs a comprehensive OWASP Top 10 scan and generates an HTML report.

### 2. Scan with JSON Output
```bash
python scanner.py https://example.com -o results.json --format json
```
Generates a machine-readable JSON report for further processing.

### 3. Comprehensive Scan with Subdomains
```bash
python scanner.py https://example.com -s -m 30 -t 10
```
Discovers up to 30 subdomains and scans them using 10 concurrent threads.

### 4. Generate All Report Formats
```bash
python scanner.py https://example.com --all-formats
```
Creates HTML, JSON, and text reports simultaneously.

### 5. Quiet Scan Without Banner
```bash
python scanner.py https://example.com --no-banner
```
Runs scan without displaying the ASCII banner.

### 6. Verbose Scan for Debugging
```bash
python scanner.py https://example.com -v
```
Shows detailed debug information during the scan.

## Understanding the Results

### Risk Levels
- **Critical** - Immediate action required, severe security risk
- **High** - Should be fixed soon, significant security risk
- **Medium** - Should be addressed, moderate security risk
- **Low** - Minor security concern, fix when possible

### OWASP Top 10 Categories Scanned

1. **A01:2021 - Broken Access Control**
   - Checks for unauthorized access to resources
   - IDOR vulnerabilities
   - Missing authentication

2. **A02:2021 - Cryptographic Failures**
   - SSL/TLS configuration
   - Insecure cookies
   - Missing security headers

3. **A03:2021 - Injection**
   - SQL injection
   - Command injection
   - XSS vulnerabilities

4. **A04:2021 - Insecure Design**
   - Design flaws
   - Business logic vulnerabilities

5. **A05:2021 - Security Misconfiguration**
   - Default credentials
   - Directory listing
   - Information disclosure

6. **A06:2021 - Vulnerable Components**
   - Outdated libraries
   - Known CVEs

7. **A07:2021 - Authentication Failures**
   - Weak authentication
   - Session management issues

8. **A08:2021 - Software and Data Integrity Failures**
   - Insecure deserialization
   - Supply chain risks

9. **A09:2021 - Security Logging and Monitoring Failures**
   - Missing logs
   - Insufficient monitoring

10. **A10:2021 - Server-Side Request Forgery (SSRF)**
    - SSRF vulnerabilities
    - Internal service exposure

## Report Formats

### HTML Report
- Beautiful, interactive web page
- Color-coded vulnerability severities
- Detailed findings with recommendations
- Easy to share with stakeholders

### JSON Report
- Machine-readable format
- Perfect for integration with CI/CD
- Contains all scan metadata
- Structured for automated processing

### Text Report
- Plain text format
- Suitable for command-line review
- Easy to grep and process with standard tools
- Minimal formatting

## Advanced Usage

### Integration with CI/CD

#### GitHub Actions
```yaml
- name: Run Security Scan
  run: |
    python scanner.py ${{ secrets.TARGET_URL }} --format json -o scan-results.json

- name: Upload Results
  uses: actions/upload-artifact@v2
  with:
    name: security-scan
    path: scan-results.json
```

#### GitLab CI
```yaml
security_scan:
  script:
    - python scanner.py https://staging.example.com --format json -o results.json
  artifacts:
    paths:
      - results.json
    expire_in: 1 week
```

### Automated Scanning Script
```bash
#!/bin/bash
# automated-scan.sh

TARGETS=(
    "https://example.com"
    "https://staging.example.com"
    "https://api.example.com"
)

for target in "${TARGETS[@]}"; do
    echo "Scanning $target..."
    python scanner.py "$target" --all-formats
done
```

## Troubleshooting

### Common Issues

#### 1. Connection Timeouts
```bash
# Increase timeout or reduce threads
python scanner.py https://example.com -t 3
```

#### 2. Permission Denied Errors
```bash
# Ensure proper file permissions
chmod +x scanner.py
```

#### 3. Module Not Found
```bash
# Install dependencies
pip install -r requirements.txt
```

#### 4. SSL Certificate Errors
The scanner automatically handles SSL certificates. If issues persist:
```bash
# Check DNS resolution
nslookup example.com

# Verify SSL certificate
openssl s_client -connect example.com:443
```

## Best Practices

1. **Always Get Authorization** - Only scan systems you own or have explicit permission to test
2. **Start with Low Thread Count** - Avoid overwhelming target servers
3. **Review Reports Thoroughly** - Automated scans may have false positives
4. **Regular Scans** - Schedule periodic scans to catch new vulnerabilities
5. **Combine with Manual Testing** - Use automated scans as a starting point
6. **Keep Updated** - Regularly update the scanner and its dependencies

## Performance Tips

- Use `-t 10` for faster scans on robust infrastructure
- Disable subdomain scanning (`-s`) if not needed
- Generate only required report format (avoid `--all-formats` for speed)
- Use JSON format for fastest report generation

## Security Considerations

- **Rate Limiting** - The scanner includes delays to avoid triggering rate limits
- **Legal Compliance** - Ensure you have proper authorization
- **Data Handling** - Reports may contain sensitive information, store securely
- **Network Safety** - Use VPN or authorized networks for testing

## Support

For issues, feature requests, or questions:
- GitHub Issues: https://github.com/anubhavmohandas/owasp_scanner/issues
- Documentation: https://github.com/anubhavmohandas/owasp_scanner

## License

This tool is for authorized security testing only. Unauthorized scanning may be illegal.
