# 🚀 Bug Bounty Hunter - Quick Start Guide

## Installation

```bash
# Clone the repository
git clone https://github.com/anubhavmohandas/owasp_scanner.git
cd owasp_scanner

# Install dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x bounty_hunter.py program_parser.py scanner2025.py

# Run validation tests
python3 test_bounty_hunter.py
```

---

## Quick Usage

### 1. Basic Reconnaissance
```bash
python bounty_hunter.py https://target.com --recon
```
Discovers technologies, endpoints, APIs, forms, and attack surface.

### 2. Directory Enumeration
```bash
python bounty_hunter.py https://target.com --enum
```
Finds hidden paths, admin panels, backups, configs, and exposed files.

### 3. OWASP Vulnerability Scan
```bash
python bounty_hunter.py https://target.com --owasp
```
Scans for all OWASP Top 10:2025 vulnerabilities.

### 4. Complete Bug Bounty Scan
```bash
python bounty_hunter.py https://target.com --full --bounty-report
```
Runs reconnaissance + enumeration + OWASP scan + generates professional report.

---

## Complete Workflow

### Step 1: Parse Bug Bounty Program
```bash
# Use a generic example
python program_parser.py \
  --file examples/generic_program.txt \
  --output program.json

# Or parse from text
python program_parser.py \
  --text "Low 0-3.9, Medium 4-6.9, High 7-8.9, Critical 9-10" \
  --output program.json
```

### Step 2: Run Full Scan
```bash
python bounty_hunter.py https://target.com \
  --full \
  --program "Bug Bounty Program" \
  --program-file program.json \
  --bounty-report \
  --threads 15 \
  -o bounty_report.txt
```

### Step 3: Review Report
```bash
cat bounty_report.txt
```

The report includes:
- Vulnerability severity (Critical/High/Medium/Low)
- CVSS scores (0-10)
- Bounty tier estimates
- Reproduction steps
- Impact descriptions
- Remediation recommendations
- Reconnaissance data

---

## Command Options

### Scan Modes
```bash
--full              Complete scan (recon + enum + OWASP)
--recon             Reconnaissance only
--enum              Directory enumeration only
--owasp             OWASP vulnerability scan only
--bounty-report     Generate bounty-formatted report
```

### Program Details
```bash
--program "Name"                Set program name
--program-file program.json     Load program details from file
```

### Performance
```bash
-t, --threads 20               Number of concurrent threads
--wordlist custom.txt          Custom wordlist for enumeration
```

### Output
```bash
-o report.txt                  Output file
-v, --verbose                  Verbose output
--no-banner                    Disable banner
```

---

## Examples

### Example 1: Quick Web App Scan
```bash
python bounty_hunter.py https://app.example.com \
  --full \
  --bounty-report
```

### Example 2: API Security Scan
```bash
python bounty_hunter.py https://api.example.com \
  --recon \
  --owasp
```

### Example 3: Custom Enumeration
```bash
# Create API-specific wordlist
cat > api-paths.txt << EOF
/api/v1
/api/v2
/graphql
/swagger
/openapi.json
/api/users
/api/admin
EOF

# Scan with custom wordlist
python bounty_hunter.py https://api.example.com \
  --enum \
  --wordlist api-paths.txt \
  --threads 20
```

### Example 4: Comprehensive Scan
```bash
# Parse program
python program_parser.py \
  --file examples/generic_program.txt \
  --output program.json

# Full scan
python bounty_hunter.py https://target.com \
  --full \
  --program-file program.json \
  --bounty-report \
  --verbose \
  -o findings_$(date +%Y%m%d).txt
```

---

## What Gets Scanned

### Reconnaissance Phase
- ✅ Web technologies (WordPress, React, Angular, etc.)
- ✅ Server information (Apache, Nginx, versions)
- ✅ All page endpoints
- ✅ API endpoints
- ✅ Forms and input points
- ✅ JavaScript files
- ✅ Security headers

### Directory Enumeration
- ✅ Admin panels (/admin, /administrator, etc.)
- ✅ API endpoints (/api, /graphql, /swagger)
- ✅ Backup files (.git, .env, backup.zip)
- ✅ Config files (config.php, web.config)
- ✅ Package manifests (package.json, composer.json)
- ✅ Source control exposure
- ✅ 100+ common paths

### OWASP Top 10:2025 Scan
1. **A01** - Broken Access Control
2. **A02** - Security Misconfiguration
3. **A03** - Software Supply Chain Failures ✨
4. **A04** - Cryptographic Failures
5. **A05** - Injection
6. **A06** - Insecure Design
7. **A07** - Authentication Failures
8. **A08** - Software/Data Integrity Failures
9. **A09** - Logging & Alerting Failures
10. **A10** - Mishandling of Exceptional Conditions ✨

---

## Report Format

```
================================================================================
BUG BOUNTY VULNERABILITY REPORT
================================================================================

Program: Your Bug Bounty Program
Target: https://target.com
Date: 2025-12-03 14:30:00

================================================================================
CRITICAL SEVERITY FINDINGS
================================================================================

[CRITICAL #1] A03:2025 - Software Supply Chain Failures

CVSS Score: 9.2
Bounty Tier: $5,000

Description:
  Exposed package.json reveals complete dependency tree

Location:
  https://target.com/package.json

Reproduction Steps:
  1. Navigate to the affected URL
  2. Observe the vulnerability as described
  3. Verify the security impact

Recommendation:
  Restrict access to package manifests

Impact:
  Can lead to complete system compromise, data breach, or
  significant business impact

--------------------------------------------------------------------------------

... (more findings) ...

================================================================================
SUMMARY
================================================================================

Total Vulnerabilities Found: 8
  Critical: 2
  High: 3
  Medium: 2
  Low: 1

================================================================================
RECONNAISSANCE DATA
================================================================================

Technologies Detected:
  • Server: nginx/1.18.0
  • Node.js backend
  • React frontend
  ...

API Endpoints Found:
  • https://target.com/api/v1
  • https://target.com/graphql
  ...
```

---

## Validation

Before running on real targets, test the tool:

```bash
# Run validation tests
python3 test_bounty_hunter.py

# Expected output:
# ✅ Import dependencies
# ✅ Import bounty_hunter.py
# ✅ Program parser
# ✅ Reconnaissance engine
# ✅ Directory enumerator
# ✅ Report generator
# ✅ CLI help command
# ✅ Example files present
# ✅ Quick recon scan
#
# RESULTS: 9 passed, 1 failed (network connectivity is expected)
# ✅ All tests passed! Tool is ready to use.
```

---

## Performance Tips

1. **Start with fewer threads** (default: 10)
   ```bash
   --threads 10  # Conservative
   ```

2. **Increase for faster scans**
   ```bash
   --threads 30  # Aggressive (use carefully)
   ```

3. **Use custom wordlists** for targeted scans
   ```bash
   --wordlist focused-paths.txt
   ```

4. **Run phases separately** if needed
   ```bash
   # First recon
   python bounty_hunter.py https://target.com --recon -o recon.txt

   # Then targeted enum
   python bounty_hunter.py https://target.com --enum -o enum.txt

   # Finally OWASP scan
   python bounty_hunter.py https://target.com --owasp -o vulns.txt
   ```

---

## Legal & Ethical Use

⚠️ **IMPORTANT**

- ✅ Only scan targets you have permission to test
- ✅ Follow bug bounty program rules
- ✅ Do not access real user data
- ✅ Report responsibly
- ❌ Never perform DoS attacks
- ❌ Never scan without authorization

**Unauthorized scanning is illegal.**

---

## Troubleshooting

### Import Errors
```bash
pip install -r requirements.txt
```

### Permission Issues
```bash
chmod +x bounty_hunter.py program_parser.py
```

### Network Timeouts
```bash
# Reduce threads
python bounty_hunter.py https://target.com --full -t 5
```

### Module Not Found
```bash
# Ensure you're in the correct directory
cd owasp_scanner
python3 bounty_hunter.py --help
```

---

## Next Steps

1. ✅ Run validation: `python3 test_bounty_hunter.py`
2. ✅ Parse a program: `python program_parser.py --file examples/generic_program.txt`
3. ✅ Test on example.com: `python bounty_hunter.py https://example.com --recon`
4. ✅ Read the full guide: [BUG_BOUNTY_GUIDE.md](BUG_BOUNTY_GUIDE.md)
5. ✅ Start hunting (with permission)!

---

**Happy Hunting! 🎯**
