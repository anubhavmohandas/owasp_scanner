# 🎯 Bug Bounty Hunter - Complete Guide

## Overview

The **Bug Bounty Hunter** is an automated security testing platform that combines:
- 🔍 **Reconnaissance** - Technology detection, endpoint discovery
- 📂 **Directory Enumeration** - Dirbuster-style path discovery
- 🛡️ **OWASP Top 10:2025 Scanning** - Comprehensive vulnerability detection
- 📊 **Bounty Report Generation** - Ready-to-submit vulnerability reports

---

## 🚀 Quick Start

### Installation
```bash
# Make scripts executable
chmod +x bounty_hunter.py program_parser.py

# Install dependencies (already done if you installed OWASP scanner)
pip install -r requirements.txt
```

### Basic Usage
```bash
# Full bug bounty scan
python bounty_hunter.py https://target.com --full

# This will:
#  1. Run reconnaissance
#  2. Enumerate directories
#  3. Scan for OWASP Top 10 vulnerabilities
#  4. Generate bounty-formatted report
```

---

## 📋 Features

### 1. **Reconnaissance Engine**
Automatically discovers:
- ✅ Technologies used (WordPress, React, Angular, etc.)
- ✅ Server information (Apache, Nginx, versions)
- ✅ Endpoints and links
- ✅ API endpoints
- ✅ Forms and input points
- ✅ JavaScript files
- ✅ Security headers

### 2. **Directory Enumeration**
Built-in wordlist includes:
- Admin panels (/admin, /wp-admin, /cpanel)
- API endpoints (/api, /graphql, /rest)
- Backup files (.env, backup.zip, database.sql)
- Config files (config.php, web.config)
- Source control (.git, .svn)
- Package manifests (package.json, composer.json)

### 3. **OWASP Top 10:2025 Scanning**
Detects all OWASP 2025 categories:
- A01: Broken Access Control
- A02: Security Misconfiguration
- A03: Software Supply Chain Failures ✨
- A04: Cryptographic Failures
- A05: Injection
- A06: Insecure Design
- A07: Authentication Failures
- A08: Software/Data Integrity Failures
- A09: Logging & Alerting Failures
- A10: Mishandling of Exceptional Conditions ✨

### 4. **Bug Bounty Report Generation**
Creates professional reports with:
- CVSS scoring
- Bounty tier estimation
- Impact descriptions
- Reproduction steps
- Remediation recommendations
- Reconnaissance data

---

## 💻 Command Line Options

```
python bounty_hunter.py [OPTIONS] <URL>

Required:
  url                   Target URL to scan

Program Options:
  --program NAME        Bug bounty program name
  --program-file FILE   File containing program details

Scan Options:
  --full               Run complete scan (recon + enum + OWASP)
  --recon              Run reconnaissance only
  --enum               Run directory enumeration only
  --owasp              Run OWASP scan only
  --bounty-report      Generate bounty-formatted report

General Options:
  -o, --output FILE    Output file for report
  -t, --threads N      Number of threads (default: 10)
  -v, --verbose        Verbose output
  --wordlist FILE      Custom wordlist for enumeration
  --no-banner          Disable banner
```

---

## 📚 Usage Examples

### Example 1: Full Scan with Program Details
```bash
# Parse program details first
python program_parser.py --file examples/ubisoft_program.txt --output ubisoft.json

# Run full scan
python bounty_hunter.py https://target-game.com \
  --full \
  --program "Ubisoft Game Security" \
  --bounty-report \
  -o ubisoft_findings.txt
```

### Example 2: Quick OWASP Scan
```bash
# Just run OWASP vulnerability scan
python bounty_hunter.py https://target.com --owasp
```

### Example 3: Reconnaissance + Enumeration
```bash
# Discover attack surface
python bounty_hunter.py https://target.com --recon --enum
```

### Example 4: Custom Wordlist
```bash
# Use your own wordlist
python bounty_hunter.py https://target.com \
  --enum \
  --wordlist /path/to/custom-wordlist.txt \
  --threads 20
```

### Example 5: Verbose Debugging
```bash
# See detailed progress
python bounty_hunter.py https://target.com --full -v
```

---

## 🎓 Workflow Example: Ubisoft Game Security

### Step 1: Parse Program Details
```bash
# Save Ubisoft program details to file
cat > ubisoft_program.txt << 'EOF'
Ubisoft Game Security Program

Bounties
Low      0.1 - 3.9
Medium   4.0 - 6.9
High     7.0 - 8.9
Critical 9.0 - 9.4
Exceptional 9.5 - 10.0

Tier 2 Rewards
Low       € 0
Medium    € 500
High      € 1,250
Critical  € 2,000
Exceptional € 2,500
EOF

# Parse program
python program_parser.py --file ubisoft_program.txt --output ubisoft.json
```

### Step 2: Run Comprehensive Scan
```bash
python bounty_hunter.py https://game-api.ubisoft.com \
  --full \
  --program "Ubisoft Game Security" \
  --program-file ubisoft_program.txt \
  --bounty-report \
  --threads 15 \
  -o ubisoft_report.txt
```

### Step 3: Review Report
```bash
# View the generated report
cat ubisoft_report.txt

# Report includes:
# - Severity levels (mapped to Ubisoft tiers)
# - CVSS scores
# - Bounty estimates
# - Reproduction steps
# - Impact descriptions
# - Remediation recommendations
```

### Step 4: Validate Findings
```bash
# Manually verify each finding
# - Test reproduction steps
# - Confirm impact
# - Gather additional evidence if needed
```

### Step 5: Submit via Intigriti
- Copy findings from report
- Add screenshots/POC if available
- Submit through Intigriti platform

---

## 📊 Report Format

The bug bounty report includes:

```
================================================================================
BUG BOUNTY VULNERABILITY REPORT
================================================================================

Program: Ubisoft Game Security
Target: https://game-api.ubisoft.com
Date: 2025-12-03 14:30:00
Reporter: Security Researcher

================================================================================

================================================================================
CRITICAL SEVERITY FINDINGS
================================================================================

[CRITICAL #1] A03:2025 - Software Supply Chain Failures

CVSS Score: 9.2
Bounty Tier: € 2,000

Description:
  Exposed package.json reveals complete dependency tree

Location:
  https://game-api.ubisoft.com/package.json

Evidence:
  File accessible without authentication

Reproduction Steps:
  1. Navigate to https://game-api.ubisoft.com/package.json
  2. Observe complete dependency information
  3. Verify security impact

Recommendation:
  Restrict access to package manifests

Impact:
  Can lead to complete system compromise, data breach, or significant
  business impact

--------------------------------------------------------------------------------

[CRITICAL #2] A01:2025 - Broken Access Control

CVSS Score: 9.5
Bounty Tier: € 2,500 (Exceptional)

Description:
  Admin panel accessible without authentication

Location:
  https://game-api.ubisoft.com/admin/

...

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
  • X-Powered-By: Express
  • Node.js backend detected
  ...

API Endpoints Found:
  • https://game-api.ubisoft.com/api/v1
  • https://game-api.ubisoft.com/graphql
  ...
```

---

## 🔧 Advanced Features

### Custom Wordlists

Create your own wordlist for specific targets:

```bash
# game-specific-wordlist.txt
/api/player
/api/inventory
/api/matchmaking
/api/leaderboard
/api/achievements
/game-server/status
/cdn/assets
/telemetry
```

Use it:
```bash
python bounty_hunter.py https://game.com \
  --enum \
  --wordlist game-specific-wordlist.txt
```

### Chaining with Other Tools

```bash
# 1. Run bug bounty hunter
python bounty_hunter.py https://target.com --full -o findings.txt

# 2. Extract URLs for further testing
grep "https://" findings.txt > urls.txt

# 3. Use with other tools
cat urls.txt | nuclei -t vulnerabilities/
```

### Integration with CI/CD

```yaml
# .github/workflows/bounty-scan.yml
name: Weekly Bounty Scan

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run Bug Bounty Scan
        run: |
          python bounty_hunter.py ${{ secrets.TARGET_URL }} \
            --full \
            --bounty-report \
            -o weekly-scan.txt

      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: scan-results
          path: weekly-scan.txt
```

---

## ⚠️ Best Practices

### Before Scanning

1. **Read the Program Rules**
   - Understand scope
   - Check prohibited activities
   - Verify authorization

2. **Use Test Accounts**
   - Don't use real user data
   - Create disposable accounts
   - Test in isolation

3. **Rate Limiting**
   - Start with low thread count
   - Increase gradually
   - Monitor for blocks

### During Scanning

1. **Monitor Progress**
   - Use --verbose for debugging
   - Check for errors
   - Save intermediate results

2. **Respect Infrastructure**
   - Don't DDoS the target
   - Use reasonable delays
   - Stop if issues occur

3. **Document Everything**
   - Take screenshots
   - Save requests/responses
   - Note timestamps

### After Scanning

1. **Validate Findings**
   - Manually verify each vulnerability
   - Test reproduction steps
   - Assess real impact

2. **De-duplicate**
   - Remove false positives
   - Combine related findings
   - Prioritize by severity

3. **Professional Reporting**
   - Use clear language
   - Provide POC when safe
   - Suggest remediations

---

## 🎯 Maximizing Bounties

### Focus on High-Value Vulns

1. **Authentication Bypass** (Critical/Exceptional)
   - Admin access without credentials
   - JWT vulnerabilities
   - Session fixation

2. **Data Exposure** (Critical/High)
   - PII disclosure
   - API key exposure
   - Database leaks

3. **RCE/Injection** (Critical)
   - SQL injection
   - Command injection
   - Template injection

4. **Access Control** (High)
   - IDOR
   - Privilege escalation
   - Path traversal

### Chain Vulnerabilities

Combine findings for higher impact:
```
Low: Missing CSRF token
+
Medium: Predictable session IDs
=
High/Critical: Account takeover
```

### Demonstrate Impact

- Show real-world exploitation
- Explain business impact
- Provide detailed POC
- Suggest fixes

---

## 🛡️ Legal & Ethical

### Always Remember

✅ **DO:**
- Get written authorization
- Follow program rules
- Test on test accounts
- Report responsibly
- Wait for remediation before disclosure

❌ **DON'T:**
- Scan without permission
- Access real user data
- Perform DoS attacks
- Publicly disclose before fix
- Extort or blackmail

### Disclosure Timeline

1. **Report submitted** - Day 0
2. **Acknowledged** - Within 48 hours
3. **Triage** - Within 7 days
4. **Fix deployed** - 30-90 days
5. **Bounty paid** - After fix verification
6. **Public disclosure** - 90 days or after approval

---

## 📞 Support

For questions about the Bug Bounty Hunter:
- GitHub Issues: https://github.com/anubhavmohandas/owasp_scanner/issues
- Documentation: This file

For program-specific questions:
- Contact the program directly through their platform

---

## 🏆 Success Stories

Use this tool to:
- Discover vulnerabilities faster
- Generate professional reports
- Estimate potential rewards
- Automate reconnaissance
- Validate findings

Remember: **Quality > Quantity**

One well-researched Critical vulnerability is worth more than
dozens of Low-severity info disclosures.

---

**Happy Hunting! 🎯💰**
