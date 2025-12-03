# 🛡️ OWASP Top 10:2025 Scanner

## 🎉 Now Supporting OWASP Top 10:2025!

This scanner has been updated to support the **latest OWASP Top 10:2025** categories, reflecting the current threat landscape and modern security challenges.

---

## 🆕 What's New in OWASP 2025

### **New Categories**

1. **✨ A03:2025 - Software Supply Chain Failures** (NEW)
   - Replaces/expands "Vulnerable and Outdated Components"
   - Focus on supply chain security
   - Detects: Exposed package manifests, missing SRI, vulnerable dependencies
   - Why it matters: Supply chain attacks have increased significantly (SolarWinds, Log4Shell)

2. **✨ A10:2025 - Mishandling of Exceptional Conditions** (NEW)
   - Replaces "Server-Side Request Forgery (SSRF)"
   - Focus on error handling and exception management
   - Detects: Verbose error messages, stack trace exposure, improper status codes
   - Why it matters: Poor error handling leads to information disclosure

### **Reordered Categories**

- **A02:2025 - Security Misconfiguration** ⬆️ (moved from #5 to #2)
  - Now #2 priority (was #5 in 2021)
  - Reflects increased importance of proper configuration

- **A04:2025 - Cryptographic Failures** (moved from #2 to #4)
  - Still critical, but reordered based on prevalence

- **A05:2025 - Injection** (moved from #3 to #5)
  - Still important, but modern frameworks have better protection

---

## 📋 OWASP Top 10:2025 Complete List

| Rank | Category | Status | Change from 2021 |
|------|----------|--------|------------------|
| 1 | **A01:2025** - Broken Access Control | ✅ Full | Same position |
| 2 | **A02:2025** - Security Misconfiguration | ✅ Full | ⬆️ Moved from #5 |
| 3 | **A03:2025** - Software Supply Chain Failures | ✅ Full | ✨ NEW |
| 4 | **A04:2025** - Cryptographic Failures | ✅ Full | Moved from #2 |
| 5 | **A05:2025** - Injection | ✅ Full | Moved from #3 |
| 6 | **A06:2025** - Insecure Design | ✅ Full | Moved from #4 |
| 7 | **A07:2025** - Authentication Failures | ✅ Full | Similar to 2021 #7 |
| 8 | **A08:2025** - Software or Data Integrity Failures | ✅ Full | Similar to 2021 #8 |
| 9 | **A09:2025** - Logging & Alerting Failures | ✅ Full | Evolved from 2021 #9 |
| 10 | **A10:2025** - Mishandling of Exceptional Conditions | ✅ Full | ✨ NEW |

---

## 🚀 Using the OWASP 2025 Scanner

### Quick Start

```bash
# Use the dedicated OWASP 2025 scanner
python scanner2025.py https://example.com
```

### Full Options

```bash
# OWASP 2025 scan with HTML report
python scanner2025.py https://example.com -o report_2025.html

# Scan with subdomain discovery
python scanner2025.py https://example.com -s --max-subdomains 20

# Generate all report formats
python scanner2025.py https://example.com --all-formats

# Verbose mode
python scanner2025.py https://example.com -v
```

### Scanner Selection

- **`scanner2025.py`** - Latest OWASP 2025 categories (Recommended)
- **`scanner.py`** - OWASP 2021 categories (Still supported)

---

## 🔍 Detailed Category Coverage

### A03:2025 - Software Supply Chain Failures

**What It Detects:**
- ✅ Exposed package.json, composer.json, requirements.txt
- ✅ Missing Subresource Integrity (SRI) on CDN resources
- ✅ Vulnerable JavaScript libraries (jQuery 1.x, old Angular, etc.)
- ✅ Insecure CDN usage without integrity checks
- ✅ Dependency confusion risks
- ✅ Unscoped npm packages in private projects

**Example Findings:**
```
🔴 Critical: Vulnerable/Outdated Components
   - jQuery v1.11 detected (multiple known XSS vulnerabilities)
   - Recommendation: Update to jQuery 3.x or remove if not needed

🟠 High: Missing Subresource Integrity
   - 5 external resources loaded without SRI
   - Recommendation: Add integrity="" attribute to all CDN resources
```

**How to Fix:**
```html
<!-- ❌ Bad: No integrity check -->
<script src="https://cdn.example.com/library.js"></script>

<!-- ✅ Good: With SRI -->
<script src="https://cdn.example.com/library.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/ux..."
        crossorigin="anonymous"></script>
```

### A10:2025 - Mishandling of Exceptional Conditions

**What It Detects:**
- ✅ Stack trace exposure in error pages
- ✅ Database error messages visible to users
- ✅ Framework debug mode enabled in production
- ✅ File path disclosure in errors
- ✅ Missing custom error pages (404, 500, etc.)
- ✅ Improper HTTP status code usage

**Example Findings:**
```
🔴 High: Stack Trace Exposure
   - PHP stack traces visible in error responses
   - Recommendation: Disable display_errors in production

🟡 Medium: Missing Custom Error Pages
   - Default server error pages detected for: HTTP 404, 500
   - Recommendation: Configure custom error pages
```

**How to Fix:**
```php
// ❌ Bad: Shows detailed errors to users
ini_set('display_errors', '1');
error_reporting(E_ALL);

// ✅ Good: Log errors, show generic messages
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', '/var/log/php_errors.log');

// Custom error handler
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    error_log("Error [$errno]: $errstr in $errfile:$errline");
    // Show generic message to user
    echo "An error occurred. Please try again later.";
});
```

---

## 📊 Comparison: OWASP 2021 vs 2025

| 2021 Position | Category | 2025 Position | Change |
|---------------|----------|---------------|--------|
| #1 | Broken Access Control | #1 | ✅ Same |
| #2 | Cryptographic Failures | #4 | ⬇️ |
| #3 | Injection | #5 | ⬇️ |
| #4 | Insecure Design | #6 | ⬇️ |
| #5 | Security Misconfiguration | #2 | ⬆️ **Major increase** |
| #6 | Vulnerable/Outdated Components | #3 | ⬆️ Evolved to Supply Chain |
| #7 | Auth Failures | #7 | ✅ Same |
| #8 | Data Integrity Failures | #8 | ✅ Same |
| #9 | Logging/Monitoring Failures | #9 | ✅ Same (renamed) |
| #10 | SSRF | — | ❌ Removed as standalone |
| — | Exceptional Conditions | #10 | ✨ **New** |

---

## 🎯 Why the Changes?

### Security Misconfiguration → #2
- Cloud misconfigurations are now the leading cause of breaches
- Container and orchestration complexity increases misconfiguration risks
- Default credentials and exposed admin panels remain prevalent

### Software Supply Chain → #3
- Supply chain attacks increased 742% in 2023
- High-profile incidents: SolarWinds, Log4j, Codecov
- NPM/PyPI typosquatting and dependency confusion attacks

### Exceptional Conditions → #10
- Information disclosure through errors remains common
- Verbose error messages aid attackers in reconnaissance
- Poor error handling can lead to DoS and data leaks

### SSRF Removed
- Integrated into other categories (Insecure Design, Injection)
- Less prevalent as a standalone category
- Still checked, but not a separate Top 10 item

---

## 🛠️ Migration Guide

### From 2021 Scanner to 2025

```bash
# Old way (OWASP 2021)
python scanner.py https://example.com

# New way (OWASP 2025)
python scanner2025.py https://example.com
```

### Both Scanners Are Supported

You can run both and compare results:

```bash
# Run OWASP 2021 scan
python scanner.py https://example.com -o report_2021.html

# Run OWASP 2025 scan
python scanner2025.py https://example.com -o report_2025.html

# Compare findings
```

---

## 📈 Enhanced Detection in 2025

### New Checks Added

1. **Package Manifest Exposure**
   - Checks for publicly accessible package.json, composer.json, etc.
   - Identifies version information disclosure

2. **SRI Verification**
   - Validates integrity attributes on external resources
   - Identifies missing crossorigin attributes

3. **Dependency Analysis**
   - Detects known vulnerable library versions
   - Checks for outdated dependencies

4. **Error Handling Quality**
   - Tests error responses for information leakage
   - Validates custom error page configuration
   - Checks HTTP status code correctness

5. **CDN Security**
   - Analyzes third-party CDN usage
   - Validates security attributes

---

## 💡 Best Practices for OWASP 2025

### For Supply Chain Security

1. **Use SRI for all external resources**
   ```html
   <script src="https://cdn.com/lib.js"
           integrity="sha384-..."
           crossorigin="anonymous"></script>
   ```

2. **Keep dependencies updated**
   ```bash
   npm audit fix
   pip-audit
   composer audit
   ```

3. **Use scoped packages for private code**
   ```json
   {
     "dependencies": {
       "@yourorg/private-package": "^1.0.0"
     }
   }
   ```

4. **Implement SBOM (Software Bill of Materials)**
   - Track all components and their versions
   - Monitor for new vulnerabilities

### For Exception Handling

1. **Disable debug mode in production**
   ```python
   # Django
   DEBUG = False

   # Flask
   app.debug = False

   # PHP
   ini_set('display_errors', '0');
   ```

2. **Implement custom error pages**
   ```nginx
   error_page 404 /404.html;
   error_page 500 502 503 504 /50x.html;
   ```

3. **Log errors server-side**
   ```python
   import logging
   logging.error('Error details', exc_info=True)
   # Don't show to user
   ```

4. **Use generic error messages**
   ```javascript
   // ❌ Bad
   res.status(500).send(`Database error: ${err.message}`);

   // ✅ Good
   logger.error('DB error:', err);
   res.status(500).send('An error occurred. Please try again.');
   ```

---

## 📚 Resources

### Official OWASP Resources
- [OWASP Top 10:2025](https://owasp.org/Top10/) - Official documentation
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Tools & References
- [Snyk](https://snyk.io/) - Dependency vulnerability scanning
- [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) - NPM security audit
- [SBOM Tools](https://www.cisa.gov/sbom) - Software Bill of Materials
- [SRI Hash Generator](https://www.srihash.org/) - Generate integrity hashes

---

## 🔄 Staying Updated

The OWASP Top 10 evolves every few years. This scanner will be updated to reflect:
- New vulnerability categories
- Emerging threat patterns
- Industry best practices
- Framework-specific checks

**Star this repository** to get notified of updates!

---

## 📞 Support

For questions about OWASP 2025 scanner:
- GitHub Issues: [Report issues](https://github.com/anubhavmohandas/owasp_scanner/issues)
- Discussions: [Ask questions](https://github.com/anubhavmohandas/owasp_scanner/discussions)

---

**Last Updated:** December 2025
**Scanner Version:** 2.1.0
**OWASP Standard:** Top 10:2025
