# OWASP Top 10 Security Checklist

Quick reference for manual code review. Use alongside automated scans.

## A01: Broken Access Control

**Check for:**
- Missing authorization checks on endpoints/functions
- Direct object references (IDOR) - e.g., `/user/123` without ownership validation
- Path traversal: `../` in file operations
- CORS misconfiguration allowing `*` origins
- Missing function-level access control
- Metadata manipulation (JWT tampering, hidden fields)

**Review patterns:**
```python
# BAD: No authorization check
@app.route('/admin/users')
def list_users():
    return User.query.all()

# GOOD: Authorization check
@app.route('/admin/users')
@require_role('admin')
def list_users():
    return User.query.all()
```

## A02: Cryptographic Failures

**Check for:**
- Hardcoded secrets, keys, passwords
- Weak algorithms: MD5, SHA1, DES, RC4
- Missing encryption for sensitive data in transit/at rest
- Weak random number generation (`random` instead of `secrets`)
- Self-signed or expired certificates
- Missing HTTPS redirects

**Weak vs Strong:**
| Weak | Strong |
|------|--------|
| MD5, SHA1 | SHA-256, SHA-3 |
| DES, 3DES | AES-256 |
| random.random() | secrets.token_bytes() |
| RSA-1024 | RSA-2048+ |

## A03: Injection

**SQL Injection:**
```python
# BAD
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# GOOD
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

**Command Injection:**
```python
# BAD
os.system(f"ping {user_input}")

# GOOD
subprocess.run(["ping", user_input], shell=False)
```

**Code Injection:**
```python
# BAD - Never use with user input
eval(user_expression)
exec(user_code)
```

## A04: Insecure Design

**Check for:**
- Missing rate limiting on sensitive operations
- No account lockout after failed attempts
- Missing CAPTCHA on public forms
- Lack of input validation strategy
- No business logic validation
- Missing audit logging

## A05: Security Misconfiguration

**Check for:**
- Debug mode enabled in production
- Default credentials still active
- Unnecessary features enabled
- Missing security headers
- Verbose error messages exposing internals
- Outdated software/dependencies

**Required headers:**
```
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
```

## A06: Vulnerable Components

**Check for:**
- Known vulnerabilities in dependencies (use `check_dependencies.py`)
- Outdated frameworks/libraries
- Unmaintained packages
- Components with no security patches

**Tools:** `pip-audit`, `npm audit`, `snyk`, OSV.dev

## A07: Authentication Failures

**Check for:**
- Weak password requirements
- Missing MFA on sensitive operations
- Session fixation vulnerabilities
- Credentials in URLs
- Missing session timeout
- Predictable session IDs

**Session security:**
```python
# Required session settings
SESSION_COOKIE_SECURE = True      # HTTPS only
SESSION_COOKIE_HTTPONLY = True    # No JS access
SESSION_COOKIE_SAMESITE = 'Lax'   # CSRF protection
```

## A08: Software/Data Integrity Failures

**Check for:**
- Insecure deserialization (pickle, yaml.load)
- Missing integrity checks on downloads
- CI/CD pipeline vulnerabilities
- Unsigned updates/packages

**Deserialization:**
```python
# BAD
data = pickle.loads(untrusted_data)
config = yaml.load(file)

# GOOD
data = json.loads(untrusted_data)
config = yaml.safe_load(file)
```

## A09: Logging & Monitoring Failures

**Check for:**
- Missing logs for authentication events
- No logging of access control failures
- Logs without timestamps
- Sensitive data in logs (passwords, tokens)
- No alerting mechanism
- Logs not protected from tampering

## A10: Server-Side Request Forgery (SSRF)

**Check for:**
- User-controllable URLs in requests
- Internal service access via user input
- URL validation bypass potential

```python
# BAD
response = requests.get(user_provided_url)

# GOOD
def validate_url(url):
    parsed = urlparse(url)
    if parsed.hostname in BLOCKED_HOSTS:
        raise ValueError("Blocked host")
    return url
```

---

## Quick Severity Guide

| Severity | Impact | Examples |
|----------|--------|----------|
| CRITICAL | Full compromise | RCE, SQLi, Auth bypass, Hardcoded prod creds |
| HIGH | Significant damage | Stored XSS, IDOR, Command injection |
| MEDIUM | Moderate impact | CSRF, Information disclosure, Weak crypto |
| LOW | Minor impact | Missing headers, Debug info, Security TODOs |
