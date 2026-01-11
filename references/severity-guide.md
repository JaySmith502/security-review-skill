# Security Finding Severity Guide

## Severity Levels

### CRITICAL (Score 9.0-10.0)
**Requires immediate attention. Stop deployment.**

- Remote Code Execution (RCE)
- SQL Injection with data access
- Authentication bypass
- Hardcoded production credentials
- Exposed private keys
- Unrestricted file upload leading to RCE
- Deserialization of untrusted data

**Action:** Fix before any deployment. Block PR.

### HIGH (Score 7.0-8.9)
**Significant risk. Fix before production.**

- Stored Cross-Site Scripting (XSS)
- Insecure Direct Object References (IDOR)
- Server-Side Request Forgery (SSRF)
- Command injection
- Path traversal with file access
- Broken access control
- Sensitive data exposure

**Action:** Fix before release. May deploy to staging for testing.

### MEDIUM (Score 4.0-6.9)
**Moderate risk. Fix in current sprint.**

- Reflected XSS
- CSRF on non-critical functions
- Weak cryptographic algorithms (MD5, SHA1)
- Missing security headers
- Information disclosure
- Debug mode enabled
- Verbose error messages

**Action:** Track in issue system. Fix within current development cycle.

### LOW (Score 0.1-3.9)
**Minor risk. Fix when convenient.**

- Security-related TODOs/FIXMEs
- Commented credentials (likely examples)
- Missing best practices
- Minor information leaks
- HTTP for localhost/internal only

**Action:** Add to backlog. Fix during refactoring.

---

## Context Adjustments

**Increase severity when:**
- Finding is in authentication/authorization code
- Involves financial or PII data
- Publicly exposed (not internal tool)
- No existing compensating controls
- Easy to exploit

**Decrease severity when:**
- Internal tool only
- Already mitigated by other controls
- Requires authenticated access
- Test/example code clearly marked
- Additional exploitation steps required

---

## Inline Comment Format

When adding TODO comments to code:

```python
# SECURITY: [SEVERITY] - Brief description
# Example:
# SECURITY: HIGH - SQL injection via string formatting. Use parameterized query.
```

For multi-line:
```python
# SECURITY: CRITICAL - Remote code execution risk
# The eval() call here processes user input without validation.
# FIX: Replace with ast.literal_eval() or remove entirely.
```
