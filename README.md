# Security Review Skill for Claude Code

A comprehensive security code review skill for [Claude Code](https://claude.ai/code) that combines automated vulnerability scanning with manual OWASP Top 10 auditing.

## Features

- **Automated Security Scanning**
  - Hardcoded secrets detection (API keys, passwords, tokens)
  - Dependency vulnerability checking via OSV.dev
  - Insecure code pattern detection (SQL injection, XSS, weak crypto, etc.)

- **Manual Review Framework**
  - OWASP Top 10 checklist with code examples
  - Structured severity assessment
  - Professional markdown report generation

- **Two Review Modes**
  - **Quick Scan** (~2-5 min): Fast automated scanning for critical issues
  - **Deep Audit** (~15-30 min): Comprehensive OWASP review with inline annotations

## Installation

1. Clone this repository to your Claude Code skills directory:

```bash
cd ~/.claude/skills  # or %USERPROFILE%\.claude\skills on Windows
git clone https://github.com/YOUR-USERNAME/security-review.git
```

2. The skill requires Python 3.10+ (no additional dependencies needed)

## Usage

### In Claude Code

Run a quick security scan:
```
/security-review quick
```

Run a comprehensive security audit:
```
/security-review deep
```

### Standalone Scripts

You can also run the scanning scripts independently:

```bash
# Scan for hardcoded secrets
python scripts/scan_secrets.py /path/to/project --severity HIGH

# Check dependencies for vulnerabilities
python scripts/check_dependencies.py /path/to/project

# Find insecure code patterns
python scripts/find_patterns.py /path/to/project --severity HIGH
```

## Severity Levels

| Severity | Impact | Action Required |
|----------|--------|-----------------|
| **CRITICAL** | RCE, SQLi, auth bypass, exposed credentials | Block deployment immediately |
| **HIGH** | Stored XSS, IDOR, command injection | Fix before production release |
| **MEDIUM** | CSRF, weak crypto, missing headers | Fix in current sprint |
| **LOW** | Best practices, minor info leaks | Add to backlog |

## What Gets Detected

### Secrets & Credentials
- AWS, GCP, Azure credentials
- GitHub, GitLab tokens
- API keys and secret keys
- Database connection strings
- Private keys (RSA, PGP, SSH)
- JWT tokens
- Slack/Discord webhooks

### Code Vulnerabilities
- **Injection**: SQL injection, command injection, code injection (eval/exec)
- **XSS**: innerHTML, dangerouslySetInnerHTML, document.write
- **Weak Crypto**: MD5, SHA1, DES, weak random number generation
- **Deserialization**: pickle, unsafe YAML loading
- **Path Traversal**: Unsanitized file operations
- **XXE**: XML External Entity vulnerabilities
- **SSRF**: Server-Side Request Forgery risks

### Dependencies
- Known CVEs in Python packages (PyPI)
- Known CVEs in Node.js packages (npm)
- Checks requirements.txt, package.json, Pipfile, pyproject.toml

## Output Formats

### Quick Scan
- Summary of findings grouped by severity
- Count of critical/high/medium/low issues
- Top priority issues requiring immediate attention

### Deep Audit
- Full markdown security report (see [report-template.md](assets/report-template.md))
- Inline code annotations with `# SECURITY:` comments
- Detailed remediation recommendations
- OWASP Top 10 coverage analysis

## Repository Structure

```
security-review/
├── scripts/              # Automated scanning tools
│   ├── scan_secrets.py   # Secret & credential detection
│   ├── check_dependencies.py  # Dependency vulnerability check
│   └── find_patterns.py  # Insecure code pattern detection
├── references/           # Review guides and checklists
│   ├── owasp-checklist.md    # OWASP Top 10 review guide
│   └── severity-guide.md     # Severity classification rules
├── assets/
│   └── report-template.md    # Markdown report template
├── SKILL.md             # Skill workflow documentation
└── CLAUDE.md            # Developer guide for Claude Code
```

## Supported Languages

- **Python**: Full coverage for common vulnerabilities and frameworks
- **JavaScript/TypeScript**: Node.js and browser-side security issues
- **General**: Language-agnostic patterns (secrets, debug flags, TODOs)

## Examples

### Finding hardcoded AWS credentials
```bash
$ python scripts/scan_secrets.py . --severity CRITICAL
{
  "findings": [
    {
      "file": "config.py",
      "line": 12,
      "severity": "CRITICAL",
      "type": "aws_access_key",
      "description": "AWS Access Key ID",
      "match": "AKIAIOSFODNN7EXAMPLE"
    }
  ]
}
```

### Detecting SQL injection
```bash
$ python scripts/find_patterns.py . --type sql_injection
{
  "findings": [
    {
      "file": "database.py",
      "line": 45,
      "severity": "CRITICAL",
      "type": "sql_injection",
      "description": "f-string in SQL query",
      "recommendation": "Use parameterized queries"
    }
  ]
}
```

## OWASP Top 10 Coverage

The deep audit mode reviews code against all OWASP Top 10 categories:

1. **A01** - Broken Access Control
2. **A02** - Cryptographic Failures
3. **A03** - Injection
4. **A04** - Insecure Design
5. **A05** - Security Misconfiguration
6. **A06** - Vulnerable Components
7. **A07** - Authentication Failures
8. **A08** - Software/Data Integrity Failures
9. **A09** - Logging & Monitoring Failures
10. **A10** - Server-Side Request Forgery

See [references/owasp-checklist.md](references/owasp-checklist.md) for detailed review criteria.

## When to Use

- **Before deploying to production** - Quick scan to catch critical issues
- **During code review** - Deep audit for pull requests with security-sensitive changes
- **Regular security audits** - Periodic deep audits of entire codebase
- **After adding auth/authz code** - Review authentication and authorization logic
- **When handling sensitive data** - Review PII, payment, or credential handling

## Limitations

- Pattern-based detection may produce false positives
- Cannot detect complex business logic vulnerabilities
- Dependency checking requires network access to OSV.dev
- Manual review quality depends on code reviewer expertise
- Not a replacement for professional penetration testing

## Contributing

Contributions welcome! Areas for improvement:
- Additional language support (Java, Go, Ruby, PHP)
- More vulnerability patterns
- Integration with additional vulnerability databases
- GitHub Actions workflow examples

## License

MIT License - see LICENSE file for details

## Related Projects

- [Claude Code](https://claude.ai/code) - AI-powered CLI coding assistant
- [OWASP Top 10](https://owasp.org/Top10/) - Web application security risks
- [OSV.dev](https://osv.dev/) - Open source vulnerability database
