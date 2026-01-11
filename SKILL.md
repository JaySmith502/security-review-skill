---
name: security-review
description: |
  Comprehensive security code review skill with automated scanning and manual analysis. Supports two modes:
  - `/security-review quick` - Fast scan for critical issues (secrets, dependencies, obvious vulnerabilities)
  - `/security-review deep` - Thorough audit including OWASP Top 10 manual review and inline annotations

  Use when: (1) Before deploying code to production, (2) Reviewing pull requests for security issues, (3) Auditing existing codebases, (4) After adding new authentication/authorization code, (5) When handling sensitive data or credentials, (6) User requests security review, security audit, vulnerability scan, or code security check.
---

# Security Review Skill

## Review Modes

### Quick Scan (`/security-review quick`)
Fast automated scan (~2-5 min). Run this first.

1. Run all three scanning scripts in parallel
2. Report findings grouped by severity
3. Flag any CRITICAL/HIGH issues requiring immediate attention

### Deep Audit (`/security-review deep`)
Comprehensive review (~15-30 min). Run after quick scan or for thorough audits.

1. Run automated scans
2. Manual code review against OWASP Top 10 (see `references/owasp-checklist.md`)
3. Review authentication, authorization, and data handling code
4. Add inline `# SECURITY:` comments to problematic code
5. Generate full markdown report using `assets/report-template.md`

## Workflow

### Step 1: Automated Scans

Run these scripts from the project root:

```bash
# Scan for hardcoded secrets
python scripts/scan_secrets.py . --severity HIGH

# Check dependencies for vulnerabilities
python scripts/check_dependencies.py .

# Find insecure code patterns
python scripts/find_patterns.py . --severity HIGH
```

For quick mode, run all three in parallel. Parse JSON output and aggregate findings.

### Step 2: Analyze Results

Group findings by severity:
- **CRITICAL**: Stop. These must be fixed before any deployment.
- **HIGH**: Flag for immediate fix. Block PR if in review context.
- **MEDIUM**: Track for fix in current sprint.
- **LOW**: Add to backlog.

### Step 3: Manual Review (Deep Mode Only)

Focus manual review on:
1. **Authentication code** - Login, session management, password handling
2. **Authorization code** - Access control, permission checks
3. **Data handling** - User input processing, database queries, file operations
4. **External integrations** - API calls, webhooks, third-party services
5. **Cryptography usage** - Encryption, hashing, random generation

Use `references/owasp-checklist.md` as review guide.

### Step 4: Annotate Code (Deep Mode Only)

Add inline comments for issues found:

```python
# SECURITY: HIGH - SQL injection via string formatting
# FIX: Use parameterized query instead of f-string
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

Format: `# SECURITY: [SEVERITY] - [Description]`

### Step 5: Generate Report

**Quick mode**: Summarize findings in response with severity counts and top issues.

**Deep mode**: Use `assets/report-template.md` to generate full report. Replace placeholders:
- `{{PROJECT_NAME}}` - Project/repository name
- `{{DATE}}` - Current date
- `{{REVIEW_TYPE}}` - "Quick Scan" or "Deep Audit"
- `{{CRITICAL_COUNT}}`, `{{HIGH_COUNT}}`, etc. - Finding counts
- `{{OVERALL_RISK}}` - CRITICAL/HIGH/MEDIUM/LOW based on worst finding
- `{{*_FINDINGS}}` - Findings grouped by severity
- `{{IMMEDIATE_ACTIONS}}` - Specific fixes for Critical/High
- `{{FILES_REVIEWED}}` - List of files examined

## Script Reference

### scan_secrets.py
Detects hardcoded credentials: API keys, passwords, tokens, private keys, connection strings.

```bash
python scripts/scan_secrets.py [path] [options]
  --severity LEVEL    # Minimum severity (CRITICAL, HIGH, MEDIUM, LOW)
  --include-examples  # Include findings from test/example files
  -o FILE            # Output to file
```

### check_dependencies.py
Checks Python (requirements.txt, Pipfile, pyproject.toml) and Node.js (package.json) dependencies against OSV.dev vulnerability database.

```bash
python scripts/check_dependencies.py [path] [options]
  --no-vuln-check    # Just list packages, skip vulnerability check
  --severity LEVEL   # Minimum severity to report
  -o FILE           # Output to file
```

### find_patterns.py
Scans Python and JavaScript/TypeScript for insecure code patterns: injection, XSS, weak crypto, etc.

```bash
python scripts/find_patterns.py [path] [options]
  --severity LEVEL   # Minimum severity
  --type TYPE        # Filter by vulnerability type
  -o FILE           # Output to file
```

## Output Format

Always provide both:
1. **Markdown report** - Structured findings with severity, location, description, and fix
2. **Inline code comments** (deep mode) - Add `# SECURITY:` annotations directly to files

## Severity Reference

See `references/severity-guide.md` for detailed severity definitions and context adjustments.

Quick reference:
- **CRITICAL**: RCE, SQLi, auth bypass, exposed prod secrets
- **HIGH**: Stored XSS, IDOR, command injection, broken access control
- **MEDIUM**: CSRF, weak crypto, missing headers, debug mode
- **LOW**: TODOs, best practices, minor info leaks
