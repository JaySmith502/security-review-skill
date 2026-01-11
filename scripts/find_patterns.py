#!/usr/bin/env python3
"""
Scan code for insecure patterns and common vulnerabilities.
Supports Python, JavaScript/TypeScript, and general patterns.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Insecure patterns by language/category
# (pattern, vuln_type, severity, description, recommendation)
PATTERNS = {
    'python': [
        # Injection
        (r'exec\s*\(', 'code_injection', 'CRITICAL', 'Use of exec() can lead to code injection', 'Avoid exec() or use ast.literal_eval for data'),
        (r'eval\s*\(', 'code_injection', 'CRITICAL', 'Use of eval() can lead to code injection', 'Avoid eval() or use ast.literal_eval for data'),
        (r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', 'command_injection', 'CRITICAL', 'shell=True enables command injection', 'Use shell=False and pass args as list'),
        (r'os\.system\s*\(', 'command_injection', 'HIGH', 'os.system() is vulnerable to command injection', 'Use subprocess with shell=False'),
        (r'os\.popen\s*\(', 'command_injection', 'HIGH', 'os.popen() is vulnerable to command injection', 'Use subprocess with shell=False'),

        # SQL Injection
        (r'\.execute\s*\(\s*["\'][^"\']*%s', 'sql_injection', 'CRITICAL', 'String formatting in SQL query', 'Use parameterized queries'),
        (r'\.execute\s*\(\s*f["\']', 'sql_injection', 'CRITICAL', 'f-string in SQL query', 'Use parameterized queries'),
        (r'\.execute\s*\([^)]*\+', 'sql_injection', 'CRITICAL', 'String concatenation in SQL query', 'Use parameterized queries'),
        (r'\.execute\s*\([^)]*\.format\s*\(', 'sql_injection', 'CRITICAL', '.format() in SQL query', 'Use parameterized queries'),

        # Deserialization
        (r'pickle\.loads?\s*\(', 'deserialization', 'CRITICAL', 'Pickle deserialization can execute arbitrary code', 'Use JSON or validate source'),
        (r'yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)', 'deserialization', 'HIGH', 'yaml.load without safe Loader', 'Use yaml.safe_load() instead'),
        (r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.(?:Unsafe)?Loader', 'deserialization', 'HIGH', 'Using unsafe YAML Loader', 'Use yaml.SafeLoader'),

        # Cryptography
        (r'hashlib\.md5\s*\(', 'weak_crypto', 'MEDIUM', 'MD5 is cryptographically broken', 'Use SHA-256 or better for security'),
        (r'hashlib\.sha1\s*\(', 'weak_crypto', 'MEDIUM', 'SHA1 is cryptographically weak', 'Use SHA-256 or better'),
        (r'from\s+Crypto\.Cipher\s+import\s+DES', 'weak_crypto', 'HIGH', 'DES encryption is insecure', 'Use AES-256'),
        (r'random\.(random|randint|choice|randrange)\s*\(', 'weak_random', 'MEDIUM', 'random module not cryptographically secure', 'Use secrets module for security-sensitive randomness'),

        # Path traversal
        (r'open\s*\([^)]*\+', 'path_traversal', 'HIGH', 'String concatenation in file path', 'Validate/sanitize file paths'),
        (r'os\.path\.join\s*\([^)]*request', 'path_traversal', 'HIGH', 'User input in file path', 'Validate paths against allowed directories'),

        # XXE
        (r'etree\.parse\s*\(', 'xxe', 'MEDIUM', 'XML parsing may be vulnerable to XXE', 'Disable external entities in parser'),
        (r'xml\.dom\.minidom\.parse\s*\(', 'xxe', 'MEDIUM', 'XML parsing may be vulnerable to XXE', 'Use defusedxml library'),

        # Debug/Development
        (r'DEBUG\s*=\s*True', 'debug_enabled', 'MEDIUM', 'Debug mode enabled', 'Disable DEBUG in production'),
        (r'app\.run\s*\([^)]*debug\s*=\s*True', 'debug_enabled', 'MEDIUM', 'Flask debug mode enabled', 'Disable debug in production'),

        # SSRF
        (r'requests\.(get|post|put|delete|head)\s*\([^)]*\+', 'ssrf', 'HIGH', 'User-controllable URL', 'Validate URLs against allowlist'),
        (r'urllib\.request\.urlopen\s*\([^)]*\+', 'ssrf', 'HIGH', 'User-controllable URL', 'Validate URLs against allowlist'),

        # Hardcoded binding
        (r'\.run\s*\([^)]*host\s*=\s*["\']0\.0\.0\.0["\']', 'insecure_binding', 'MEDIUM', 'Binding to all interfaces', 'Bind to specific interface in production'),
    ],

    'javascript': [
        # Injection
        (r'eval\s*\(', 'code_injection', 'CRITICAL', 'Use of eval() can lead to code injection', 'Avoid eval() entirely'),
        (r'new\s+Function\s*\(', 'code_injection', 'CRITICAL', 'Function constructor can execute arbitrary code', 'Avoid dynamic code execution'),
        (r'setTimeout\s*\(\s*["\']', 'code_injection', 'HIGH', 'String in setTimeout can execute code', 'Pass function reference instead'),
        (r'setInterval\s*\(\s*["\']', 'code_injection', 'HIGH', 'String in setInterval can execute code', 'Pass function reference instead'),

        # XSS
        (r'\.innerHTML\s*=', 'xss', 'HIGH', 'innerHTML can lead to XSS', 'Use textContent or sanitize HTML'),
        (r'document\.write\s*\(', 'xss', 'HIGH', 'document.write can lead to XSS', 'Use DOM manipulation methods'),
        (r'\.outerHTML\s*=', 'xss', 'HIGH', 'outerHTML can lead to XSS', 'Use textContent or sanitize HTML'),
        (r'dangerouslySetInnerHTML', 'xss', 'HIGH', 'React dangerouslySetInnerHTML can lead to XSS', 'Sanitize HTML with DOMPurify'),

        # SQL Injection (Node.js)
        (r'\.query\s*\(\s*`[^`]*\$\{', 'sql_injection', 'CRITICAL', 'Template literal in SQL query', 'Use parameterized queries'),
        (r'\.query\s*\(\s*["\'][^"\']*\+', 'sql_injection', 'CRITICAL', 'String concatenation in SQL', 'Use parameterized queries'),

        # Command Injection
        (r'child_process\.exec\s*\(', 'command_injection', 'HIGH', 'exec() may allow command injection', 'Use execFile() with arguments array'),
        (r'child_process\.spawn\s*\([^)]*shell\s*:\s*true', 'command_injection', 'HIGH', 'shell: true enables command injection', 'Use shell: false'),

        # Prototype pollution
        (r'Object\.assign\s*\(\s*\{\}', 'prototype_pollution', 'MEDIUM', 'Object.assign may be vulnerable to prototype pollution', 'Validate object keys'),
        (r'\[.*\]\s*=(?!=)', 'prototype_pollution', 'LOW', 'Dynamic property assignment', 'Validate property names'),

        # Regex DoS
        (r'new\s+RegExp\s*\([^)]*\+', 'regex_dos', 'MEDIUM', 'User input in regex can cause ReDoS', 'Validate or escape regex input'),

        # Insecure randomness
        (r'Math\.random\s*\(\)', 'weak_random', 'MEDIUM', 'Math.random() not cryptographically secure', 'Use crypto.randomBytes()'),

        # CORS
        (r'Access-Control-Allow-Origin.*\*', 'insecure_cors', 'MEDIUM', 'Wildcard CORS allows any origin', 'Specify allowed origins'),
    ],

    'general': [
        # Hardcoded credentials (generic)
        (r'password\s*=\s*["\'][^"\']{4,}["\']', 'hardcoded_password', 'HIGH', 'Hardcoded password', 'Use environment variables'),
        (r'api[_-]?key\s*=\s*["\'][^"\']{10,}["\']', 'hardcoded_secret', 'HIGH', 'Hardcoded API key', 'Use environment variables'),

        # Insecure protocols
        (r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)', 'insecure_protocol', 'MEDIUM', 'HTTP instead of HTTPS', 'Use HTTPS for external connections'),
        (r'ftp://', 'insecure_protocol', 'MEDIUM', 'FTP is unencrypted', 'Use SFTP or FTPS'),
        (r'telnet://', 'insecure_protocol', 'HIGH', 'Telnet is unencrypted', 'Use SSH instead'),

        # Commented credentials
        (r'#.*password.*=', 'commented_secret', 'LOW', 'Commented password reference', 'Remove commented credentials'),
        (r'//.*password.*=', 'commented_secret', 'LOW', 'Commented password reference', 'Remove commented credentials'),

        # TODO security
        (r'(?i)todo.*(?:security|auth|password|credential|secret|key)', 'security_todo', 'LOW', 'Security-related TODO', 'Address security TODOs'),
        (r'(?i)fixme.*(?:security|auth|password|credential|secret|key)', 'security_todo', 'MEDIUM', 'Security-related FIXME', 'Address security FIXMEs'),
    ]
}

# File extensions to language mapping
EXTENSION_MAP = {
    '.py': 'python',
    '.pyw': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'javascript',
    '.tsx': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
}

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'env',
             'dist', 'build', '.idea', '.vscode', 'vendor'}


def get_language(filepath: Path) -> str | None:
    """Determine language from file extension."""
    return EXTENSION_MAP.get(filepath.suffix.lower())


def should_skip(filepath: Path) -> bool:
    """Check if path should be skipped."""
    for part in filepath.parts:
        if part in SKIP_DIRS:
            return True
    return False


def scan_file(filepath: Path) -> list[dict[str, Any]]:
    """Scan a file for insecure patterns."""
    findings = []
    lang = get_language(filepath)

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except (IOError, OSError):
        return findings

    # Get patterns to check
    patterns_to_check = PATTERNS.get('general', [])[:]
    if lang and lang in PATTERNS:
        patterns_to_check.extend(PATTERNS[lang])

    for line_num, line in enumerate(lines, 1):
        for pattern, vuln_type, severity, description, recommendation in patterns_to_check:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    'file': str(filepath),
                    'line': line_num,
                    'type': vuln_type,
                    'severity': severity,
                    'description': description,
                    'recommendation': recommendation,
                    'context': line.strip()[:120],
                    'language': lang or 'general'
                })

    return findings


def scan_directory(root_path: Path) -> list[dict[str, Any]]:
    """Recursively scan directory for insecure patterns."""
    all_findings = []

    for filepath in root_path.rglob('*'):
        if filepath.is_file() and not should_skip(filepath):
            # Only scan files with known extensions or common config files
            if filepath.suffix.lower() in EXTENSION_MAP or filepath.name in {'config.js', 'settings.py', '.env'}:
                findings = scan_file(filepath)
                all_findings.extend(findings)

    return all_findings


def main():
    parser = argparse.ArgumentParser(description='Scan code for insecure patterns')
    parser.add_argument('path', nargs='?', default='.', help='Path to scan (default: current directory)')
    parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], help='Minimum severity')
    parser.add_argument('--type', dest='vuln_type', help='Filter by vulnerability type')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')

    args = parser.parse_args()

    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    path = Path(args.path).resolve()

    if path.is_file():
        findings = scan_file(path)
    else:
        findings = scan_directory(path)

    # Filter by severity
    if args.severity:
        min_sev = severity_order[args.severity]
        findings = [f for f in findings if severity_order.get(f['severity'], 0) >= min_sev]

    # Filter by type
    if args.vuln_type:
        findings = [f for f in findings if f['type'] == args.vuln_type]

    # Sort by severity then file
    findings.sort(key=lambda x: (-severity_order.get(x['severity'], 0), x['file'], x['line']))

    result = {
        'scan_path': str(path),
        'total_findings': len(findings),
        'findings': findings,
        'summary': {
            'CRITICAL': len([f for f in findings if f['severity'] == 'CRITICAL']),
            'HIGH': len([f for f in findings if f['severity'] == 'HIGH']),
            'MEDIUM': len([f for f in findings if f['severity'] == 'MEDIUM']),
            'LOW': len([f for f in findings if f['severity'] == 'LOW']),
        },
        'by_type': {}
    }

    # Group by type
    for f in findings:
        t = f['type']
        if t not in result['by_type']:
            result['by_type'][t] = 0
        result['by_type'][t] += 1

    output = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
    else:
        print(output)

    if result['summary']['CRITICAL'] > 0:
        sys.exit(2)
    elif result['summary']['HIGH'] > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
