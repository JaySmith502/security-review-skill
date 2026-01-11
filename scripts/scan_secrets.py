#!/usr/bin/env python3
"""
Scan files for hardcoded secrets, API keys, and credentials.
Outputs JSON with findings including file, line, type, and severity.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Patterns for detecting secrets (pattern, type, severity, description)
SECRET_PATTERNS = [
    # API Keys
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'api_key', 'HIGH', 'Hardcoded API key'),
    (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'secret_key', 'CRITICAL', 'Hardcoded secret key'),

    # AWS
    (r'AKIA[0-9A-Z]{16}', 'aws_access_key', 'CRITICAL', 'AWS Access Key ID'),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', 'aws_secret', 'CRITICAL', 'AWS Secret Access Key'),

    # Google Cloud
    (r'AIza[0-9A-Za-z\-_]{35}', 'google_api_key', 'HIGH', 'Google API Key'),
    (r'"type"\s*:\s*"service_account"', 'gcp_service_account', 'HIGH', 'GCP Service Account JSON'),

    # GitHub/GitLab
    (r'gh[pousr]_[A-Za-z0-9_]{36,}', 'github_token', 'CRITICAL', 'GitHub Token'),
    (r'glpat-[A-Za-z0-9\-_]{20,}', 'gitlab_token', 'CRITICAL', 'GitLab Personal Access Token'),

    # Database
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', 'password', 'CRITICAL', 'Hardcoded password'),
    (r'(?i)mongodb(\+srv)?://[^:]+:[^@]+@', 'mongodb_uri', 'CRITICAL', 'MongoDB connection string with credentials'),
    (r'(?i)postgres(ql)?://[^:]+:[^@]+@', 'postgres_uri', 'CRITICAL', 'PostgreSQL connection string with credentials'),
    (r'(?i)mysql://[^:]+:[^@]+@', 'mysql_uri', 'CRITICAL', 'MySQL connection string with credentials'),
    (r'(?i)redis://:[^@]+@', 'redis_uri', 'HIGH', 'Redis connection string with password'),

    # JWT/Tokens
    (r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+', 'jwt_token', 'HIGH', 'JWT Token'),
    (r'(?i)(bearer|token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?', 'bearer_token', 'HIGH', 'Bearer/Auth token'),

    # Private Keys
    (r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', 'private_key', 'CRITICAL', 'Private key'),
    (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'pgp_private_key', 'CRITICAL', 'PGP Private key'),

    # Slack/Discord
    (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', 'slack_token', 'CRITICAL', 'Slack Token'),
    (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+', 'slack_webhook', 'HIGH', 'Slack Webhook URL'),
    (r'https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+', 'discord_webhook', 'MEDIUM', 'Discord Webhook URL'),

    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24,}', 'stripe_secret', 'CRITICAL', 'Stripe Secret Key'),
    (r'rk_live_[0-9a-zA-Z]{24,}', 'stripe_restricted', 'HIGH', 'Stripe Restricted Key'),

    # Twilio
    (r'SK[0-9a-fA-F]{32}', 'twilio_api_key', 'HIGH', 'Twilio API Key'),

    # SendGrid
    (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', 'sendgrid_key', 'HIGH', 'SendGrid API Key'),

    # Generic patterns
    (r'(?i)(client[_-]?secret)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'client_secret', 'HIGH', 'OAuth client secret'),
    (r'(?i)(auth[_-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'auth_token', 'HIGH', 'Authentication token'),
]

# Files/directories to skip
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'env', '.env',
             'dist', 'build', '.idea', '.vscode', 'vendor', 'packages', '.tox'}
SKIP_EXTENSIONS = {'.pyc', '.pyo', '.so', '.dll', '.exe', '.bin', '.jpg', '.jpeg',
                   '.png', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot',
                   '.mp3', '.mp4', '.avi', '.mov', '.pdf', '.zip', '.tar', '.gz'}

# Files that commonly contain example/fake secrets
EXAMPLE_FILES = {'example', 'sample', 'test', 'mock', 'fake', 'dummy', 'template'}


def should_skip_file(filepath: Path) -> bool:
    """Check if file should be skipped."""
    # Skip binary/media files
    if filepath.suffix.lower() in SKIP_EXTENSIONS:
        return True

    # Skip files in ignored directories
    for part in filepath.parts:
        if part in SKIP_DIRS:
            return True

    return False


def is_likely_example(filepath: Path, line: str) -> bool:
    """Check if the finding is likely an example/placeholder."""
    name_lower = filepath.stem.lower()

    # Check filename for example indicators
    if any(indicator in name_lower for indicator in EXAMPLE_FILES):
        return True

    # Check line content for placeholder patterns
    placeholder_patterns = [
        r'your[_-]?api[_-]?key',
        r'xxx+',
        r'placeholder',
        r'example',
        r'<[^>]+>',  # <YOUR_KEY_HERE>
        r'\${[^}]+}',  # ${API_KEY}
        r'\{\{[^}]+\}\}',  # {{api_key}}
    ]

    for pattern in placeholder_patterns:
        if re.search(pattern, line, re.IGNORECASE):
            return True

    return False


def scan_file(filepath: Path) -> list[dict[str, Any]]:
    """Scan a single file for secrets."""
    findings = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except (IOError, OSError):
        return findings

    for line_num, line in enumerate(lines, 1):
        for pattern, secret_type, severity, description in SECRET_PATTERNS:
            matches = re.finditer(pattern, line)
            for match in matches:
                # Skip likely examples
                if is_likely_example(filepath, line):
                    continue

                # Mask the actual secret value
                matched_text = match.group(0)
                if len(matched_text) > 10:
                    masked = matched_text[:5] + '***' + matched_text[-3:]
                else:
                    masked = '***'

                findings.append({
                    'file': str(filepath),
                    'line': line_num,
                    'type': secret_type,
                    'severity': severity,
                    'description': description,
                    'matched': masked,
                    'context': line.strip()[:100]
                })

    return findings


def scan_directory(root_path: Path, include_examples: bool = False) -> list[dict[str, Any]]:
    """Scan directory recursively for secrets."""
    all_findings = []

    for filepath in root_path.rglob('*'):
        if filepath.is_file() and not should_skip_file(filepath):
            findings = scan_file(filepath)
            if not include_examples:
                findings = [f for f in findings if not is_likely_example(filepath, f.get('context', ''))]
            all_findings.extend(findings)

    return all_findings


def main():
    parser = argparse.ArgumentParser(description='Scan for hardcoded secrets and credentials')
    parser.add_argument('path', nargs='?', default='.', help='Path to scan (default: current directory)')
    parser.add_argument('--include-examples', action='store_true', help='Include findings from example/test files')
    parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], help='Minimum severity to report')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')

    args = parser.parse_args()

    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    min_severity = severity_order.get(args.severity, 0)

    path = Path(args.path).resolve()

    if path.is_file():
        findings = scan_file(path)
    else:
        findings = scan_directory(path, args.include_examples)

    # Filter by severity
    if min_severity:
        findings = [f for f in findings if severity_order.get(f['severity'], 0) >= min_severity]

    # Sort by severity (critical first) then by file
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
        }
    }

    output = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
    else:
        print(output)

    # Exit with error code if critical findings
    if result['summary']['CRITICAL'] > 0:
        sys.exit(2)
    elif result['summary']['HIGH'] > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
