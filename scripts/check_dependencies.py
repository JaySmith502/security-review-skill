#!/usr/bin/env python3
"""
Check project dependencies for known vulnerabilities.
Supports Python (requirements.txt, Pipfile, pyproject.toml) and Node.js (package.json).
Uses OSV.dev API for vulnerability data.
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

OSV_API = "https://api.osv.dev/v1/query"


def parse_requirements_txt(filepath: Path) -> list[dict[str, str]]:
    """Parse requirements.txt file."""
    packages = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # Parse package==version or package>=version etc.
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*([=<>!~]+)?\s*([0-9a-zA-Z.*]+)?', line)
                if match:
                    packages.append({
                        'name': match.group(1),
                        'version': match.group(3) or 'unknown',
                        'ecosystem': 'PyPI'
                    })
    except (IOError, OSError):
        pass
    return packages


def parse_package_json(filepath: Path) -> list[dict[str, str]]:
    """Parse package.json file."""
    packages = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            for dep_type in ['dependencies', 'devDependencies']:
                deps = data.get(dep_type, {})
                for name, version in deps.items():
                    # Clean version string (remove ^, ~, etc.)
                    clean_version = re.sub(r'^[\^~>=<]+', '', str(version))
                    packages.append({
                        'name': name,
                        'version': clean_version,
                        'ecosystem': 'npm'
                    })
    except (IOError, OSError, json.JSONDecodeError):
        pass
    return packages


def parse_pyproject_toml(filepath: Path) -> list[dict[str, str]]:
    """Parse pyproject.toml dependencies (basic parsing without tomllib)."""
    packages = []
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            # Simple regex for dependencies list
            deps_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if deps_match:
                deps_str = deps_match.group(1)
                for line in deps_str.split('\n'):
                    line = line.strip().strip(',').strip('"').strip("'")
                    if line:
                        match = re.match(r'^([a-zA-Z0-9_-]+)\s*([=<>!~]+)?\s*([0-9a-zA-Z.*]+)?', line)
                        if match:
                            packages.append({
                                'name': match.group(1),
                                'version': match.group(3) or 'unknown',
                                'ecosystem': 'PyPI'
                            })
    except (IOError, OSError):
        pass
    return packages


def parse_pipfile(filepath: Path) -> list[dict[str, str]]:
    """Parse Pipfile dependencies (basic parsing)."""
    packages = []
    try:
        with open(filepath, 'r') as f:
            in_packages = False
            for line in f:
                line = line.strip()
                if line in ['[packages]', '[dev-packages]']:
                    in_packages = True
                    continue
                elif line.startswith('['):
                    in_packages = False
                    continue
                if in_packages and '=' in line:
                    parts = line.split('=', 1)
                    name = parts[0].strip()
                    version = parts[1].strip().strip('"').strip("'")
                    if version == '*':
                        version = 'unknown'
                    packages.append({
                        'name': name,
                        'version': version,
                        'ecosystem': 'PyPI'
                    })
    except (IOError, OSError):
        pass
    return packages


def check_osv(package: dict[str, str]) -> list[dict[str, Any]]:
    """Query OSV.dev API for vulnerabilities."""
    vulnerabilities = []

    query = {
        "package": {
            "name": package['name'],
            "ecosystem": package['ecosystem']
        }
    }

    # Include version if known
    if package['version'] != 'unknown':
        query["version"] = package['version']

    try:
        req = urllib.request.Request(
            OSV_API,
            data=json.dumps(query).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode('utf-8'))
            vulns = result.get('vulns', [])
            for vuln in vulns:
                severity = 'MEDIUM'  # Default
                # Try to extract severity from CVSS
                for sev in vuln.get('severity', []):
                    if 'score' in str(sev).lower():
                        score = float(re.search(r'[\d.]+', str(sev.get('score', '5'))).group())
                        if score >= 9.0:
                            severity = 'CRITICAL'
                        elif score >= 7.0:
                            severity = 'HIGH'
                        elif score >= 4.0:
                            severity = 'MEDIUM'
                        else:
                            severity = 'LOW'
                        break

                # Check for CRITICAL/HIGH keywords in summary
                summary = vuln.get('summary', '').lower()
                if any(kw in summary for kw in ['remote code execution', 'rce', 'arbitrary code']):
                    severity = 'CRITICAL'
                elif any(kw in summary for kw in ['sql injection', 'xss', 'authentication bypass']):
                    severity = 'HIGH'

                vulnerabilities.append({
                    'id': vuln.get('id'),
                    'summary': vuln.get('summary', 'No summary available'),
                    'severity': severity,
                    'aliases': vuln.get('aliases', []),
                    'references': [r.get('url') for r in vuln.get('references', [])[:3]],
                    'package': package['name'],
                    'ecosystem': package['ecosystem'],
                    'affected_version': package['version']
                })
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
        pass

    return vulnerabilities


def find_dependency_files(root_path: Path) -> dict[str, list[Path]]:
    """Find all dependency files in the project."""
    files = {
        'requirements.txt': [],
        'package.json': [],
        'pyproject.toml': [],
        'Pipfile': []
    }

    skip_dirs = {'node_modules', '.git', 'venv', '.venv', 'env', '__pycache__'}

    for filepath in root_path.rglob('*'):
        if any(skip in filepath.parts for skip in skip_dirs):
            continue
        if filepath.name in files:
            files[filepath.name].append(filepath)

    return files


def scan_dependencies(root_path: Path, check_vulnerabilities: bool = True) -> dict[str, Any]:
    """Scan all dependencies in the project."""
    dep_files = find_dependency_files(root_path)
    all_packages = []
    all_vulnerabilities = []

    # Parse each dependency file type
    for req_file in dep_files['requirements.txt']:
        packages = parse_requirements_txt(req_file)
        for pkg in packages:
            pkg['source_file'] = str(req_file)
        all_packages.extend(packages)

    for pkg_file in dep_files['package.json']:
        packages = parse_package_json(pkg_file)
        for pkg in packages:
            pkg['source_file'] = str(pkg_file)
        all_packages.extend(packages)

    for pyproj_file in dep_files['pyproject.toml']:
        packages = parse_pyproject_toml(pyproj_file)
        for pkg in packages:
            pkg['source_file'] = str(pyproj_file)
        all_packages.extend(packages)

    for pipfile in dep_files['Pipfile']:
        packages = parse_pipfile(pipfile)
        for pkg in packages:
            pkg['source_file'] = str(pipfile)
        all_packages.extend(packages)

    # Check for vulnerabilities
    if check_vulnerabilities:
        for pkg in all_packages:
            vulns = check_osv(pkg)
            all_vulnerabilities.extend(vulns)

    # Sort vulnerabilities by severity
    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    all_vulnerabilities.sort(key=lambda x: -severity_order.get(x['severity'], 0))

    return {
        'scan_path': str(root_path),
        'dependency_files_found': {k: [str(p) for p in v] for k, v in dep_files.items() if v},
        'total_packages': len(all_packages),
        'packages': all_packages,
        'total_vulnerabilities': len(all_vulnerabilities),
        'vulnerabilities': all_vulnerabilities,
        'summary': {
            'CRITICAL': len([v for v in all_vulnerabilities if v['severity'] == 'CRITICAL']),
            'HIGH': len([v for v in all_vulnerabilities if v['severity'] == 'HIGH']),
            'MEDIUM': len([v for v in all_vulnerabilities if v['severity'] == 'MEDIUM']),
            'LOW': len([v for v in all_vulnerabilities if v['severity'] == 'LOW']),
        }
    }


def main():
    parser = argparse.ArgumentParser(description='Check dependencies for known vulnerabilities')
    parser.add_argument('path', nargs='?', default='.', help='Path to scan (default: current directory)')
    parser.add_argument('--no-vuln-check', action='store_true', help='Skip vulnerability check (just list packages)')
    parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], help='Minimum severity to report')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')

    args = parser.parse_args()

    path = Path(args.path).resolve()
    result = scan_dependencies(path, not args.no_vuln_check)

    # Filter by severity
    if args.severity:
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        min_sev = severity_order[args.severity]
        result['vulnerabilities'] = [v for v in result['vulnerabilities']
                                     if severity_order.get(v['severity'], 0) >= min_sev]
        result['total_vulnerabilities'] = len(result['vulnerabilities'])

    output = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
    else:
        print(output)

    # Exit codes
    if result['summary']['CRITICAL'] > 0:
        sys.exit(2)
    elif result['summary']['HIGH'] > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
