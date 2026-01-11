# Security Review Report

**Project:** {{PROJECT_NAME}}
**Date:** {{DATE}}
**Review Type:** {{REVIEW_TYPE}}
**Reviewer:** Claude Security Review

---

## Executive Summary

{{SUMMARY}}

### Risk Overview

| Severity | Count |
|----------|-------|
| CRITICAL | {{CRITICAL_COUNT}} |
| HIGH | {{HIGH_COUNT}} |
| MEDIUM | {{MEDIUM_COUNT}} |
| LOW | {{LOW_COUNT}} |

**Overall Risk Level:** {{OVERALL_RISK}}

---

## Critical Findings

{{CRITICAL_FINDINGS}}

---

## High-Priority Findings

{{HIGH_FINDINGS}}

---

## Medium-Priority Findings

{{MEDIUM_FINDINGS}}

---

## Low-Priority Findings

{{LOW_FINDINGS}}

---

## Recommendations

### Immediate Actions (Critical/High)

{{IMMEDIATE_ACTIONS}}

### Short-Term Improvements (Medium)

{{SHORT_TERM}}

### Long-Term Enhancements (Low/Best Practices)

{{LONG_TERM}}

---

## Appendix

### Files Reviewed

{{FILES_REVIEWED}}

### Tools Used

- `scan_secrets.py` - Credential and secret detection
- `check_dependencies.py` - Dependency vulnerability check (OSV.dev)
- `find_patterns.py` - Insecure code pattern detection
- Manual code review against OWASP Top 10

### Limitations

{{LIMITATIONS}}
