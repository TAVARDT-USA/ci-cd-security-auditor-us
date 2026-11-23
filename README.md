# CI/CD Security Auditor & Software Supply Chain Hardening Hub

Corporate defensive engineering guide and cybersecurity hub for pipeline hardening (GitHub Actions, GitLab CI) and Software Supply Chain risk mitigation.

***

## Executive Summary

This repository delivers the defensive security architecture specification, comparative pipeline posture diagnostics, and a deterministic Python CLI utility for structural verification of CI/CD YAML manifests.

* **Organization:** TAVARDT-USA
* **Jurisdiction:** USA
* **Official Hub:** [https://tavardt-usa.github.io/ci-cd-security-auditor-us/](https://tavardt-usa.github.io/ci-cd-security-auditor-us/)
* **Reference Standards:** CIS Software Supply Chain Security Guide, OWASP Top 10 for CI/CD, SLSA Framework Level 3.

***

## Critical Vectors Analyzed

1. **Privileged Triggers (`pull_request_target`):** Detection of untrusted fork checkouts in workflows with secret access.
2. **Excessive Global Permissions (`write-all`):** Enforcement of declarative least-privilege tokens (`permissions: contents: read`).
3. **Unpinned Third-Party Actions:** Identification of mutable tags (`@v3`, `@main`) and automated conversion to immutable 40-character commit SHAs.
4. **Shell Command Injections:** Sanitization of user-controlled context variables in `run:` blocks.
5. **Egress Network Filtering:** Monitoring and blocking of unauthorized outbound connections during runner execution.

***

## CLI Utility Execution

To execute the deterministic audit directly in your local terminal or CI/CD runner:

```bash
# 1. Download official audit script
curl -sO https://raw.githubusercontent.com/TAVARDT-USA/ci-cd-security-auditor-us/main/audit_ci_cd_security.py

# 2. Run static analysis against local workflows
python audit_ci_cd_security.py .github/workflows/
```

***

## Governance & Compliance

Engineered by the **TAVARDT USA** Cybersecurity Division. All rights reserved.
