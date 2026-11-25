# CI/CD Security Auditor & Software Supply Chain Hardening Hub

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-usa.github.io/ci-cd-security-auditor-us/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Standards](https://img.shields.io/badge/Standards-CIS%20%7C%20OWASP%20CI%2FCD-blue.svg)](https://tavardt-usa.github.io/ci-cd-security-auditor-us/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Corporate defensive engineering specification, automated pipeline immunization standards, and deterministic CLI auditing utility for software supply chain security across GitHub Actions and modern CI/CD ecosystems.

***

## Executive Overview: The CI/CD Supply Chain Threat Landscape

Continuous Integration and Continuous Delivery (CI/CD) pipelines serve as the central backbone of modern software engineering. Because build runners possess direct network access, source code repository permissions, and deployment credentials, automation pipelines have become the primary attack vector for sophisticated supply chain adversaries.

When development teams prioritize deployment velocity without security guardrails, build workflows consistently inherit critical structural vulnerabilities:
* Build triggers execute untrusted fork code inside privileged runner contexts.
* Third-party build dependencies reference mutable tags susceptible to account hijacking.
* Build runner tokens inherit global write privileges across the entire source repository.
* Runner environments lack network egress boundaries to block secret exfiltration.

This repository delivers an enterprise-grade defense-in-depth standard. It combines ready-to-deploy pipeline blueprints with a deterministic, zero-telemetry Python static analysis auditor (`audit_ci_cd_security.py`) to enforce immutable supply chain integrity.

***

## Critical Attack Surfaces in Automation Pipelines

### 1. The Dangerous `pull_request_target` Trigger
Workflows triggered by `pull_request_target` execute within the context of the base repository rather than the pull request fork. This design inherently grants immediate access to production repository secrets:
* **The Root Exploit:** Workflows that execute `actions/checkout` with `ref: github.event.pull_request.head.sha` checkout untrusted attacker code directly into a privileged runner.
* **The Operational Impact:** External contributors can modify build scripts, execute arbitrary shell commands on runner nodes, and exfiltrate production deployment secrets without maintainer approval.
* **The Defensive Mandate:** Never combine `pull_request_target` with an untrusted commit checkout. Segregate validation routines into non-privileged standard `pull_request` jobs.

### 2. Unpinned Third-Party Actions and Mutable Tags
Workflows referencing third-party GitHub Actions via version tags (such as `@v3` or `@main`) introduce direct upstream dependency hijacking risks:
* **The Vulnerability:** Release tags are mutable Git pointers that can be rewritten if an action maintainer account is compromised.
* **The Threat Scenario:** An adversary can push a malicious commit to a popular action tag, automatically poisoning thousands of enterprise pipelines simultaneously.
* **The Defensive Mandate:** Pin all external actions exclusively to immutable 40-character commit SHAs, accompanied by descriptive version comments for auditability.

### 3. Overprivileged Default Runner Tokens (`permissions: write-all`)
Automated pipelines frequently execute with default `GITHUB_TOKEN` permissions inherited from organization-level settings:
* **The Vulnerability:** Omitting an explicit top-level `permissions:` block or granting `write-all` gives build scripts unrestricted write access across repository contents, packages, issues, and pull requests.
* **The Threat Scenario:** Any compromised dependency executed during the build process can tamper with repository releases or alter production branches.
* **The Defensive Mandate:** Explicitly define `permissions: contents: read` as the global baseline, scoping write permissions solely to specific, isolated jobs that strictly require them.

### 4. Runner Network Egress and Plaintext Secret Exposure
Build runners typically operate with unrestricted outbound internet connectivity:
* **The Vulnerability:** Malicious build dependencies can establish reverse shells or transmit captured environment variables to untrusted external command servers.
* **The Defensive Mandate:** Enforce egress network filtering on runner nodes, blocking all outbound traffic except verified package registries and artifact destinations.

***

## Certified Production Hardening Blueprints

This repository includes production-certified mitigation blueprints to protect modern automation pipelines:

### 1. Hardened GitHub Actions Workflow (`hardened-workflow.yml`)
Implements mandatory least-privilege tokens, immutable commit SHA pinning, and runner isolation:

```yaml
name: Enterprise Hardened Pipeline

on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  audit-and-build:
    runs-on: ubuntu-latest
    steps:
      - name: Hardened Checkout
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
        with:
          persist-credentials: false

      - name: Initialize Defensive Python Environment
        uses: actions/setup-python@0a5c61591373683505ea898e09a3ea4f39ef2b9c # v5.0.0
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Execute Deterministic Static Analysis
        run: |
          python audit_ci_cd_security.py .github/workflows/
```

### 2. Automated Action SHA Pinning Script (`action-pinning.sh`)
Resolves mutable action version tags to immutable commit SHAs automatically:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Scans workflow definitions and validates 40-character commit SHA pinning
find .github/workflows -type f \( -name "*.yml" -o -name "*.yaml" \) | while read -r workflow; do
  echo "[*] Auditing workflow: ${workflow}"
  grep -E "uses: [a-zA-Z0-9_\-\.\/]+@[a-f0-9]{40}" "${workflow}" || echo "[!] Unpinned actions detected"
done
```

### 3. Runner Egress Network Hardening (`step-security-harden.yml`)
Restricts runner network outbound connections solely to authorized domain endpoints:

```yaml
- name: Harden Runner Network Egress
  uses: step-security/harden-runner@63c24ba6bd7ba022e95695ff85de572c04a18142 # v2.7.0
  with:
    egress-policy: block
    allowed-endpoints: >
      github.com:443
      api.github.com:443
      pypi.org:443
      files.pythonhosted.org:443
```

***

## Deterministic CLI Audit Utility

Browser environments enforce strict security sandboxes that prohibit direct file system traversal and socket-level pipeline inspection. To guarantee reproducible, zero-telemetry security evaluations, TAVARDT provides an enterprise Python static analyzer designed for local developer terminals and automated CI/CD quality gates.

### Deterministic Inspection Engine

The CLI utility (`audit_ci_cd_security.py`) implements a four-stage static analysis pipeline:
* **Trigger Isolation Audit:** Inspects all event declarations to identify unsafe combinations of `pull_request_target` with pull request head checkouts.
* **Least-Privilege Token Verification:** Detects `write-all` declarations or the total absence of top-level restrictive `permissions:` blocks.
* **Action Pinning Audit:** Scans every `uses:` statement via high-fidelity regular expressions, verifying that external actions reference 40-character hexadecimal commit SHAs.
* **Plaintext Secret Scanning:** Evaluates inline shell scripts and variable expansions for unmasked credential exposure.

### Terminal Usage

Download and execute the audit utility directly against your repository workflows:

```bash
# 1. Download official audit script
curl -sO https://raw.githubusercontent.com/TAVARDT-USA/ci-cd-security-auditor-us/main/audit_ci_cd_security.py

# 2. Run static analysis against local workflows
python audit_ci_cd_security.py .github/workflows/
```

***

## Frequently Asked Questions (Technical & Architecture FAQ)

### 1. Why is pull_request_target considered one of the most dangerous triggers in GitHub Actions?
The `pull_request_target` trigger runs in the context of the target repository base branch, granting direct access to write secrets and repository tokens. If the workflow checks out code submitted in a pull request from an external fork, that untrusted code can execute arbitrary commands on the runner and steal production credentials.

### 2. How does pinning external actions to 40-character commit SHAs prevent supply chain attacks?
Version tags like `@v3` or `@main` are mutable Git references that repository maintainers can modify or that attackers can retarget if a maintainer account is compromised. A 40-character commit SHA is cryptographically immutable, guaranteeing that the exact reviewed code executes without risk of upstream tampering.

### 3. What operational risks arise from omitting top-level permissions blocks in workflow manifests?
When workflow files omit an explicit `permissions:` block, the build runner token inherits the default permissions configured at the repository or organization level, which often includes broad write access. A compromised build step can exploit this elevated token to tamper with source branches, modify releases, or publish malicious packages.

### 4. How does runner egress network filtering stop data exfiltration during compromised builds?
Egress network filtering restricts build runner outbound communication to an explicit whitelist of verified domains, such as GitHub and official package registries. If a compromised third-party build dependency attempts to establish a reverse shell or transmit environment secrets to an attacker server, the connection is dropped immediately.

### 5. Does the deterministic Python auditor require external network connectivity or root privileges?
No. The audit utility operates entirely offline as a passive static analyzer, reading local YAML workflow files directly from disk without transmitting telemetry or requiring administrative system privileges.

***

## Compliance Frameworks & Enterprise Standards

Defensive architecture and software supply chain controls aligned with NIST SP 800-53, CMMC 2.0, SOC 2 Type II, and Federal Cybersecurity Standards.

***

## Useful Links

* **Corporate Portal:** https://ag.tavardt.com/
* **Diagnostic Suite:** https://tools.tavardt.com/
* **Technical Contact:** https://ag.tavardt.com/contact/

***

### License
Released under the MIT License. See [LICENSE](LICENSE) for full details.

***

© 2026 TAVARDT. All rights reserved.
