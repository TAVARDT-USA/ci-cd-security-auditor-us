# CI/CD Security Auditor & Pipeline Secret Leak Detector | TAVARDT United States

[![Licence](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI/CD Security](https://img.shields.io/badge/CI%2FCD-Security%20Hardened-00d26a.svg)](README.md)
[![Language](https://img.shields.io/badge/Language-English-green.svg)](README.md)
[![Engineering](https://img.shields.io/badge/TAVARDT-Cybersecurity-5b3cf5.svg)](https://ag.tavardt.com/us/ciberseguranca/)

Static defensive security auditor and policy linter for continuous integration pipelines (GitHub Actions). Identifies high-risk supply chain misconfigurations, vulnerable pull request triggers, excessive GITHUB_TOKEN permissions, and corporate secret exposure.

## Interactive Web Application

Access the browser-based live evaluation tool to audit your workflow YAML manifests in real time:

- [https://tavardt-usa.github.io/ci-cd-security-auditor-us/](https://tavardt-usa.github.io/ci-cd-security-auditor-us/)

---

## 1. Overview of the CI/CD Security Auditor

Continuous integration and automation runners have become primary targets for modern supply chain campaigns. Attackers leverage compromised developer credentials and misconfigured repository triggers to execute arbitrary code within runners and extract protected environment variables, cloud infrastructure tokens (AWS, GCP, Azure), and production deployment keys.

The TAVARDT CI/CD Security Auditor performs deterministic, passive inspection of workflow manifests, validating each directive against the OWASP Top 10 for CI/CD Security and the SLSA framework.

---

## 2. Inspected Risk Vectors

| Risk Vector | Pipeline Failure Mode | Technical Impact |
| :--- | :--- | :--- |
| **Insecure pull_request_target** | The workflow executes in the base repository context and checks out pull request code (`ref: ${{ github.event.pull_request.head.sha }}`). | Immediate authenticated Remote Code Execution (RCE) on the build runner with full access to repository secrets. |
| **Unrestricted write-all Permissions** | The pipeline specifies `permissions: write-all` or omits explicit root permission controls. | The default token inherits write access across code, releases, and packages, allowing malicious release tampering. |
| **Untrusted Shell Command Injection** | Untrusted context variables (such as `${{ github.event.issue.title }}`) are concatenated directly within `run:` script commands. | Enables shell syntax breakout and direct remote command injection on the runner operating system. |
| **Actions Pinned to Mutable Tags** | Directives use mutable tags (like `@v3` or `@main`) instead of immutable full commit SHAs. | Exposes the pipeline to supply chain poisoning should the upstream action author account be compromised. |
| **Hardcoded Secrets & Direct Exfiltration** | Occurrence of hardcoded private keys or `curl` commands transmitting `${{ secrets.* }}` to external endpoints. | Immediate compromise of connected cloud infrastructure and violation of security compliance baselines. |

---

## 3. Local Installation & CLI Execution

The scanner operates in terminal environments without external dependencies, utilizing Python 3 standard modules.

### Clone the Repository

```bash
git clone https://github.com/TAVARDT-USA/ci-cd-security-auditor-us.git
cd ci-cd-security-auditor-us
```

### Audit a Single Workflow YAML File

```bash
python scanner.py .github/workflows/deploy.yml
```

### Audit an Entire Workflow Directory with JSON Output

```bash
python scanner.py .github/workflows/ --json
```

---

## 4. Professional Hardening & Technical Support

If your audit revealed pipeline vulnerabilities, credential leakage, or the need for Zero Trust runner governance:

- **Institutional Portal:** [TAVARDT United States](https://ag.tavardt.com/us/ciberseguranca/)
- **Tools Center:** [TAVARDT Defensive Tools](https://tools.tavardt.com/us/)
- **Engineering Consultation:** [Incident Response & Architecture Review](https://ag.tavardt.com/us/contato/)

---

## License

Distributed under the open-source MIT License. See [`LICENSE`](LICENSE) for details.  
Copyright (c) 2026 TAVARDT United States.
