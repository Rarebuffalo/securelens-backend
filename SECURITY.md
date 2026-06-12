# Security Policy

We take the security of SecureLens and the codebases it scans seriously. This document details how to report vulnerabilities, which versions are supported, and our disclosure process.

---

## Supported Versions

Security updates are actively backported to the current major version. We recommend all users upgrade to the latest stable release of SecureLens to receive security patches.

| Version | Supported |
|---|---|
| 1.x.x | Yes |
| < 1.0.0 | No |

---

## Reporting a Vulnerability

If you discover a security vulnerability in SecureLens, please do not open a public GitHub issue. Public issues allow zero-day exploits to be used before patches are available.

Instead, report vulnerabilities through one of the following methods:
* **Private Vulnerability Reporting:** Submit a draft security advisory directly on GitHub via the Security tab.
* **Email:** Send details of the issue to security@securelens.io.

### What to Include in Your Report

To help us triage and patch the issue quickly, please include:
* A detailed description of the vulnerability and its potential impact.
* Step-by-step instructions or a proof-of-concept (PoC) to reproduce the issue.
* The version of SecureLens (both backend and CLI) and dependencies used.
* Any potential mitigation steps you have identified.

---

## Our Security Response Process

Once a vulnerability report is received:
1. **Acknowledgement:** We will acknowledge receipt of your report within 48 hours.
2. **Triage:** We will investigate and verify the vulnerability. We may contact you for further details or clarification.
3. **Patch Development:** We will develop a fix for the vulnerability.
4. **Coordination & Disclosure:** We will work with you to coordinate a release date for the security update. We aim to publish a patched release and advisory within 30 days of validation.
