# Security Policy

## Reporting a Vulnerability (Private Disclosure)

If you discover an undisclosed **security vulnerability** related to this repository, its code, or any SAML-related library, **please do not file a public issue or pull request.** Instead, report it to us **privately** so we can investigate and fix it safely and responsibly.

- **Email:** [security@stytch.com](mailto:security@stytch.com)
- **Acknowledgment:** We aim to acknowledge your report within **2 business days**.
- **Remediation:** Stytch commits to triaging, resolving, and coordinating disclosure in alignment with our [Responsible Disclosure Policy](https://stytch.com/docs/resources/security-and-trust/security).

### What to Include in Your Report

To help us assess the issue quickly:

- A clear description of the vulnerability and its potential impact.
- Steps to reproduce or proof-of-concept code, if available.
- Affected components or dependencies, including versions.
- Logs, stack traces, or data samples (no personal or user data).
- Whether the issue has already been disclosed elsewhere.

## Third-Party SAML Library Vulnerabilities

SAMLShield exists to protect applications from vulnerabilities in **third-party SAML libraries**. We strongly encourage reports of vulnerabilities you discover in libraries such as:

- `python-saml` / OneLogin SAML Toolkit
- `xmlsec` bindings
- Other SAML processors or middleware used in the ecosystem

Please email these reports to [security@stytch.com](mailto:security@stytch.com) as described above. Clearly indicate that the issue affects a **third-party SAML library** and include reproduction details and impact assessment. We may coordinate with the upstream maintainers and/or implement mitigations within SAMLShield to protect affected users.

## Publicly Disclosed Vulnerabilities and Improvements

For issues that are already public or not security-sensitive:

- If a vulnerability has already been disclosed elsewhere, feel free to open an issue or PR with links to public advisories (e.g., CVEs, blog posts).
- For general bug fixes, improvements, or tests, submit a pull request with documentation and references.
- If unsure whether an issue is sensitive, please report it **privately first**. We’ll advise on how to proceed.

## Guidelines for Safe Security Research

We appreciate responsible security research and welcome contributions from the community. Please follow these principles:

- Only test against accounts or systems you own.
- Do not attempt to access, modify, or destroy data belonging to others.
- Avoid any denial-of-service (DoS), spam, or social engineering techniques.
- Do not target Stytch infrastructure or employees.
- Respect Coordinated Vulnerability Disclosure timelines.

Stytch will not pursue legal action against researchers who act in good faith and follow this policy.

## Our Commitment

- We will acknowledge valid reports within **2 business days**.
- We aim to resolve critical issues within **30 days** or faster where possible.
- We will keep you updated throughout the process.
- We will credit you for your discovery (with permission) when disclosure is appropriate.
- We follow **Coordinated Vulnerability Disclosure** practices and appreciate your collaboration in keeping users safe.

---

Thank you for helping secure the SAMLShield project and the broader SAML ecosystem.
