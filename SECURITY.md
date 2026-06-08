# Security Policy

## Reporting a vulnerability in Mareu

Mareu itself may have security vulnerabilities. If you find one:

- **Do not open a public issue.**
- Email `qurnp@proton.me` or reach out via `@Phlegmelm` on GitHub with a
  description and reproduction steps.
- Allow 90 days for a fix before public disclosure.

We will credit researchers in the changelog unless anonymity is requested.

---

## Responsible disclosure statement (values, not contract)

Mareu is a tool for security research. The authors expect users to:

- Obtain authorization before testing systems they do not own.
- Follow coordinated disclosure norms when reporting findings to vendors.
- Not use this tool to harm third parties or production systems without consent.

This is a statement of values, not an enforceable contract. The authors
understand that the tool is dual-use, that most users are researchers acting in
good faith, and that the security community is better served by capable, honest
tooling than by tools that refuse to function.

Mareu does not maintain a list of prohibited targets and does not detect intent.
The one place it draws a line is the scaffold intent check (`mareu scaffold`):
it declines requests framed as "attack this specific named external host"
rather than "scaffold this bug class." That is a framing nudge, not an
enforcement mechanism — reframe in terms of the vulnerability and it proceeds.
