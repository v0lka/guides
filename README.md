# Guides — Guides on Security in Development

A collection of practical guides for developers who want to write secure code without deep-diving into AppSec. No pentesting expertise required — just engineering discipline and language idioms.

---

## Secure Go Development

[English](secure-go-development/secure-go-development_en.md) · [Русский](secure-go-development/secure-go-development_ru.md)

A practical guide for Go developers covering 13 sections mapped to the **OWASP Top 10 for Web Applications** ([2021](https://owasp.org/Top10/2021/) / [2025](https://owasp.org/Top10/2025/)). Each section follows the same structure:

- **How to do it in Go** — idioms and code examples
- **Libraries & Tools** — what to use off the shelf
- **Rules** — a short checklist you can use as a PR review list (including PRs from AI agents)

### Topics Covered

| # | Topic | OWASP |
|---|-------|-------|
| 1 | Access Control | A01 |
| 2 | Cryptographic Failures | A02 |
| 3 | Injection | A03 |
| 4 | Insecure Design | A04 |
| 5 | Security Misconfiguration | A05 |
| 6 | Vulnerable & Outdated Components | A06 |
| 7 | Identification & Authentication Failures | A07 |
| 8 | Software & Data Integrity Failures | A08 |
| 9 | Security Logging & Monitoring Failures | A09 |
| 10 | SSRF | A10 |
| 11 | Open Redirect | — |
| 12 | SSRF / External API Integration | — |
| 13 | AI-Assisted Development Risks | — |

### Companion Project

Vulnerability examples that the guide trains against are available in the educational project **[ShopVault](https://github.com/v0lka/ShopVault)** — each section references its category and contains both vulnerable and secure code.

### Core Principle

> **A vulnerability is a bug.** If you catch it in review, cover it with tests, and fix it before release, a significant portion of AppSec problems are closed long before the first pentester or SAST/DAST scanner gets to them.

## License

All materials are licensed under [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/) (CC BY-SA 4.0).
