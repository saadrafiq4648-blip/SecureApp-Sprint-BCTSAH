# Protection Needs Elicitation (PNE) & CIA Mapping Report

## 1. Asset Inventory

| ID | Asset | Type | Owner | Value / Impact if Compromised |
| :--- | :--- | :--- | :--- | :--- |
| A-01 | User credentials (password hashes) | Data | User | Account takeover; High |
| A-02 | Session tokens / cookies | Data | User | Session hijack; High |
| A-03 | Uploaded files, file metadata and share records | Data | User | Privacy breach; High |
| A-04 | Application source code and secrets | Component | Dev team | Full compromise; Critical |
| A-05 | Native parsing module (`libmetaparse.so`) | Component | Dev team | Remote code execution; Critical |
| A-06 | Server host / OS process layer | Component | Operator | System takeover; Critical |
| A-07 | SQLite Database | Component | Operator | Mass data loss/leak; Critical |
| A-08 | Admin console / management interface | Process | Admin | Privilege abuse; High |
| A-09 | Audit and application logs | Data | Operator | Loss of non-repudiation; Medium |
| A-10 | CI/CD pipeline and repository secrets | Process | Dev team | Supply-chain attack; High |
| A-11 | Service availability | Process | Operator | Business disruption; Medium |

## 2. Protection Needs Mapped to CIA Triad

| PN ID | Protection Need | Assets | C | I | A | Jira Issue |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| PN-01 | Only the file owner or an explicitly shared user may read, download, rename or delete a file | A-03 | X | X | | SEC-5 |
| PN-02 | User input must never be interpreted as shell commands | A-06 | X | X | X | SEC-4 |
| PN-03 | Native code must not be corrupted by oversized or malformed input | A-05, A-06 | X | X | X | SEC-3 |
| PN-04 | State-changing requests must originate from the genuine UI | A-01, A-03 | | X | | SEC-6 |
| PN-05 | Sensitive pages must not be embeddable in hostile frames | A-02, A-08 | X | X | | SEC-7 |
| PN-06 | Credentials stored only as salted slow hashes (bcrypt) | A-01 | X | | | SEC-1 |
| PN-07 | Sessions are unguessable, expire, and use secure cookie flags | A-02 | X | X | | SEC-6 |
| PN-08 | Security-relevant events are logged and tamper-evident | A-09 | | X | | SEC-1 |
| PN-09 | Service resists oversized uploads and request floods | A-11 | | | X | SEC-1 |
| PN-10 | No vulnerable code or secrets reach production | A-04, A-10 | X | X | | SEC-8 |

## 3. Measurable Security Requirements

| SR ID | Requirement (Testable) | Derived From | Verification Method |
| :--- | :--- | :--- | :--- |
| SR-01 | Object-level authorization enforced on 100% of object endpoints | PN-01 | Negative IDOR pytest per endpoint |
| SR-02 | No shell interpreter call with user strings; arguments passed as arrays | PN-02 | Semgrep/Bandit + injection test |
| SR-03 | Bounded memory copies in C (`snprintf`); compiled with canary, PIE, RELRO, FORTIFY | PN-03 | ASAN test + `checksec` |
| SR-04 | Every POST/PUT/DELETE requires valid CSRF token; cookies set `SameSite=Lax` | PN-04 | Forged-request test + ZAP |
| SR-05 | Every HTML response sends `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY` | PN-05 | Header check + iframe PoC |
| SR-09 | CI pipeline fails automatically on any Critical or High severity SAST/DAST finding | PN-10 | Fail-on-critical PR demo |
