# Security Policy

## Overview

Password Security Checker is a defensive cybersecurity application designed to help users understand password security and identify potentially weak passwords.

The application performs password analysis locally whenever possible and uses secure methods for external breach checking.

---

## Security Features

The application includes several security-related features:

- Password strength analysis
- Password entropy calculation
- Common password detection
- Weak pattern detection
- Username similarity detection
- Password breach checking
- Security policy validation
- Risk assessment
- Security health calculation
- Audit logging
- Error handling
- Automated security tests

---

## Password Privacy

The application is designed to avoid storing passwords as plain text.

Passwords are not included in audit logs.

Security results may contain information such as:

- Security score
- Risk level
- Strength level
- Detected patterns
- Breach status
- Recommendations

The actual password is not included in these records.

---

## Breach Checking

Password breach checking uses the Have I Been Pwned Passwords API.

The application uses the SHA-1 k-anonymity model.

The general process is:

1. The password is hashed locally.
2. Only a prefix of the hash is sent to the API.
3. The API returns matching hash suffix information.
4. The application performs the final comparison locally.

This approach avoids sending the complete password hash to the external service.

---

## Sensitive Data Handling

The application follows these principles:

- Do not store passwords in audit logs.
- Do not include passwords in error messages.
- Do not expose passwords in exported security reports.
- Perform password analysis locally where possible.
- Minimize sensitive information sent to external services.

---

## Audit Logging

The audit system records security-related events and results.

Examples include:

- Security checks
- Analysis results
- Security scores
- Risk levels
- Timestamps

The password itself is not recorded in the audit log.

---

## Error Handling

The application includes error handling for:

- Invalid input
- Network failures
- API failures
- Export failures
- Logging failures
- Unexpected application errors

Error messages are designed to avoid exposing sensitive password information.

---

## Security Testing

Automated tests are included in:

```text
tests/test_security_core.py