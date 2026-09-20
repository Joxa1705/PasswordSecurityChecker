# Password Security Checker — Architecture

## 1. System Overview

Password Security Checker is a desktop cybersecurity application built with Python and Tkinter.

The application analyzes passwords using multiple security checks and provides a security score, risk level, recommendations, pattern analysis, breach information, and security policy results.

The system is designed as a local desktop application with an external breach-checking API used only when necessary.

---

## 2. Application Architecture

The application follows a modular architecture:

```text
User
  │
  ▼
GUI Layer (gui.py)
  │
  ▼
Security Core (security_core.py)
  │
  ├── Password Analysis
  ├── Pattern Detection
  ├── Entropy Calculation
  ├── Common Password Detection
  ├── Breach Checking
  ├── Risk Calculation
  └── Security Health
  │
  ▼
Results
  │
  ├── Security Report
  ├── Recommendations
  ├── Security Policies
  └── Audit Log