# NovaTech Security Lab

## Overview

You have joined **NovaTech** as a Junior Cloud Security Engineer.

NovaTech operates a hybrid environment containing:

- Azure cloud resources
- Microsoft Entra ID identities
- Cisco network equipment
- Linux servers
- Firewalls
- VPN infrastructure
- Web applications
- Databases
- Storage systems

You do **not** have access to the live environment.

Instead, Security Engineering has provided exported configuration files, cloud inventories, identity records, network logs, authentication logs, firewall logs, and incident data.

Your job is to build a **Python-based security analysis workstation** that:

1. Parses the provided datasets.
2. Inventories cloud and identity resources.
3. Detects insecure configurations.
4. Finds suspicious activity.
5. Correlates related events across different data sources.
6. Generates findings and incident reports.
7. Optionally integrates Claude and/or OpenAI for evidence-grounded investigation assistance.
8. Sanitizes sensitive information before sending telemetry to external AI APIs.

---

# Rules of Engagement

This is a defensive cybersecurity training lab.

All IP addresses, usernames, systems, and organizations in this repository are fictional or use documentation-only address ranges.

Do not use these scripts against systems that you do not own or have permission to assess.

---

# Project Objectives

By the end of this project you should be able to demonstrate:

- Python scripting
- JSON parsing
- Log parsing
- Security detection logic
- Azure security concepts
- Identity and RBAC analysis
- Network security analysis
- Cisco log analysis
- Incident investigation
- Event correlation
- Risk scoring
- CLI development
- Report generation
- AI API integration
- Secret and telemetry sanitization
- Git and GitHub workflow

---

# Environment Setup

## Required tools

Install:

- Python 3.11+
- Git
- VS Code
- jq
- curl
- Wireshark
- GitHub CLI (optional)

Check Python:

```bash
python --version
```

Check Git:

```bash
git --version
```

Clone or unzip the project and enter the directory:

```bash
cd novatech-security-lab
```

Create a Python virtual environment:

```bash
python -m venv .venv
```

Activate on macOS/Linux:

```bash
source .venv/bin/activate
```

Activate on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install packages:

```bash
pip install -r requirements.txt
```

---

# Optional AI Integration

The project is designed so that detection logic is performed by Python.

AI may be used to:

- explain findings
- summarize evidence
- suggest investigation steps
- help generate reports
- assist with code development
- explain MITRE ATT&CK mappings

AI should **not** replace deterministic detection logic.

Copy:

```text
.env.example
```

to:

```text
.env
```

Then add your API keys locally.

Never commit `.env`.

Example:

```text
OPENAI_API_KEY=your-key-here
ANTHROPIC_API_KEY=your-key-here
```

---

# Repository Structure

```text
novatech-security-lab/

├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
│
├── data/
│   ├── cloud/
│   │   ├── azure_resources.json
│   │   ├── network_security_groups.json
│   │   └── azure_activity.json
│   ├── identity/
│   │   ├── entra_users.json
│   │   ├── entra_roles.json
│   │   └── entra_signins.json
│   ├── network/
│   │   └── cisco-core.log
│   ├── firewall/
│   │   └── cisco_firewall.log
│   ├── endpoint/
│   │   └── linux_auth.log
│   └── incidents/
│       └── incident_queue.json
│
├── src/
│   ├── security.py
│   ├── inventory.py
│   ├── cloud_analyzer.py
│   ├── iam_analyzer.py
│   ├── network_analyzer.py
│   ├── firewall_analyzer.py
│   ├── correlator.py
│   ├── risk_engine.py
│   ├── sanitize.py
│   ├── ai_assistant.py
│   └── report_generator.py
│
├── rules/
│   ├── cloud_rules.json
│   ├── identity_rules.json
│   └── network_rules.json
│
├── reports/
├── investigations/
├── tests/
└── instructor/
    └── ANSWER_KEY.md
```

---

# Assignment 1 — Inventory the Environment

Build:

```text
src/inventory.py
```

Your script must read the JSON files and produce an inventory.

Target command:

```bash
python src/security.py inventory
```

Target output:

```text
NOVATECH ENVIRONMENT

Virtual Machines       2
Storage Accounts       2
SQL Databases          1
Key Vaults             1
VNets                   1
NSGs                    2
Users                   8
Privileged Users        3
Network Devices         2
```

Do not hardcode totals.

Read the data and calculate them.

---

# Assignment 2 — Cloud Security Scanner

Build:

```text
src/cloud_analyzer.py
```

Your scanner should evaluate:

## Virtual machines

Check for:

- public IP addresses
- missing managed identity
- password-based authentication
- missing disk encryption indication

## Storage

Check for:

- public blob access
- public network access
- old TLS version
- weak network restrictions

## SQL

Check for:

- public network access
- auditing disabled
- excessive firewall ranges

## Key Vault

Check for:

- public network access
- secrets without expiration
- secrets expiring within 30 days

## NSGs

Check for:

- SSH exposed to the Internet
- RDP exposed to the Internet
- overly broad administrative access

Target command:

```bash
python src/security.py scan
```

---

# Assignment 3 — Identity and RBAC Analysis

Build:

```text
src/iam_analyzer.py
```

Analyze:

```text
data/identity/entra_users.json
data/identity/entra_roles.json
data/identity/entra_signins.json
```

Detect:

- Owner assignments
- Contributor assignments
- stale privileged accounts
- suspicious failed logins
- successful login after repeated failures
- privileged access from unusual sources

Target output should include:

```text
Finding ID
Severity
Identity
Reason
Evidence
Recommendation
```

---

# Assignment 4 — Cisco Log Analysis

Build:

```text
src/network_analyzer.py
```

Analyze:

```text
data/network/cisco-core.log
```

Detect:

- repeated failed administrative login attempts
- successful authentication after failures
- configuration changes after suspicious authentication
- repeated activity from the same source IP

Target command:

```bash
python src/security.py hunt 198.51.100.77
```

---

# Assignment 5 — Firewall Analysis

Build:

```text
src/firewall_analyzer.py
```

Analyze:

```text
data/firewall/cisco_firewall.log
```

Look for:

- repeated denied connections
- port scanning behavior
- successful connections after scanning
- lateral movement
- unusual outbound connections
- suspicious VPN activity

---

# Assignment 6 — Linux Authentication Analysis

Analyze:

```text
data/endpoint/linux_auth.log
```

Identify:

- brute-force attempts
- username enumeration
- successful SSH login following repeated failures
- privileged login patterns

Do not simply count the word `Failed`.

Build behavioral logic.

---

# Assignment 7 — Correlation Engine

Build:

```text
src/correlator.py
```

Correlate events using:

- source IP
- username
- timestamp
- target system
- action
- resource

The engine should be able to identify one incident that spans multiple systems.

Example:

```text
198.51.100.77
    ↓
Cisco failed logins
    ↓
Cisco successful admin login
    ↓
Cisco configuration modification
    ↓
Linux successful SSH login
    ↓
Azure network security rule modification
    ↓
Outbound firewall traffic
```

The output should explain why those events may represent one incident.

---

# Assignment 8 — Rule Engine

Do not hardcode every security rule in Python.

Use:

```text
rules/cloud_rules.json
rules/identity_rules.json
rules/network_rules.json
```

Your Python application should load rule definitions dynamically.

Add at least five new rules of your own.

---

# Assignment 9 — Security CLI

Build:

```text
src/security.py
```

Target commands:

```bash
python src/security.py inventory
python src/security.py scan
python src/security.py hunt 198.51.100.77
python src/security.py investigate INC-001
python src/security.py report
```

Optional:

```bash
python src/security.py investigate INC-001 --ai
```

---

# Assignment 10 — AI Assistant

Build:

```text
src/ai_assistant.py
```

Support OpenAI and/or Claude.

The Python security tooling must create structured evidence first.

Example:

```json
{
  "source_ip": "198.51.100.77",
  "failed_logins": 8,
  "successful_logins": 2,
  "systems": [
    "CORE-SW01",
    "web-prod-01"
  ],
  "configuration_changes": 1
}
```

Only then may AI be used to:

- summarize
- explain
- map to MITRE ATT&CK
- suggest containment
- recommend next investigation steps

---

# Assignment 11 — Sanitization

Build:

```text
src/sanitize.py
```

Before sending data to an external AI service, redact:

- passwords
- API keys
- tokens
- private keys
- connection strings
- secrets

Example:

```text
password=SuperSecret123
```

must become:

```text
password=[REDACTED]
```

---

# Assignment 12 — Incident Reports

For each incident you investigate, create:

```text
investigations/INC-XXX.md
```

Each report should include:

1. Incident ID
2. Severity
3. Executive Summary
4. Timeline
5. Affected Systems
6. Affected Identities
7. Indicators
8. Evidence
9. Root Cause
10. Attack Path
11. Containment
12. Remediation
13. MITRE ATT&CK Mapping

---

# Assignment 13 — Automated Reports

Generate:

```text
reports/security-report.json
reports/security-report.csv
reports/security-report.html
```

Include:

- finding ID
- severity
- category
- affected resource
- evidence
- recommendation

---

# Investigation Queue

Start with:

```text
data/incidents/incident_queue.json
```

Do not read the instructor answer key until all investigations are complete.

---

# GitHub Requirements

Your GitHub repository should contain:

- clean README
- Python source code
- rules
- sample reports
- incident reports
- screenshots of terminal output
- architecture diagram
- lessons learned

Never commit:

- API keys
- passwords
- access tokens
- `.env`
- private keys
- real customer data

---

# Interview Preparation

When finished, be able to answer:

- How does your detection engine work?
- Why did you separate rules from Python code?
- How did you correlate logs across systems?
- How did you detect brute-force behavior?
- How did you distinguish normal HTTPS exposure from risky SSH exposure?
- How did you analyze RBAC?
- What did you learn from Cisco logs?
- How did you use AI safely?
- How did you sanitize data?
- What would you change if this were a production security product?

---

# Success Criteria

The project is complete when:

- all datasets can be parsed
- cloud configuration risks are identified
- suspicious authentication patterns are detected
- Cisco events are analyzed
- firewall activity is analyzed
- at least one multi-system incident is correlated
- reports are generated
- AI integration is optional but functional
- sensitive data is sanitized before AI use
- code is committed to GitHub
- you can explain every major component without relying on AI
