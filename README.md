# CloudShield

> **Cloud Security Simulation, Web Attack Detection, and Digital Forensics Platform**  
> *MSc Information Security and Digital Forensics Capstone Project*

CloudShield is an enterprise-grade, locally hosted Security Operations Center (SOC) web application designed for cloud security monitoring, web attack detection, incident response, and digital forensic investigation. It simulates a cloud infrastructure environment (AWS-style EC2 VMs, S3 buckets, IAM roles, Security Groups) and provides real-time detection, forensic timeline reconstruction, and cryptographically verified evidence custody without requiring an external cloud provider account.

---

## Key Capabilities & Features

### 1. Cloud Security Posture Management (CSPM)
- **Simulated Cloud Assets**: Monitor virtual machines, object storage buckets, database instances, and IAM credentials.
- **CIS Benchmark Misconfiguration Scanner**: Automated rule evaluation detecting public S3 buckets, unencrypted volumes, exposed SSH/RDP ports, wildcard IAM permissions, and missing access logs.
- **Interactive Risk Scoring**: Dynamically calculates infrastructure risk posture with remediation guidance.

### 2. Live Attack Detection & SOC Triage
- **Signature & Heuristic Detection Engine**: Detects SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, Credential Stuffing, and Brute Force authentication attacks.
- **MITRE ATT&CK Mapping**: Maps alerts to standard techniques (T1190, T1110, T1530, T1078).
- **SOC Analyst Workflow**: Acknowledge, investigate, escalate, or classify alerts as false positives with rationale logging.

### 3. Incident Management & Digital Forensics
- **Case Management**: Create, assign, track, and close formal security incidents.
- **Forensic Timeline Reconstruction**: Correlate chronological events across multiple sources and visualize attack progression.
- **Evidence Vault & Cryptographic Chain of Custody**:
  - Securely upload and preserve forensic artifacts (logs, memory dumps, PCAP files).
  - Calculates SHA-256 cryptographic hashes upon ingestion.
  - Continuous integrity verification against disk tampering adhering to ISO/IEC 27037 standards.
  - Complete immutable handling ledger tracking every access and export.

### 4. Automated Containment & Reversible Playbooks
- **Safe Local Containment**: Isolate compromised virtual machines, restrict public storage buckets, and temporarily lock suspect demo accounts.
- **One-Click Rollback**: All containment actions maintain an execution ledger and can be reversed with a single click.
- **Zero External Risk**: All actions execute strictly within the local simulation state—never impacting host system or external infrastructure.

### 5. Compliance & Forensic Reporting
- **Executive & Technical PDF Generation**: Built with ReportLab to generate publication-ready Incident Investigation Dossiers, Cloud Security Posture Audits, and Chain of Custody Verification Reports.

### 6. Administration & Role-Based Access Control (RBAC)
- **Tiered Permissions**:
  - **Administrator**: Full platform configuration, user provisioning, detection rule toggling, and audit log inspection.
  - **Security Analyst**: Alert triage, case management, evidence upload/verification, and containment execution.
  - **Viewer**: Read-only oversight for auditors and stakeholders.
- **Comprehensive Audit Trail**: Every user action, state change, and login is immutably logged with timestamp, actor, IP, and payload metadata.

---

## Technology Stack

- **Backend**: Python 3.10+, Flask 3.0, Flask-Login, Flask-WTF, Flask-SQLAlchemy, Werkzeug
- **Database**: SQLite (via SQLAlchemy ORM)
- **Frontend**: Vanilla HTML5, Custom Cyber Dark SOC CSS Theme, Vanilla JavaScript
- **Visualization**: Chart.js 4.4, Lucide Icons
- **PDF Engine**: ReportLab

---

## Getting Started

### 1. Prerequisites
- Python 3.10 or higher installed.

### 2. Setup Virtual Environment
```bash
# Clone or navigate to the repository directory
cd Cloudshield

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Windows (CMD):
.\.venv\Scripts\activate.bat
# Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Initialize & Seed Demo Data
Populate the platform with simulated cloud infrastructure, security events, alerts, open cases, and sample forensic evidence:
```bash
python app.py seed
```

### 4. Run the Application
```bash
python app.py
```
Open your web browser and navigate to:
**`http://127.0.0.1:5000`**

---

## Default Credentials

The seeding script configures pre-populated accounts for immediate evaluation:

| Role | Username | Password | Notes |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `CloudShield@Admin2024!` | Full system control |
| **Security Analyst** | `analyst_demo` | `Demo@Analyst2024!` | Triage & Forensics |
| **Auditor / Viewer** | `viewer_demo` | `Demo@Viewer2024!` | Read-only inspection |

---

## Project Structure

```
Cloudshield/
├── app.py                      # Application factory, error handlers, and CLI runner
├── config.py                   # Environment configuration and security parameters
├── requirements.txt            # Python dependencies
├── models/                     # SQLAlchemy data models
│   ├── __init__.py             # User, Resource, Event, Alert, Incident, Evidence, Audit models
├── modules/                    # Core business and security engines
│   ├── attack_detection.py     # Attack pattern signatures and event generation
│   ├── audit_logger.py         # Administrative action audit logging
│   ├── demo_data.py            # Comprehensive realistic SOC scenario seeder
│   ├── evidence_manager.py     # SHA-256 calculation, custody ledger, and integrity verification
│   └── report_generator.py     # ReportLab PDF generator for dossiers and posture audits
├── routes/                     # Blueprint modular controllers
│   ├── alerts.py               # SOC alert queue and triage
│   ├── audit.py                # Admin audit log viewer
│   ├── auth.py                 # Authentication and session management
│   ├── dashboard.py            # Metrics, charts, and SOC overview
│   ├── events.py               # Raw security event feed
│   ├── evidence.py             # Forensic evidence vault and chain of custody
│   ├── forensics.py            # Timeline correlation and attack reconstruction
│   ├── incidents.py            # Incident lifecycle management and case files
│   ├── posture.py              # Cloud security posture and CIS rule scanner
│   ├── reports.py              # Report generation and download handlers
│   ├── resources.py            # Simulated cloud resource inventory
│   ├── response.py             # Containment playbooks and rollback orchestration
│   └── settings.py             # User provisioning and detection rule toggles
├── static/                     # Static assets
│   ├── css/cloudshield.css     # Premium dark SOC stylesheet
│   └── js/cloudshield.js       # Dynamic UI interactions and Chart.js configs
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Master layout with responsive sidebar and navigation
│   ├── alerts/                 # Alert queue and detail views
│   ├── audit/                  # Audit trail log table
│   ├── auth/                   # Login interface
│   ├── dashboard/              # SOC Overview dashboard
│   ├── errors/                 # 403, 404, 500 error pages
│   ├── events/                 # Security events list and payload inspector
│   ├── evidence/               # Evidence vault, deposit form, and custody ledger
│   ├── forensics/              # Timeline reconstruction and correlation views
│   ├── incidents/              # Case list, creation form, and case file detail
│   ├── posture/                # Posture findings and compliance status
│   ├── reports/                # Report generation center
│   ├── resources/              # Cloud asset inventory and creation forms
│   ├── response/               # Automated response playbooks and action ledger
│   └── settings/               # User administration and detection rules
└── instance/                   # Local SQLite database and uploaded evidence vault
```

---

## Academic & Forensic Integrity Note

CloudShield was designed as an MSc Information Security and Digital Forensics demonstration platform. All simulated attacks, evidence records, and containment playbooks adhere to forensic preservation methodologies:
- **RFC 3227** guidelines for evidence collection and archiving.
- **ISO/IEC 27037** standards for digital evidence handling and verification.
- **MITRE ATT&CK Framework** for threat classification and correlation.
