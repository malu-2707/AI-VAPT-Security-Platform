## AI-VAPT Security Platform 

## About the Project

AI-VAPT Security Platform is a web-based security assessment tool developed for automated vulnerability assessment and penetration testing.

The platform allows an authorized user to add a target, run security scanners, identify vulnerabilities, analyze findings using AI, calculate risk, and generate security assessment reports.

This project is mainly designed for learning cybersecurity concepts and demonstrating how different security tools can be integrated into a single platform.

## Main Features

* User login and authentication
* Authorized target management
* Target authorization confirmation
* Automated security scanning
* Nmap network and service scanning
* Nuclei vulnerability detection
* Nikto web server scanning
* Vulnerability findings management
* AI-assisted vulnerability analysis
* Risk score calculation
* Scan history
* Security findings dashboard
* Security assessment reports
* Report download
* Web-based security dashboard

## How the Platform Works

The basic workflow is:

```text
Login
  |
  v
Add Authorized Target
  |
  v
Select Security Scanner
  |
  v
Run Security Scan
  |
  v
Collect Findings
  |
  v
AI Analysis
  |
  v
Risk Assessment
  |
  v
View Findings
  |
  v
Generate Security Report
```

## Technologies Used

### Backend

* Python
* FastAPI
* SQLAlchemy
* PostgreSQL
* JWT Authentication

### Security Tools

* Nmap
* Nuclei
* Nikto

### AI

* Google Gemini API
* Google GenAI Python SDK

### Frontend

* HTML
* CSS
* JavaScript

### Operating Environment

* Kali Linux
* Python Virtual Environment

## Project Structure

```text
AI-VAPT-Security-Platform/
│
├── app/
│   │
│   ├── ai/
│   │   ├── __init__.py
│   │   └── analyzer.py
│   │
│   ├── auth/
│   │   ├── dependencies.py
│   │   ├── login.py
│   │   └── register.py
│   │
│   ├── models/
│   │   ├── finding.py
│   │   ├── report.py
│   │   ├── scan.py
│   │   ├── target.py
│   │   └── user.py
│   │
│   ├── reports/
│   │   ├── __init__.py
│   │   └── routes.py
│   │
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── nikto_routes.py
│   │   ├── nikto_scanner.py
│   │   ├── nmap_scanner.py
│   │   ├── nuclei_scanner.py
│   │   └── routes.py
│   │
│   ├── security/
│   │   ├── auth.py
│   │   ├── jwt.py
│   │   ├── password.py
│   │   ├── risk.py
│   │   └── roles.py
│   │
│   ├── targets/
│   │   ├── __init__.py
│   │   └── routes.py
│   │
│   ├── database.py
│   └── findings_routes.py
│
├── frontend/
│   ├── index.html
│   └── login.html
│
├── create_admin.py
├── creat_tables.py
├── main.py
├── opencode.json
├── requirements.txt
├── .gitignore
└── README.md
```

## Description of Important Files

### `main.py`

This is the main FastAPI application file. It starts the backend and connects the different application modules.

### `app/database.py`

This file contains the PostgreSQL database connection and database configuration.

### `app/models/`

This folder contains the database models used by the platform.

The models represent users, targets, scans, findings, and reports.

### `app/auth/`

This folder handles user authentication and registration.

It contains the login, registration, and authentication dependency logic.

### `app/security/`

This folder contains security-related functions such as JWT handling, password protection, user roles, authentication, and risk calculation.

### `app/targets/`

This module manages authorized security testing targets.

### `app/scanners/`

This module contains the security scanner integration.

The platform currently supports:

* Nmap
* Nuclei
* Nikto

### `app/ai/analyzer.py`

This file connects the platform with Google Gemini.

It analyzes detected security findings and provides:

* Vulnerability explanation
* Security impact
* Exploitability assessment
* Risk reasoning
* Recommended remediation
* AI priority

### `app/findings_routes.py`

This module provides API routes for viewing and analyzing security findings.

### `app/reports/`

This module handles security assessment report generation and report-related API operations.

### `frontend/index.html`

This is the main security dashboard.

It displays targets, scanners, scan history, findings, risk assessment, and reports.

### `frontend/login.html`

This provides the login interface for the platform.

### `creat_tables.py`

This script creates the required database tables.

### `create_admin.py`

This script is used to create an administrator account.

### `requirements.txt`

This file contains the Python packages required to run the project.

## Security Assessment Workflow

The platform follows a basic VAPT workflow.

### 1. Authentication

The user logs into the platform using the authentication system.

### 2. Target Authorization

The user adds a target and confirms that they are authorized to perform security testing.

### 3. Scanner Selection

The user selects an available security scanner.

### 4. Vulnerability Assessment

The selected scanner checks the authorized target and produces scan results.

### 5. Finding Collection

Detected security issues are stored as findings in the database.

### 6. AI Analysis

Gemini analyzes the available vulnerability information and provides an understandable security assessment.

### 7. Risk Assessment

The platform calculates the security risk based on the detected findings.

### 8. Reporting

The user can view the assessment results and generate a security report.

## Example Testing Environment

The platform can be tested using intentionally vulnerable applications and systems created for security training.

Examples include:

* OWASP Juice Shop
* DVWA
* Metasploitable
* Local test applications

Only systems that you own or have explicit permission to test should be used.

## Installation

Clone the repository:

```bash
git clone https://github.com/malu-2707/AI-VAPT-Security-Platform.git
cd AI-VAPT-Security-Platform
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Configure the required environment variables in a `.env` file.

Do not upload the `.env` file to GitHub because it may contain passwords, API keys, or other sensitive information.

## Running the Backend

Start the FastAPI server:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available locally at:

```text
http://127.0.0.1:8000
```

FastAPI documentation:

```text
http://127.0.0.1:8000/docs
```

## Running the Frontend

From the project directory:

```bash
cd frontend
python3 -m http.server 3000
```

Then open:

```text
http://127.0.0.1:3000
```

## Current Scanner Support

| Scanner | Purpose                                      |
| ------- | -------------------------------------------- |
| Nmap    | Port and service discovery                   |
| Nuclei  | Vulnerability and security template scanning |
| Nikto   | Web server security checks                   |

## AI-Assisted Analysis

The AI component is used to make security findings easier to understand.

Instead of displaying only raw scanner output, the platform can provide a structured explanation of the finding and suggest defensive remediation steps.

The AI analysis is intended to assist the security assessment process and should not replace manual security verification.

## Reports

The platform provides security assessment reports containing information such as:

* Target
* Scanner
* Scan status
* Risk score
* Risk level
* Severity counts
* Security findings
* Assessment information

Reports can also be downloaded for documentation.

## Project Purpose

This project was developed as a cybersecurity academic project to understand how vulnerability assessment tools, APIs, databases, authentication, AI analysis, and reporting can be combined into one security platform.

The project also provides practical experience with:

* Vulnerability assessment
* Web application security
* Security automation
* API development
* Database management
* Authentication
* Security reporting
* AI-assisted security analysis

## Limitations

The platform is intended for authorized security testing and educational use.

Scanner results may require manual verification because automated tools can produce incomplete results or false positives.

AI-generated analysis should also be reviewed by a security professional before making security decisions.

## Responsible Use

Use this platform only against systems that you own or have explicit permission to assess.

Do not use it to scan or attack unauthorized websites, servers, networks, or applications.

## Author

Malini S

BE Computer Science and Engineering - Cyber Security

## License

This project is intended for educational and cybersecurity learning purposes.

## Screenshot Image
# 1) On Docs:
<img width="1274" height="626" alt="Image" src="https://github.com/user-attachments/assets/93f9e727-6968-4e62-bb53-30043dbd1a84" />

<img width="1274" height="626" alt="Image" src="https://github.com/user-attachments/assets/9362444a-a025-4465-a131-ec67bc3b6c67" />

<img width="1274" height="626" alt="Image" src="https://github.com/user-attachments/assets/2846bc1a-15e6-4176-af9d-8eee522aadde" />

# 2) Login Page:

<img width="718" height="571" alt="Image" src="https://github.com/user-attachments/assets/9bdd66d2-9e84-4470-be6c-fc50230fc2cc" />

# 3) Frontend:
<img width="1269" height="640" alt="Image" src="https://github.com/user-attachments/assets/06bc3bb9-4c61-4744-9279-32b31132c254" />
   
<img width="1269" height="640" alt="Image" src="https://github.com/user-attachments/assets/56cd6de1-1041-4b77-a638-a2dea246d203" />

<img width="952" height="655" alt="Image" src="https://github.com/user-attachments/assets/51ead56c-e5ba-4a36-aca9-feaa6c2953ce" />

# 4) Security report:
<img width="1063" height="636" alt="Image" src="https://github.com/user-attachments/assets/d07a9ceb-b97b-49b3-bd4a-14198bdc3dd4" />

# 5) Document downloaded model:
<img width="1063" height="636" alt="Image" src="https://github.com/user-attachments/assets/9e7f8784-4594-4b4b-860a-f572bca7d2c4" />
