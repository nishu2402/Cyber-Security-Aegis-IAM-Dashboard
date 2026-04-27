# Aegis-IAM Dashboard (Cyber-Security HUD)

High-end IAM Privilege Escalation Detection + Risk Analysis dashboard.

## Features
- **Awaiting Data** startup (no auto demo)
- Manual **Initialize Simulation** button (loads demo dataset)
- Robust JSON ingestion:
  - Simple schema: `users/roles/permissions/inherits`
  - AWS IAM: `aws iam get-account-authorization-details`
- Privilege escalation path discovery (graph traversal)
- Dynamic remediation playbook per finding
- One-click PDF export (client-side html2pdf)

## Run
```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open: http://127.0.0.1:5000

## AWS Export (Real World)
```bash
aws configure
aws iam get-account-authorization-details --output json > iam_auth.json
```
Upload `iam_auth.json` in the dashboard.

## Security Notes
- Uploaded JSON is parsed only (no code execution).
- File size limited to 2MB.
- Use only in authorized environments.

Owned and Developed by Nisarg Chasmawala (Shroff). © 2026 All Rights Reserved.
