# 🛡️ SOC Automation: IP Reputation Scanner
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Security](https://img.shields.io/badge/Cybersecurity-Red?style=for-the-badge&logo=fortinet&logoColor=white)

## 📖 Overview
This project is an automated **Threat Intelligence** gathering tool designed to streamline **SOC (Security Operations Center)** monitoring workflows. It addresses the challenge of "Alert Fatigue" by quickly triaging IP addresses against the **VirusTotal API v3**, reducing the time spent on manual investigations.

## 🎯 Use Case
- **Incident Response:** Rapidly identify if an external IP communicating with the network has a malicious history.
- **Phishing Analysis:** Verify the reputation of IPs found in suspicious email headers.
- **Log Enrichment:** Can be integrated into SIEM workflows to provide context to security alerts.

## 🛠️ Tech Stack & Security
- **Language:** Python 3.x
- **API:** VirusTotal v3 (JSON-RPC)
- **Library:** `requests` for HTTP communication.
- **Security:** Implements `python-dotenv` for **Environment Variable Management**, ensuring zero-exposure of sensitive API credentials (following DevSecOps best practices).

## 🚀 How to Setup
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Kaoliveiras/soc-automation-virustotal.git](https://github.com/Kaoliveiras/soc-automation-virustotal.git)