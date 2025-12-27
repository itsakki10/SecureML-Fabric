# SecureML Fabric

**ML-Enabled Network Anomaly Detection & Automated Response System**

---

## Overview

SecureML Fabric is a real-time Machine Learning based network anomaly
detection and response system designed for future integration with
Web Application Firewalls (WAF).

The system performs behavioral baselining of live network traffic,
detects anomalous activity without relying on static signatures,
and enforces automated kernel-level mitigation using Linux firewall rules.

---

## Key Features

- Live per-IP traffic capture and behavioral profiling
- ML-based anomaly detection using Isolation Forest
- Confidence-driven decision logic to reduce false positives
- Kernel-level IP blocking using iptables
- Explainable alerts and human-readable WAF rule recommendations
- Administrator dashboard with attack timelines and controls
- Time-bound blocking with manual override support

---

## System Architecture

Traffic Collector → ML Engine → Decision Engine → Kernel Firewall
↓
Dashboard UI

---

## Technology Stack

- **Python**
- **Scapy** (live traffic capture)
- **Scikit-learn** (ML anomaly detection)
- **Streamlit** (administrator dashboard)
- **iptables** (kernel-level mitigation on Linux)

---

## How to Run

### 1. Install Dependencies

```bash
pip install -r requirements.txt


## 2. Start Live Traffic Capture (Ubuntu)
Requires root privileges for packet capture
sudo python3 traffic_collector/capture.py

## 3. Start the Dashboard
streamlit run dashboard/app.py
Access the dashboard at:

http://localhost:8501

## 4. Simulate an Attack (Example)

From a Windows or Linux attacker machine:

for ($i=0; $i -lt 5000; $i++) {
    Invoke-WebRequest http://<victim-ip>:8080 -UseBasicParsing | Out-Null
}


This generates high-rate traffic that triggers anomaly detection
and automated blocking.

## Automated Response Logic:-

High-confidence anomalies are blocked at the kernel level
Blocking is time-bound and automatically reversible
Manual unblock option available via dashboard
All security actions are logged for auditability

## Explainability :-

For every detected anomaly, the system provides:
Anomaly confidence level (LOW / MEDIUM / HIGH)
Feature deviation explanation (rate, packets, bytes)
Recommended WAF-style rules for administrator approval

## Logs & Audit :-

All mitigation actions are recorded in:

logs/blocked_ips.log

This enables post-incident analysis and compliance auditing.

### Future Enhancements:-
1.Encrypted traffic metadata analysis (TLS fingerprints)
2.Direct integration with open-source WAFs (e.g., ModSecurity)
3.Federated learning across distributed nodes
4.Adaptive retraining using administrator feedback

## Demo:-

A demonstration video showcasing live detection, blocking,
and dashboard visualization is included as part of the submission.

[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/bH96jorA)
>>>>>>> dba2653851f7e6124afc491f39c4e714e8751550
```
