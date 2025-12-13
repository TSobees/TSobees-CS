# Nmap Network Security Assessment

## 📌 Project Overview
This project documents a network security assessment performed using **Nmap 7.94SVN** on a private lab network. The goal was to identify live hosts, open ports, running services, and potential security risks.

> ⚠️ This scan was conducted in a controlled lab environment on a private IP range (192.168.x.x).

---

## 🛠 Tools Used
- Nmap 7.94SVN
- Linux (Kali Linux)
- VMware virtual network

---

## 🎯 Objectives
- Discover live hosts
- Identify open ports and services
- Detect operating systems
- Highlight potential security misconfigurations
- Provide security recommendations

---

## 🧪 Methodology

### Host Discovery
```bash
nmap -sn 192.168.204.128/24
Service & Port Scanning
bash
Copy code
nmap -sS -sV 192.168.204.128/24
Aggressive Scan
bash
Copy code
nmap -A -oA network_scan 192.168.204.128/24
## 📄 Findings Summary
4 live hosts discovered

HTTP service detected with risky TRACE method enabled

DNS service detected with unrecognized response

Firewall filtering observed on multiple hosts

Detailed findings are available in the full report.

## 📊 Report
📁 report/Network_Scan_Report.md

## 🔐 Ethical Disclaimer
This project was conducted strictly for educational purposes in a lab environment. No unauthorized networks were scanned.

## Findings
Host: 192.168.204.1

Status: Up

Port 80/tcp: Open

Service: HTTP (Microsoft IIS 10.0)

Risk: TRACE method enabled

Host: 192.168.204.2

Port 53/tcp: Open

Service: DNS (Unrecognized response)

...

## Recommendations

Disable TRACE on IIS

Harden DNS configurations

Review firewall rules

## Conclusion

The assessment identified security gaps that should be addressed to improve network posture.

