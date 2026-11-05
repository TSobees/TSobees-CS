> Historical report retained from the original project. Some methodology commands below are illustrative and use a different subnet. Recorded scope and results are in [the XML evidence](../../data/scans/network_scan.xml). OS detections are guesses; this report does not demonstrate exploitation or current network state.

# Network Scan Report

## Introduction
This report outlines the results of a network scan conducted using **Nmap 7.94SVN** on **January 22, 2025**. The objective was to identify live hosts, open ports, running services, and potential vulnerabilities within the network range **192.168.204.128/24**.

---

## Methodology

### Scan Command
```bash
/usr/lib/nmap/nmap --privileged -A -oA network_scan 192.168.204.128/24
```

### Options Used
- **-A**: Enables OS detection, version detection, script scanning, and traceroute  
- **-oA**: Saves output in all formats (`.nmap`, `.xml`, `.gnmap`)

---

## Step 3.1: Discover Live Hosts
```bash
nmap -sn 192.168.1.0/24
```
**Explanation**
- `-sn`: Ping scan to identify active hosts
- Network range specified using CIDR notation

---

## Step 3.2: Scan Open Ports and Services
```bash
nmap -sS -sV 192.168.1.0/24
```
- **-sS**: TCP SYN scan  
- **-sV**: Service and version detection

---

## Step 3.3: Perform an Aggressive Scan
```bash
nmap -A 192.168.1.0/24
```

---

## Step 3.4: Save the Scan Results
```bash
nmap -A -oA network_scan 192.168.1.0/24
```
**Output Files**
- `network_scan.nmap`
- `network_scan.xml`
- `network_scan.gnmap`

---

## Findings

### Host: 192.168.204.1
- **Status**: Up (0.0013s latency)
- **Open Port**: 80/tcp
- **Service**: HTTP (Microsoft IIS 10.0)
- **Issue**: TRACE method enabled
- **OS Detection**:
  - Windows 11 (92%)
  - FreeBSD 6.x (88%)
- **MAC**: VMware
- **Traceroute**: 1 hop

---

### Host: 192.168.204.2
- **Status**: Up (0.00065s latency)
- **Open Port**: 53/tcp
- **Service**: DNS (NOTIMP response)
- **Issue**: Unrecognized service
- **OS Detection**:
  - VMware NAT device (98%)
  - Windows XP SP3 (93%)

---

### Host: 192.168.204.254
- **Status**: Up
- **Ports**: Filtered
- **OS Detection**: Inconclusive
- **MAC**: VMware

---

### Host: 192.168.204.128
- **Status**: Up
- **Ports**: Closed
- **OS Detection**: Insufficient data

---

## Network Topology
All hosts were reachable within a single hop, indicating a flat network topology.

---

## Recommendations

### 192.168.204.1
- Disable TRACE in IIS
- Keep server patched

### 192.168.204.2
- Investigate DNS misconfiguration
- Harden DNS service

### 192.168.204.254
- Review firewall rules
- Monitor logs

### 192.168.204.128
- Validate closed-port policy

---

## Conclusion
Four live hosts were identified. Security issues such as risky HTTP methods and unidentified DNS behavior should be addressed to improve network security posture.

---

## Appendix
Refer to scan logs:
- `network_scan.nmap`
- `network_scan.xml`
- `network_scan.gnmap`
