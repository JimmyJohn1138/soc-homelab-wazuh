# Wazuh SOC Homelab - Detection Lab
**Hands-on SOC Detection & Response Lab with Wazuh**

A fully self-built Security Operations Center (SOC) homelab using Wazuh — an open-source SIEM and XDR platform. This project demonstrates end-to-end threat detection and response workflows in a realistic multi-OS environment, focusing on entry-level SOC analyst skills: log ingestion, alert triage, detection engineering, troubleshooting, and basic incident response.

![SSH Authentication Failure Spike](screenshots/auth-failure-spike.png)
*Wazuh Dashboard showing massive authentication failure spike during SSH brute-force simulation*

## Project Summary and Motivation

As an aspiring cybersecurity professional targeting junior SOC analyst roles, I created this lab to bridge the gap between theoretical knowledge (e.g., Microsoft SC-200/SC-300 coursework, Security+ certification) and hands-on experience that employers actually look for.

This homelab replicates real SOC workflows:
- Deploying and managing agents across Linux and Windows endpoints
- Ingesting and enriching logs
- Detecting attacks using stock and custom rules
- Triaging alerts in the dashboard
- Mapping to MITRE ATT&CK
- Simulating incident response actions

It highlights my ability to troubleshoot common production issues (agent connectivity, indexer performance, certificate errors, and configuration failures) — skills directly transferable to tools like Wazuh, Splunk, Elastic, or Microsoft Sentinel.

Everything runs on **bare-metal personal hardware** (no VMs for the endpoints) to ensure authentic log behavior and network interactions.

**Contact**: John Gill | Security+ (SY0-701) | [LinkedIn](https://www.linkedin.com/in/jessemcgeejr)

## Lab Architecture

![Lab Architecture Diagram](screenshots/lab-architecture-diagram.jpg)
*Homelab network topology: Wazuh manager centralizing logs from Linux/Windows endpoints and monitored attacker machine*

## ⚙️ Setup Overview

This homelab runs entirely on **bare‑metal hardware** with one attacker system (also monitored as a Wazuh agent) and two additional endpoints. All systems report logs to a central Wazuh Manager for detection and visualization.

- **Wazuh Manager/Dashboard (Ubuntu 22.04)**  
  Installed using [Wazuh official guide](https://documentation.wazuh.com/current/installation-guide/index.html). Configured to collect logs from Windows, Linux, and Parrot agents.

- **Windows 10 Agent ("Fistandantilus")**  
  Wazuh agent + Sysmon installed. Used for RDP brute-force and malware execution scenarios.

- **Linux Agent ("Raistlin")**  
  Wazuh agent + auditd + Suricata installed. Used for SSH brute-force, privilege escalation, file monitoring, and **network reconnaissance** scenarios.

- **Parrot OS Attacker + Agent ("Takhisis")**  
  Dual role: generates safe attack traffic **and** reports its own logs to Wazuh. Tools: Hydra, Nmap, Atomic Red Team, EICAR.

**Note:** This repo focuses on attack/detection labs. For installation details, see [Wazuh documentation](https://documentation.wazuh.com/current/installation-guide/index.html).

## Simulated Attacks & Detection Results

### 1. SSH Brute-Force Attack (Linux Endpoint)

**Attack Execution**  
Tool: Metasploit `auxiliary/scanner/ssh/ssh_login`  
Result: 656 failed login attempts in seconds

![Metasploit Terminal](screenshots/metasploit-terminal.png)

**Detection**  
- Triggered Wazuh rule **57105** (multiple SSH authentication failures)  
- Mapped to MITRE ATT&CK **T1110.001** (Brute Force – Password Guessing)

![SSH Event JSON Details](screenshots/event-json-details.png)  
![SSH Authentication Failure Logs](screenshots/auth-failure-logs.png)

### 2. RDP Brute-Force Attack (Windows Endpoint)

**Attack Execution**  
Tool: Hydra on Parrot OS  
Result: 101 failed login attempts

![RDP Dashboard Overview](screenshots/rdp-dashboard-overview.png)  
![Hydra Terminal](screenshots/rdp-hydra-terminal.png)

**Detection**  
- Windows Event ID **4625** captured  
- Triggered Wazuh rule **18120** → Level 10 alerts  
- Mapped to MITRE ATT&CK **T1110.003** (Brute Force – Password Spraying)

![Windows Agent Status](screenshots/windows-agent-status.png)  
![RDP MITRE Framework View](screenshots/rdp-mitre-bruteforce.png)  
![RDP Event JSON](screenshots/rdp-event-json.png)

### 3. Network Reconnaissance - Nmap Port Scan (Linux Endpoint)

**Attack Execution**  
From Parrot OS attacker:

```bash
nmap -sS -A -p 1-1000 192.168.0.9

Nmap Scan Command
Detection Setup

Suricata installed on Raistlin with EVE JSON logging enabled
Custom rule to elevate severity and map to MITRE

Results

High-severity (level 12) alerts
Spike in dashboard
T1046 highlighted in MITRE heatmap

Suricata EVE Log
Wazuh Nmap Alert
MITRE Heatmap T1046
