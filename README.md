# Wazuh SOC Detection Homelab

**Hands-on SIEM & XDR Lab – Junior SOC Analyst Portfolio**  
Self-built Wazuh-based Security Operations Center homelab demonstrating real-time threat detection, alert triage, and basic incident response across Linux and Windows endpoints — all on **bare-metal hardware** (no VMs for agents).

![Hero – Brute Force Detection Spike](screenshots/auth-failure-spike.png)  
*Wazuh dashboard showing massive authentication failure spike during SSH brute-force simulation*

## Table of Contents
- [Project Summary & Motivation](#project-summary--motivation)
- [Lab Architecture](#lab-architecture)
- [Tools & Tech Stack](#tools--tech-stack)
- [Simulated Attacks & Detections](#simulated-attacks--detections)
  - [1. SSH Brute-Force (Linux Endpoint)](#1-ssh-brute-force-linux-endpoint)
  - [2. RDP Brute-Force (Windows Endpoint)](#2-rdp-brute-force-windows-endpoint)
  - [3. Network Reconnaissance – Nmap Port Scan (Linux Endpoint)](#3-network-reconnaissance--nmap-port-scan-linux-endpoint)
- [Privilege Escalation Scenarios (Linux & Windows)](#privilege-escalation-scenarios-linux--windows)
  - [Linux SSH Privilege Escalation (Raistlin)](#linux-ssh-privilege-escalation-raistlin)
  - [Windows WinRM Privilege Escalation (Fistandantilus)](#windows-winrm-privilege-escalation-fistandantilus)
- [File Integrity Monitoring (FIM) – Windows & Linux](#file-integrity-monitoring-fim--windows--linux)
- [Why This Lab Matters](#why-this-lab-matters)

## Project Summary & Motivation
As an aspiring cybersecurity professional targeting junior SOC analyst roles, I created this lab to bridge the gap between theoretical knowledge (Security+ certification) and hands-on skills employers value most: log ingestion, detection engineering, alert triage, MITRE mapping, and troubleshooting real-world issues.
**Key Outcomes**:
    • Detected **750+ authentication failures** across SSH & RDP brute-force attacks 
    • Mapped to MITRE ATT&CK **T1110** (Brute Force) 
    • Validated File Integrity Monitoring (FIM) and network reconnaissance detection 
Everything runs on **bare-metal personal hardware** to ensure authentic log behavior and network interactions.
**Contact** — John Gill | Security+ (SY0-701) | LinkedIn | Email

## Lab Architecture
![Lab Topology](screenshots/lab-architecture-diagram.jpg)

*Wazuh Manager centralizing logs from bare-metal Linux/Windows agents + monitored attacker*
    • **Manager/Dashboard**: Ubuntu 22.04 
    • **Linux Agent**: Ubuntu/Mint ("Raistlin") — SSH brute-force + FIM 
    • **Windows Agent**: Windows 10 ("Fistandantilus") — RDP brute-force + registry FIM 
    • **Attacker/Agent**: Parrot OS ("Takhisis") — Metasploit, Hydra, Nmap 

## Tools & Tech Stack
  • **SIEM/XDR**: Wazuh 4.x (manager + agents) 
  • **Network IDS**: Suricata (Emerging Threats ruleset) on Linux agent 
  • **Attack Tools**: Metasploit, Hydra, Nmap 
  • **Logging**: Sysmon (Windows), auditd (Linux), Suricata EVE JSON 
  • **Hardware**: Bare-metal dual-boot setup (no virtualization for endpoints) 
    
## Simulated Attacks & Detections

### 1. SSH Brute-Force (Linux Endpoint)

**Attack** — Metasploit auxiliary/scanner/ssh/ssh_login — 500+ attempts
**Result** — 656 failed logins
**Detection** — Rule 5710/57105 → MITRE **T1110.001** (Brute Force – Password Guessing)

![SSH Brute Force Detection Spike](screenshots/auth-failure-spike.png) 

*Dashboard showing 656 authentication failures in seconds*

![Metasploit Execution](screenshots/metasploit-terminal.png)

*Metasploit console running the attack*

![SSH Event JSON](screenshots/event-json-details.png)

*Decoded auth.log event from attacker IP*

### 2. RDP Brute-Force (Windows Endpoint)

**Attack** — Hydra — 101 failed attempts targeting administrator
**Result** — Windows Event ID 4625 volume
**Detection** — Rule 60122 → escalated to level 10 → MITRE **T1110**

![RDP Dashboard Spike](screenshots/rdp-dashboard-overview.png)

*101 authentication failures with clear spike*

![Hydra Execution](screenshots/rdp-hydra-terminal.png)

*Hydra confirming 101 attempts from 192.168.0.74*

![RDP MITRE Mapping](screenshots/rdp-mitre-bruteforce.png)

*Brute Force tactic and level 10 severity confirmed*

![RDP Event JSON](screenshots/rdp-event-json)

*Decoded Event 4625 showing failed logon details*

### 3. Network Reconnaissance – Nmap Port Scan (Linux Endpoint)

**Attack** — Nmap SYN scan with OS/service detection
**Detection** — Suricata ET SCAN rule → Wazuh ingestion → alert spike
**MITRE** — **T1595/T1046** (Active Scanning / Network Service Discovery)

![Nmap Terminal Output](screenshots/NMapScan.png)

*Scan results showing open ports and services*

![Nmap Alert Spike](screenshots/NMap%20Spike%20.png)

*Wazuh dashboard spike during reconnaissance activity*

![Suricata Alerts](screenshots/SuricataAlerts.png)

*Suricata Emerging Threats detection forwarded to Wazuh*

## File Integrity Monitoring (FIM) – Windows & Linux

### Windows File FIM – Lifecycle Test (Fistandantilus)

**Test Path**: C:\Users\Public\FIM_Test\wazuh_test.txt
**Real-time**: Enabled (syscheck + Windows file system watcher)
![FIM Demo – Fistandantilus](screenshots/FIM_Demo_Fistandantilus.PNG)

*Lifecycle: create → modify → delete events captured*

**MITRE**: **T1070.004** (File Deletion), **T1565.001** (Stored Data Manipulation)

### Windows Registry FIM – Fistandantilus

![FIM Alert - Fistandantilus](screenshots/FIM_Alerts_Fistandantilus.png)

**Observed Activity**: Firewall, Defender, TCP/IP, BAM registry changes
**Rules**: 752/751/750/594
**MITRE**: **T1112** (Modify Registry)
### Linux FIM – Raistlin

![Linux FIM Demo](screenshots/FIM_Demo_Raistlin.png)

**Monitored Path**: /home/raistlin/FIM_TEST/demo.txt
**Real-time**: Enabled (inotify)

![Linux FIM Alert](screenshots/FIM_Alert_Raistlin.png)

*Checksum change detected on CUPS subscription file*
**Rule**: 550, 553, 554 (Integrity checksum changed, file deleted, file added)

# Privilege Escalation Scenarios (Linux & Windows)

Privilege escalation is a critical post-compromise phase. These exercises demonstrate how Wazuh detects elevated activity on both Linux and Windows endpoints after initial access.

---

## Linux SSH Privilege Escalation (Raistlin)

After obtaining valid SSH access to **Raistlin**, a privilege escalation path was executed to simulate an attacker moving from a standard user to full root control.

**Scenario Highlights**:
- Remote SSH login from attacker host **Takhisis**  
- Escalation to root via `sudo`  
- Execution of privileged administrative actions  
- Wazuh correlation of authentication + PrivEsc events  

**MITRE Techniques**:
- **T1078.003** — Valid Accounts: SSH  
- **T1548.003** — Sudo Elevation  
- **T1059.004** — Unix Shell  
- **T1068** — Privilege Escalation (Linux)  

![SSH PrivEsc Session – Raistlin](https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/SSH%20_Priv_Esc.png)

![SSH PrivEsc Alerts – Raistlin](https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/Priv_Esc_Raistlin_Dashboard_Alerts.png)

[SSH PrivEsc Raw Alerts (CSV)](https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/SSH%20_Priv_Esc.csv)

---

## Windows WinRM Privilege Escalation (Fistandantilus)

Remote privilege escalation was performed on the Windows host **Fistandantilus** using **WinRM** from **Takhisis** via `evil-winrm`.

**Scenario Highlights**:
- Remote PowerShell session  
- UAC elevation attempt  
- Scheduled task creation  
- Service manipulation  
- Registry access attempts  
- Wazuh detection of NTLM logon, PrivEsc, and failed logons  

**MITRE Techniques**:
- **T1021.006** — Remote Services: WinRM  
- **T1548.002** — UAC Elevation  
- **T1053.005** — Scheduled Task PrivEsc  
- **T1543** — Service Execution  
- **T1550.002** — Pass-the-Hash Indicators  
- **T1531** — Account Access Removal  

![Evil-WinRM session on Fistandantilus](screenshots/Evil-WinRM.png)

![Wazuh alerts for WinRM PrivEsc](screenshots/Evil-WinRM_Fistandantilus_Alerts.png)

[Evil-WinRM.csv](screenshots/Evil-WinRM.csv)

<details>
<summary>WinRM Troubleshooting Notes</summary>

- Local accounts require explicit hostname or `.\username` format  
- WinRM must be enabled with `Enable-PSRemoting -Force`  
- TCP 5985 must be allowed through Windows Firewall  
- Blank passwords are rejected by WinRM  
- LocalAccountTokenFilterPolicy must be set for remote admin rights  

</details>

---

## Why This Lab Matters
This homelab proves I can:
    • Deploy and manage a SIEM/XDR platform in a multi-OS environment 
    • Simulate realistic attacks (credential access + reconnaissance) 
    • Detect and triage alerts using stock + Suricata rules 
    • Map detections to MITRE ATT&CK framework 
    • Troubleshoot production-like issues (config errors, agent connectivity, volume overload) 
These are core junior SOC analyst skills transferable to Wazuh, Splunk, Elastic, Microsoft Sentinel, and similar platforms.
**Last updated**: February 2026 

 
