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
  - [4. Windows Remote Privilege Escalation (WinRM)](#4-windows-remote-privilege-escalation-winrm)
- [File Integrity Monitoring (FIM) – Windows & Linux](#file-integrity-monitoring-fim--windows--linux)
- [Why This Lab Matters](#why-this-lab-matters)

## Project Summary & Motivation

As an aspiring cybersecurity professional targeting junior SOC analyst roles, I created this lab to bridge the gap between theoretical knowledge (Security+ certification) and hands-on skills employers value most: log ingestion, detection engineering, alert triage, MITRE mapping, and troubleshooting real-world issues.

**Key Outcomes**:
- Detected **750+ authentication failures** across SSH & RDP brute-force attacks  
- Mapped to MITRE ATT&CK **T1110** (Brute Force)  
- Validated File Integrity Monitoring (FIM) and network reconnaissance detection  

Everything runs on **bare-metal personal hardware** to ensure authentic log behavior and network interactions.

**Contact** — John Gill | Security+ (SY0-701) | [LinkedIn](https://www.linkedin.com/in/jessemcgeejr/) | [Email](mailto:john.rm.gill.3@gmail.com)

## Lab Architecture

![Lab Topology](screenshots/lab-architecture-diagram.jpg)  
*Wazuh Manager centralizing logs from bare-metal Linux/Windows agents + monitored attacker*

- **Manager/Dashboard**: Ubuntu 22.04  
- **Linux Agent**: Ubuntu/Mint ("Raistlin") — SSH brute-force + FIM  
- **Windows Agent**: Windows 10 ("Fistandantilus") — RDP brute-force + registry FIM  
- **Attacker/Agent**: Parrot OS ("Takhisis") — Metasploit, Hydra, Nmap, Evil-WinRM  

## Tools & Tech Stack

- **SIEM/XDR**: Wazuh 4.x (manager + agents)  
- **Network IDS**: Suricata (Emerging Threats ruleset) on Linux agent  
- **Attack Tools**: Metasploit, Hydra, Nmap, Evil-WinRM  
- **Logging**: Sysmon (Windows), auditd (Linux), Suricata EVE JSON  
- **Hardware**: Bare-metal dual-boot setup (no virtualization for endpoints)

## Simulated Attacks & Detections

---

### 1. SSH Brute-Force (Linux Endpoint)

**Attack** — Metasploit `auxiliary/scanner/ssh/ssh_login` — 500+ attempts  
**Result** — 656 failed logins  
**Detection** — Rule 5710/57105 → MITRE **T1110.001** (Brute Force – Password Guessing)

![SSH Brute-Force Detection Spike](screenshots/auth-failure-spike.png)

![Metasploit Execution](screenshots/metasploit-terminal.png)

![SSH Event JSON](screenshots/event-json-details.png)

---

### 2. RDP Brute-Force (Windows Endpoint)

**Attack** — Hydra — 101 failed attempts targeting administrator  
**Result** — Windows Event ID 4625 volume  
**Detection** — Rule 60122 → escalated to level 10 → MITRE **T1110**

![RDP Dashboard Spike](screenshots/rdp-dashboard-overview.png)

![Hydra Execution](screenshots/rdp-hydra-terminal.png)

![RDP MITRE Mapping](screenshots/rdp-mitre-bruteforce.png)

![RDP Event JSON](screenshots/rdp-event-json)

---

### 3. Network Reconnaissance – Nmap Port Scan (Linux Endpoint)

**Attack** — Nmap SYN scan with OS/service detection  
**Detection** — Suricata ET SCAN rule → Wazuh ingestion → alert spike  
**MITRE** — **T1595/T1046** (Active Scanning / Network Service Discovery)

![Nmap Terminal Output](screenshots/NMapScan.png)

![Nmap Alert Spike](screenshots/NMap%20Spike%20.png)

![Suricata Alerts](screenshots/SuricataAlerts.png)

---

### 4. Windows Remote Privilege Escalation (WinRM)

Remote privilege escalation was performed on the Windows host **Fistandantilus** using **WinRM** from the attacker machine (**Takhisis**) via `evil-winrm`. This demonstrates Windows-native lateral movement and privilege escalation using PowerShell remoting.

#### MITRE Techniques Simulated

| MITRE ID      | Technique Description |
|---------------|-----------------------|
| T1021.006     | Remote Services: WinRM |
| T1059.001     | PowerShell Execution |
| T1548.002     | UAC Elevation |
| T1053.005     | Scheduled Task PrivEsc |
| T1543         | Service Execution |
| T1110.001     | Failed Logon Attempts |
| T1484         | Domain Policy Modification |
| T1550.002     | Use Alternate Authentication Material |
| T1078.002     | Valid Accounts |
| T1531         | Account Access Removal |

#### Remote WinRM Session

The following screenshot captures the full sequence of commands executed during the WinRM session, including identity enumeration, UAC elevation attempt, scheduled task creation, service manipulation, and registry access attempts. These actions directly correspond to the MITRE-mapped alerts shown in the Wazuh dashboard.

![Evil-WinRM session on Fistandantilus](screenshots/Evil-WinRM.png)

#### Detection Summary

![Wazuh alerts for WinRM PrivEsc](screenshots/Evil-WinRM_Fistandantilus_Alerts.png)

#### Raw Alert Data

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

## File Integrity Monitoring (FIM) – Windows & Linux

### Windows File FIM – Lifecycle Test (Fistandantilus)

**Test Path**: `C:\Users\Public\FIM_Test\wazuh_test.txt`  
**Real-time**: Enabled (syscheck + Windows file system watcher)

![FIM Demo – Fistandantilus](screenshots/FIM_Demo_Fistandantilus.PNG)

**MITRE**: **T1070.004**, **T1565.001**

### Windows Registry FIM – Fistandantilus

![FIM Alert - Fistandantilus](screenshots/FIM_Alerts_Fistandantilus.png)

**Rules**: 752/751/750/594  
**MITRE**: **T1112**

### Linux FIM – Raistlin

![Linux FIM Demo](screenshots/FIM_Demo_Raistlin.png)

![Linux FIM Alert](screenshots/FIM_Alert_Raistlin.png)

**Rules**: 550, 553, 554

---

## Why This Lab Matters

This homelab proves I can:

- Deploy and manage a SIEM/XDR platform  
- Simulate realistic attacks  
- Detect and triage alerts  
- Map detections to MITRE ATT&CK  
- Troubleshoot production-like issues  

**Last updated**: February 2026

