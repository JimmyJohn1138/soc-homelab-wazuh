# Wazuh SOC Detection Homelab

**Hands-on SIEM & XDR Lab – Junior SOC Analyst Portfolio**  
Self-built Wazuh-based Security Operations Center homelab demonstrating real-time threat detection, alert triage, and basic incident response across Linux and Windows endpoints — all on **bare-metal hardware** (no VMs for agents).

![Authentication Failure Spike](screenshots/auth-failure-spike.png)  
*Wazuh dashboard showing massive authentication failure spike during SSH brute-force simulation*

---

## Table of Contents
- [Project Summary & Motivation](#project-summary--motivation)
- [Lab Architecture](#lab-architecture)
- [Tools & Tech Stack](#tools--tech-stack)
- [Simulated Attacks & Detections](#simulated-attacks--detections)
  - [1. SSH Brute-Force (Linux Endpoint)](#1-ssh-brute-force-linux-endpoint)
  - [2. RDP Brute-Force (Windows Endpoint)](#2-rdp-brute-force-windows-endpoint)
  - [3. Network Reconnaissance – Nmap Port Scan (Linux Endpoint)](#3-network-reconnaissance--nmap-port-scan-linux-endpoint)
- [File Integrity Monitoring (FIM) – Windows & Linux](#file-integrity-monitoring-fim--windows--linux)
- [Privilege Escalation Scenarios (Linux & Windows)](#privilege-escalation-scenarios-linux--windows)
  - [Linux SSH Privilege Escalation (Raistlin)](#linux-ssh-privilege-escalation-raistlin)
  - [Windows WinRM Privilege Escalation (Fistandantilus)](#windows-winrm-privilege-escalation-fistandantilus)
- [Why This Lab Matters](#why-this-lab-matters)

---

## Project Summary & Motivation

As an aspiring cybersecurity professional targeting junior SOC analyst roles, I created this lab to bridge the gap between theoretical knowledge (Security+ certification) and hands-on skills employers value most: log ingestion, detection engineering, alert triage, MITRE ATT&CK mapping, and troubleshooting real-world issues.

**Key Outcomes**
- Detected **750+ authentication failures** across SSH & RDP brute-force attacks  
- Mapped to MITRE ATT&CK **T1110** (Brute Force)  
- Validated File Integrity Monitoring (FIM) and network reconnaissance detection  
- Everything runs on **bare-metal personal hardware** for authentic log behavior and network interactions  

**Contact** — John Gill | Security+ (SY0-701) | LinkedIn | Email

---

## Lab Architecture

![Lab Architecture](screenshots/lab-architecture-diagram.jpg)

- **Manager/Dashboard:** Ubuntu 22.04  
- **Linux Agent:** Ubuntu/Mint ("Raistlin") — SSH brute-force, PrivEsc, Linux FIM  
- **Windows Agent:** Windows 10 ("Fistandantilus") — RDP brute-force, WinRM PrivEsc, registry FIM  
- **Attacker/Agent:** Parrot OS ("Takhisis") — Metasploit, Hydra, Nmap, Evil-WinRM  

---

## Tools & Tech Stack

- **SIEM/XDR:** Wazuh 4.x  
- **Network IDS:** Suricata (Emerging Threats ruleset)  
- **Attack Tools:** Metasploit, Hydra, Nmap, Evil-WinRM  
- **Logging:** Sysmon (Windows), auditd (Linux), Suricata EVE JSON  
- **Hardware:** Bare-metal dual-boot setup  

---

## Simulated Attacks & Detections

### 1. SSH Brute-Force (Linux Endpoint)

**Attack:** Metasploit `auxiliary/scanner/ssh/ssh_login`  
**Result:** 656 failed logins  
**Detection:** Rule 5710 / 57105 → MITRE **T1110.001**

![SSH Brute Force Spike](screenshots/auth-failure-spike.png)

![Metasploit Terminal](screenshots/metasploit-terminal.png)

![SSH Event JSON](screenshots/event-json-details.png)

---

### 2. RDP Brute-Force (Windows Endpoint)

**Attack:** Hydra — 101 failed attempts  
**Detection:** Rule 60122 → Level 10 → MITRE **T1110**

![RDP Dashboard](screenshots/rdp-dashboard-overview.png)

![Hydra Terminal](screenshots/rdp-hydra-terminal.png)

![RDP MITRE Mapping](screenshots/rdp-mitre-bruteforce.png)

![RDP Event JSON](screenshots/rdp-event-json)

---

### 3. Network Reconnaissance – Nmap Port Scan (Linux Endpoint)

**Attack:** Nmap SYN scan  
**Detection:** Suricata ET SCAN → Wazuh ingestion  
**MITRE:** **T1595**, **T1046**

![Nmap Scan Output](screenshots/NMapScan.png)

![Nmap Spike](screenshots/NMap Spike .png)

![Suricata Alerts](screenshots/SuricataAlerts.png)

---

## File Integrity Monitoring (FIM) – Windows & Linux

### Windows File FIM – Lifecycle Test (Fistandantilus)

![FIM Demo – Fistandantilus](screenshots/FIM_Demo_Fistandantilus.PNG)

**MITRE:** **T1070.004**, **T1565.001**

---

### Windows Registry FIM – Fistandantilus

![Registry FIM Alerts](screenshots/FIM_Alerts_Fistandantilus.png)

**Rules:** 752 / 751 / 750 / 594  
**MITRE:** **T1112**

---

### Linux FIM – Raistlin

![Linux FIM Demo](screenshots/FIM_Demo_Raistlin.png)

![Linux FIM Alert](screenshots/FIM_Alert_Raistlin.png)

**Rules:** 550 / 553 / 554

---

## Privilege Escalation Scenarios (Linux & Windows)

### Linux SSH Privilege Escalation (Raistlin)

![SSH PrivEsc Session](screenshots/SSH _Priv_Esc.png)

![SSH PrivEsc Alerts](screenshots/Priv_Esc_Raistlin_Dashboard_Alerts.png)

[SSH PrivEsc Raw Alerts (CSV)](screenshots/SSH _Priv_Esc.csv)

---

### Windows WinRM Privilege Escalation (Fistandantilus)

![Evil-WinRM Session](screenshots/Evil-WinRM.png)

![WinRM PrivEsc Alerts](screenshots/Evil-WinRM_Fistandantilus_Alerts.png)

[Evil-WinRM.csv](screenshots/Evil-WinRM.csv)

---

## Why This Lab Matters

This homelab demonstrates the ability to:

- Deploy and manage a SIEM/XDR platform  
- Simulate realistic attacks  
- Detect & triage alerts  
- Map detections to MITRE ATT&CK  
- Troubleshoot ingestion, configuration, and latency issues  

**Last updated:** February 2026


 
