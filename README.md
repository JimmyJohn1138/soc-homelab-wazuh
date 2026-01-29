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
- **Attacker/Agent**: Parrot OS ("Takhisis") — Metasploit, Hydra, Nmap

## Tools & Tech Stack

- **SIEM/XDR**: Wazuh 4.x (manager + agents)
- **Network IDS**: Suricata (Emerging Threats ruleset) on Linux agent
- **Attack Tools**: Metasploit, Hydra, Nmap
- **Logging**: Sysmon (Windows), auditd (Linux), Suricata EVE JSON
- **Hardware**: Bare-metal dual-boot setup (no virtualization for endpoints)

## Simulated Attacks & Detections

### 1. SSH Brute-Force (Linux Endpoint)

**Attack** — Metasploit `auxiliary/scanner/ssh/ssh_login` — 500+ attempts  
**Result** — 656 failed logins  
**Detection** — Rule 5710/57105 → MITRE **T1110.001** (Brute Force – Password Guessing)

![SSH Brute-Force Detection Spike](screenshots/auth-failure-spike.png)  
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

**Test Path**: `C:\Users\Public\FIM_Test\wazuh_test.txt`  
**Real-time**: Enabled (syscheck + Windows file system watcher)

![FIM Demo – Fistandantilus](https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/FIM_Demo_Fistandantilus.PNG)  
*Lifecycle: create → modify → delete events captured*

**MITRE**: **T1070.004** (File Deletion), **T1565.001** (Stored Data Manipulation)

### Windows Registry FIM – Malystryx

![FIM Alert - Fistandantilus](https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/FIM_Alerts_Fistandantilus.png)
**Observed Activity**: Firewall, Defender, TCP/IP, BAM registry changes  
**Rules**: 752/751/750/594  
**MITRE**: **T1112** (Modify Registry)

### Linux FIM – Raistlin & DargaardKeep

![Linux FIM Demo](https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/FIM_Demo_Raistlin.png)
**Monitored Path**: `/etc/cups/subscriptions.conf`  
**Real-time**: Enabled (inotify)

![Linux FIM Alert](https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/FIM_Alert_Raistlin.png)  
*Checksum change detected on CUPS subscription file*

**Rule**: 550 (Integrity checksum changed)

## Why This Lab Matters

This homelab proves I can:
- Deploy and manage a SIEM/XDR platform in a multi-OS environment
- Simulate realistic attacks (credential access + reconnaissance)
- Detect and triage alerts using stock + Suricata rules
- Map detections to MITRE ATT&CK framework
- Troubleshoot production-like issues (config errors, agent connectivity, volume overload)

These are core junior SOC analyst skills transferable to Wazuh, Splunk, Elastic, Microsoft Sentinel, and similar platforms.

**Last updated**: January 2026
