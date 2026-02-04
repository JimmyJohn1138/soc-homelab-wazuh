# Wazuh SOC Detection Homelab  
**Hands-on SIEM & XDR Lab – Junior SOC Analyst Portfolio**

Self-built Wazuh-based Security Operations Center homelab demonstrating real-time threat detection, alert triage, and basic incident response across Linux and Windows endpoints — all on **bare-metal** hardware (no VMs for agents).

> **Note:** Some embedded screenshot/dashboard images failed to render in earlier versions. This document focuses on structure, content, reproducibility, and technical detail.

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
  - [Windows File FIM – Lifecycle Test](#windows-file-fim--lifecycle-test)
  - [Windows Registry FIM](#windows-registry-fim)
  - [Linux FIM](#linux-fim)
- [Why This Lab Matters](#why-this-lab-matters)
- [Contact](#contact)

## Project Summary & Motivation

As an aspiring cybersecurity professional targeting junior SOC analyst roles, I created this lab to bridge the gap between theoretical knowledge (Security+ certification) and hands-on skills employers value most: log ingestion, detection engineering, alert triage, MITRE ATT&CK mapping, and troubleshooting real-world issues.

**Key Outcomes:**

- Detected 750+ authentication failures across SSH & RDP brute-force attacks
- Mapped to MITRE ATT&CK **T1110** (Brute Force)
- Validated File Integrity Monitoring (FIM) and network reconnaissance detection
- Added **Troubleshooting-Driven Reproducibility** sections to demonstrate real SOC problem-solving
- Everything runs on bare-metal personal hardware → authentic log behavior & network interactions

**Contact** — John Gill | Security+ (SY0-701) | LinkedIn | Email

## Lab Architecture

- **Manager / Dashboard:** Ubuntu 22.04  
- **Linux Agent:** Ubuntu/Mint ("Raistlin") — SSH brute-force, PrivEsc, Linux FIM  
- **Windows Agent:** Windows 10 ("Fistandantilus") — RDP brute-force, WinRM PrivEsc, registry FIM  
- **Attacker / Agent:** Parrot OS ("Takhisis") — Metasploit, Hydra, Nmap, Evil-WinRM  

Wazuh Manager centralizes logs from all bare-metal agents + the monitored attacker machine.

## Tools & Tech Stack

- **SIEM/XDR:** Wazuh 4.x (manager + agents)  
- **Network IDS:** Suricata (Emerging Threats ruleset) on Linux agent  
- **Attack Tools:** Metasploit, Hydra, Nmap, Evil-WinRM  
- **Logging:** Sysmon (Windows), auditd (Linux), Suricata EVE JSON  
- **Hardware:** Bare-metal dual-boot setup (no virtualization for endpoints)

## Simulated Attacks & Detections

### 1. SSH Brute-Force (Linux Endpoint)

- **Attack** — Metasploit `auxiliary/scanner/ssh/ssh_login` — 500+ attempts  
- **Result** — 656 failed logins  
- **Detection** — Rule 5710 / 57105 → MITRE **T1110.001** (Brute Force – Password Guessing)

**Troubleshooting-Driven Reproducibility**

**Symptoms**  
- Only rule 5710 fired  
- No correlation alerts  
- Sometimes no alerts at all  

**Root Causes**  
- `auth.log` not monitored  
- Agent connectivity issues  
- Indexer queue lag  

**Fix Implemented**

```xml
<localfile>
  <location>/var/log/auth.log</location>
  <log_format>syslog</log_format>
</localfile>
```

**Validation**  
Re-ran attack → 656 failures detected, Level-10 brute-force alert fired

### 2. RDP Brute-Force (Windows Endpoint)

- **Attack** — Hydra — 101 failed attempts targeting administrator  
- **Result** — High volume of Windows Event ID 4625  
- **Detection** — Rule 60122 → escalated to level 10 → MITRE **T1110**

**Troubleshooting-Driven Reproducibility**

**Symptoms**  
- No 4625 logs ingested  
- No brute-force alerts  
- Hydra activity not detected  

**Root Causes**  
- Windows auditing disabled  
- EventChannel not monitored  
- Sysmon not forwarding logs  

**Fix Implemented**

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```
Validation
Re-ran attack → 656 failures detected, Level-10 brute-force alert fired
2. RDP Brute-Force (Windows Endpoint)

Attack — Hydra — 101 failed attempts targeting administrator
Result — High volume of Windows Event ID 4625
Detection — Rule 60122 → escalated to level 10 → MITRE T1110

Troubleshooting-Driven Reproducibility
Symptoms

No 4625 logs ingested
No brute-force alerts
Hydra activity not detected

Root Causes

Windows auditing disabled
EventChannel not monitored
Sysmon not forwarding logs

Fix Implemented
```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```
Validation
101 failures detected, Rule 60122 fired
3. Network Reconnaissance – Nmap Port Scan (Linux Endpoint)

Attack — Nmap SYN scan with OS/service detection
Detection — Suricata ET SCAN rule → Wazuh ingestion → alert spike
MITRE — T1595 / T1046

Troubleshooting-Driven Reproducibility
Symptoms

No Suricata alerts
eve.json empty or not ingested
Wazuh not receiving IDS logs

Root Causes

Suricata disabled
EVE JSON output disabled
Wazuh not monitoring eve.json

Fix Implemented
```xml
<localfile>
  <location>/var/log/suricata/eve.json</location>
  <log_format>json</log_format>
</localfile>
```
Validation
Re-ran Nmap → Suricata alerts successfully ingested into Wazuh
Privilege Escalation Scenarios (Linux & Windows)
Linux SSH Privilege Escalation (Raistlin)
Scenario Highlights

Remote SSH login from attacker host Takhisis
Escalation to root via sudo
Execution of privileged administrative actions
Wazuh correlation of authentication + PrivEsc events

MITRE Techniques

T1078.003 — Valid Accounts: SSH
T1548.003 — Sudo Elevation
T1059.004 — Unix Shell
T1068 — Privilege Escalation (Linux)

Troubleshooting-Driven Reproducibility
Fix Implemented
```xml
<syscheck>
  <directories check_all="yes">/etc</directories>
  <directories check_all="yes">/usr/bin</directories>
</syscheck>
```
Validation
SSH → sudo → root → PrivEsc alerts fired
Windows WinRM Privilege Escalation (Fistandantilus)
Scenario Highlights

Remote PowerShell session via evil-winrm
UAC elevation attempt
Scheduled task creation, service manipulation, registry access
Wazuh detection of NTLM logon, PrivEsc indicators, failed logons

MITRE Techniques

T1021.006 — Remote Services: WinRM
T1548.002 — UAC Elevation
T1053.005 — Scheduled Task PrivEsc
T1543 — Service Execution
T1550.002 — Pass-the-Hash Indicators
T1531 — Account Access Removal

Troubleshooting-Driven Reproducibility
Fix Implemented
```xml<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
Validation
WinRM → PowerShell → PrivEsc → Alerts fired
File Integrity Monitoring (FIM) – Windows & Linux
Windows File FIM – Lifecycle Test (Fistandantilus)
MITRE: T1070.004, T1565.001
Fix Implemented
```xml
<syscheck>
  <directories check_all="yes">C:\Users\Public\FIM_Test</directories>
</syscheck>
```
Validation
Add → modify → delete → Rules 550/553/554 fired
Windows Registry FIM – Fistandantilus
Rules: 752 / 751 / 750 / 594
MITRE: T1112
Fix Implemented
```xml
<syscheck>
  <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
</syscheck>
```
Validation
Add → modify → delete → Rules 750/751/752 fired
Linux FIM – Raistlin
Rules: 550, 553, 554
Fix Implemented
```xml
<syscheck>
  <directories check_all="yes">/etc</directories>
  <directories check_all="yes">/usr/bin</directories>
</syscheck>
```
Validation
Add → modify → delete → Rules 550/553/554 fired
Why This Lab Matters
This homelab proves I can:

Deploy and manage a production-like SIEM/XDR platform
Simulate realistic attacks across Linux and Windows endpoints
Detect & triage alerts with accurate MITRE ATT&CK mapping
Implement and validate File Integrity Monitoring on both OS families
Troubleshoot real-world ingestion, configuration, and latency issues in a bare-metal environment

Last updated: February 2026
text
