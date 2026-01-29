Wazuh SOC Homelab – Detection Engineering Portfolio
Hands-on SOC Detection & Response Lab with Wazuh

A fully self-built Security Operations Center (SOC) homelab using Wazuh — an open-source SIEM and XDR platform. This project demonstrates end-to-end threat detection and response workflows in a realistic multi-OS environment, focusing on entry-level SOC analyst skills: log ingestion, alert triage, detection engineering, troubleshooting, and basic incident response.

file:///screenshots/auth-failure-spike.png  
Wazuh Dashboard showing massive authentication failure spike during SSH brute-force simulation

Project Summary and Motivation
As an aspiring cybersecurity professional targeting junior SOC analyst roles, I created this lab to bridge the gap between theoretical knowledge (e.g., Microsoft SC-200/SC-300 coursework, Security+ certification) and hands-on experience that employers actually look for.

This homelab replicates real SOC workflows:

Deploying and managing agents across Linux and Windows endpoints

Ingesting and enriching logs

Detecting attacks using stock and custom rules

Triaging alerts in the dashboard

Mapping to MITRE ATT&CK

Simulating incident response actions

It highlights my ability to troubleshoot common production issues (agent connectivity, indexer performance, certificate errors, and configuration failures) — skills directly transferable to tools like Wazuh, Splunk, Elastic, or Microsoft Sentinel.

Everything runs on bare-metal personal hardware (no VMs for the endpoints) to ensure authentic log behavior and network interactions.

Contact: John Gill | Security+ (SY0-701) | LinkedIn

Lab Architecture
file:///screenshots/lab-architecture-diagram.jpg  
Homelab network topology: Wazuh manager centralizing logs from Linux/Windows endpoints and monitored attacker machine

⚙️ Setup Overview
This homelab runs entirely on bare‑metal hardware with one attacker system (also monitored as a Wazuh agent) and two additional endpoints. All systems report logs to a central Wazuh Manager for detection and visualization.

Wazuh Manager/Dashboard (Ubuntu 22.04)  
Installed using the official Wazuh guide. Configured to collect logs from Windows, Linux, and Parrot agents.

Windows 10 Agent (“Fistandantilus”)  
Wazuh agent + Sysmon installed. Used for RDP brute-force, malware execution, and file integrity monitoring.

Linux Agent (“Raistlin”)  
Wazuh agent + auditd + Suricata installed. Used for SSH brute-force, privilege escalation, file monitoring, and network reconnaissance.

Parrot OS Attacker + Agent (“Takhisis”)  
Dual role: generates safe attack traffic and reports its own logs to Wazuh. Tools: Hydra, Nmap, Metasploit.

Simulated Attacks & Detection Results
1. SSH Brute-Force Attack (Linux Endpoint)
Attack Execution  
Tool: Metasploit auxiliary/scanner/ssh/ssh_login  
Result: 656 failed login attempts in seconds

file:///screenshots/metasploit-terminal.png

Detection

Triggered Wazuh rule 57105 (multiple SSH authentication failures)

Mapped to MITRE ATT&CK T1110.001 (Brute Force – Password Guessing)

file:///screenshots/event-json-details.png  
file:///screenshots/auth-failure-logs.png

2. RDP Brute-Force Attack (Windows Endpoint)
Attack Execution  
Tool: Hydra on Parrot OS
Result: 101 failed login attempts

file:///screenshots/rdp-dashboard-overview.png  
file:///screenshots/rdp-hydra-terminal.png

Detection

Windows Event ID 4625 captured

Triggered Wazuh rule 18120 → Level 10 alerts

Mapped to MITRE ATT&CK T1110.003 (Brute Force – Password Spraying)

file:///screenshots/windows-agent-status.png  
file:///screenshots/rdp-mitre-bruteforce.png  
https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/rdp-event-json

3. Network Reconnaissance – Nmap Port Scan (Linux Endpoint)
Detection Setup  
The Linux endpoint (“Raistlin”) runs Suricata alongside the Wazuh agent.
EVE JSON logging is enabled to capture alerts and protocol metadata:

https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/CorrectedEve-Log%20.png

Suricata service is enabled and started:

bash
sudo systemctl enable --now suricata
file:///screenshots/Suricata.png

Attack Execution  
From the Parrot OS attacker system (“Takhisis”), a SYN scan with OS and service detection was launched:

bash
nmap -sS -A -p 1-1000 192.168.0.9
file:///screenshots/NMapScan.png

Detection Results  
Suricata detects Nmap reconnaissance activity using the Emerging Threats ruleset. The alert is forwarded to Wazuh, indexed, and displayed in the dashboard.

https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/NMap%20Spike%20.png

Detection Summary  
https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/SuricataAlerts.png

4. File Integrity Monitoring (Windows Endpoint – Fistandantilus)
Test Execution
A PowerShell script simulated a full file lifecycle:

powershell
"initial"  | Out-File C:\Users\Public\FIM_Test\wazuh_test.txt
Start-Sleep 1
"modified" | Out-File C:\Users\Public\FIM_Test\wazuh_test.txt
Start-Sleep 1
Remove-Item C:\Users\Public\FIM_Test\wazuh_test.txt -Force
[Looks like the result wasn't safe to show. Let's switch things up and try something else!]

Detection
Wazuh captured all three events:

Rule 554 → File added

Rule 550 → File modified

Rule 553 → File deleted

[Looks like the result wasn't safe to show. Let's switch things up and try something else!]

Troubleshooting Performed
During initial testing, the Windows agent produced repeated warnings:

Invalid element in the configuration: 'merge'

Invalid element in the configuration: 'registry'

These errors indicated that the manager’s shared configuration was pushing unsupported XML to Windows agents.

Fix implemented:

Removed unsupported <merge> and <registry> blocks from /var/ossec/etc/shared/default/agent.conf

Restarted the Wazuh Manager

Restarted the Windows agent

Confirmed clean startup with no XML warnings

Re-ran lifecycle test and validated real-time detection

Validation
Final confirmation was obtained via dashboard alert table and raw JSON metadata:

[Looks like the result wasn't safe to show. Let's switch things up and try something else!]

Outcome
This homelab demonstrates:

Real-world attack simulation

End-to-end detection workflows

Cross-platform agent deployment

Troubleshooting and config validation

MITRE ATT&CK mapping

Dashboard triage and alert analysis

It is designed to showcase entry-level SOC analyst readiness with reproducible evidence and clean documentation.Wazuh SOC Homelab – Detection Engineering Portfolio
Hands-on SOC Detection & Response Lab with Wazuh

A fully self-built Security Operations Center (SOC) homelab using Wazuh — an open-source SIEM and XDR platform. This project demonstrates end-to-end threat detection and response workflows in a realistic multi-OS environment, focusing on entry-level SOC analyst skills: log ingestion, alert triage, detection engineering, troubleshooting, and basic incident response.

file:///screenshots/auth-failure-spike.png  
Wazuh Dashboard showing massive authentication failure spike during SSH brute-force simulation

Project Summary and Motivation
As an aspiring cybersecurity professional targeting junior SOC analyst roles, I created this lab to bridge the gap between theoretical knowledge (e.g., Microsoft SC-200/SC-300 coursework, Security+ certification) and hands-on experience that employers actually look for.

This homelab replicates real SOC workflows:

Deploying and managing agents across Linux and Windows endpoints

Ingesting and enriching logs

Detecting attacks using stock and custom rules

Triaging alerts in the dashboard

Mapping to MITRE ATT&CK

Simulating incident response actions

It highlights my ability to troubleshoot common production issues (agent connectivity, indexer performance, certificate errors, and configuration failures) — skills directly transferable to tools like Wazuh, Splunk, Elastic, or Microsoft Sentinel.

Everything runs on bare-metal personal hardware (no VMs for the endpoints) to ensure authentic log behavior and network interactions.

Contact: John Gill | Security+ (SY0-701) | LinkedIn

Lab Architecture
file:///screenshots/lab-architecture-diagram.jpg  
Homelab network topology: Wazuh manager centralizing logs from Linux/Windows endpoints and monitored attacker machine

⚙️ Setup Overview
This homelab runs entirely on bare‑metal hardware with one attacker system (also monitored as a Wazuh agent) and two additional endpoints. All systems report logs to a central Wazuh Manager for detection and visualization.

Wazuh Manager/Dashboard (Ubuntu 22.04)  
Installed using the official Wazuh guide. Configured to collect logs from Windows, Linux, and Parrot agents.

Windows 10 Agent (“Fistandantilus”)  
Wazuh agent + Sysmon installed. Used for RDP brute-force, malware execution, and file integrity monitoring.

Linux Agent (“Raistlin”)  
Wazuh agent + auditd + Suricata installed. Used for SSH brute-force, privilege escalation, file monitoring, and network reconnaissance.

Parrot OS Attacker + Agent (“Takhisis”)  
Dual role: generates safe attack traffic and reports its own logs to Wazuh. Tools: Hydra, Nmap, Metasploit.

Simulated Attacks & Detection Results
1. SSH Brute-Force Attack (Linux Endpoint)
Attack Execution  
Tool: Metasploit auxiliary/scanner/ssh/ssh_login  
Result: 656 failed login attempts in seconds

file:///screenshots/metasploit-terminal.png

Detection

Triggered Wazuh rule 57105 (multiple SSH authentication failures)

Mapped to MITRE ATT&CK T1110.001 (Brute Force – Password Guessing)

file:///screenshots/event-json-details.png  
file:///screenshots/auth-failure-logs.png

2. RDP Brute-Force Attack (Windows Endpoint)
Attack Execution  
Tool: Hydra on Parrot OS
Result: 101 failed login attempts

file:///screenshots/rdp-dashboard-overview.png  
file:///screenshots/rdp-hydra-terminal.png

Detection

Windows Event ID 4625 captured

Triggered Wazuh rule 18120 → Level 10 alerts

Mapped to MITRE ATT&CK T1110.003 (Brute Force – Password Spraying)

file:///screenshots/windows-agent-status.png  
file:///screenshots/rdp-mitre-bruteforce.png  
https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/rdp-event-json

3. Network Reconnaissance – Nmap Port Scan (Linux Endpoint)
Detection Setup  
The Linux endpoint (“Raistlin”) runs Suricata alongside the Wazuh agent.
EVE JSON logging is enabled to capture alerts and protocol metadata:

https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/CorrectedEve-Log%20.png

Suricata service is enabled and started:

bash
sudo systemctl enable --now suricata
file:///screenshots/Suricata.png

Attack Execution  
From the Parrot OS attacker system (“Takhisis”), a SYN scan with OS and service detection was launched:

bash
nmap -sS -A -p 1-1000 192.168.0.9
file:///screenshots/NMapScan.png

Detection Results  
Suricata detects Nmap reconnaissance activity using the Emerging Threats ruleset. The alert is forwarded to Wazuh, indexed, and displayed in the dashboard.

https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/NMap%20Spike%20.png

Detection Summary  
https://github.com/JimmyJohn1138/soc-homelab-wazuh/blob/main/screenshots/SuricataAlerts.png

4. File Integrity Monitoring (Windows Endpoint – Fistandantilus)
Test Execution
A PowerShell script simulated a full file lifecycle:

powershell
"initial"  | Out-File C:\Users\Public\FIM_Test\wazuh_test.txt
Start-Sleep 1
"modified" | Out-File C:\Users\Public\FIM_Test\wazuh_test.txt
Start-Sleep 1
Remove-Item C:\Users\Public\FIM_Test\wazuh_test.txt -Force
[Looks like the result wasn't safe to show. Let's switch things up and try something else!]

Detection
Wazuh captured all three events:

Rule 554 → File added

Rule 550 → File modified

Rule 553 → File deleted

[Looks like the result wasn't safe to show. Let's switch things up and try something else!]

Troubleshooting Performed
During initial testing, the Windows agent produced repeated warnings:

Invalid element in the configuration: 'merge'

Invalid element in the configuration: 'registry'

These errors indicated that the manager’s shared configuration was pushing unsupported XML to Windows agents.

Fix implemented:

Removed unsupported <merge> and <registry> blocks from /var/ossec/etc/shared/default/agent.conf

Restarted the Wazuh Manager

Restarted the Windows agent

Confirmed clean startup with no XML warnings

Re-ran lifecycle test and validated real-time detection

Validation
Final confirmation was obtained via dashboard alert table and raw JSON metadata:

[Looks like the result wasn't safe to show. Let's switch things up and try something else!]

Outcome
This homelab demonstrates:

Real-world attack simulation

End-to-end detection workflows

Cross-platform agent deployment

Troubleshooting and config validation

MITRE ATT&CK mapping

Dashboard triage and alert analysis

It is designed to showcase entry-level SOC analyst readiness with reproducible evidence and clean documentation.
