# Wazuh SOC Homelab - Detection Lab

**Home SIEM lab with Wazuh**  
A hands-on Wazuh SIEM homelab demonstrating real-world threat detection across Linux and Windows endpoints. This project simulates SSH and RDP brute-force attacks using Metasploit and Hydra, showcasing Wazuh's alerting, MITRE ATT&CK mapping, and event decoding.

![SSH Authentication Failure Spike](screenshots/auth-failure-spike.png)  
*Wazuh Dashboard showing massive authentication failure spike from SSH attack*

## Lab Setup
- **Wazuh Manager + Dashboard**: Ubuntu server
- **Agents**: Linux endpoint (Ubuntu/Mint - "Raistlin") and Windows 10 endpoint ("Fistandantilus")
- **Attacker**: Parrot OS with Metasploit and Hydra
- **Environment**: All components running **bare metal** on personal hardware (dual-boot Linux/Windows setup for realistic testing)

## Simulated Attack: SSH Brute-Force
- Used Metasploit's `auxiliary/scanner/ssh/ssh_login` module
- Targeted username: Raistlin
- Password file: RockYou first 500
- Settings: 20 threads, maximum speed, stop on success false
- Result: 500+ attempts generating 656 failed logins in seconds

![Metasploit Terminal](screenshots/metasploit-terminal.png)  
*Metasploit console showing module configuration and attack execution*

## Detection Results (Linux Agent)
- 656 authentication failures captured
- Key rules triggered: SSH/PAM login failures
- Mapped to MITRE ATT&CK **T1110.001** (Brute Force - Credential Access)

![SSH Event JSON Details](screenshots/event-json-details.png)  
*Decoded event JSON from /var/log/auth.log matching the attack*

![SSH Authentication Failure Logs](screenshots/auth-failure-logs.png)  
*Detailed logs of repeated failed login attempts*

## Simulated Attack: Windows RDP Brute-Force
- Used Hydra on Parrot OS attacker
- Targeted local "administrator" account on Windows 10 endpoint ("Fistandantilus")
- Password file: RockYou first 100
- Settings: 4 threads
- Result: 101 failed login attempts in minutes

![RDP Dashboard Overview](screenshots/rdp-dashboard-overview.png)  
*Wazuh Dashboard showing 101 authentication failures and clear spike*

![Hydra Terminal](screenshots/rdp-hydra-terminal.png)  
*Hydra execution confirming 101 attempts from attacker IP 192.168.0.74*

## Detection Results (Windows Agent)
- 101 failed logons captured via Windows Security Event 4625
- Escalated to level 10 alerts
- Mapped to MITRE ATT&CK **Brute Force** tactic (Credential Access)

![Windows Agent Status](screenshots/windows-agent-status.png)  
*Bare-metal Windows 10 agent ("Fistandantilus") actively sending alerts*

![RDP MITRE Framework View](screenshots/rdp-mitre-bruteforce.png)  
*Framework view confirming Brute Force tactic and level 10 severity*

![RDP Event JSON](screenshots/rdp-event-json)  
*Decoded Event 4625 showing failed logon from attacker IP 192.168.0.74 (text example of raw alert)*

## Lessons Learned
- Wazuh reliably detects and visualizes brute-force attempts across Linux (SSH) and Windows (RDP) endpoints
- Bare-metal dual-boot environments provide authentic testing conditions
- Stock rules deliver strong baseline detection with volume-based escalation—ideal foundation for custom tuning in a production SOC

This lab runs entirely on personal bare-metal hardware. Built to demonstrate practical SOC analyst skills for junior roles.

**Contact**: John Gill | Security+ (SY0-701) | [LinkedIn](https://www.linkedin.com/in/jessemcgeejr/)

Last updated: December 2025
