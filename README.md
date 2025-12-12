# Wazuh SOC Homelab - Detection Lab

**Home SIEM lab with Wazuh**  
A hands-on Wazuh SIEM homelab demonstrating real-world threat detection. This project simulates an SSH brute-force attack using Metasploit and showcases Wazuh's alerting, MITRE ATT&CK mapping, and event decoding capabilities.

![Authentication Failure Spike](screenshots/auth-failure-spike.png)  
*Wazuh Dashboard showing a clear spike in authentication failures during the attack*

## Lab Setup
- **Wazuh Manager + Dashboard**: Ubuntu server
- **Agent**: Linux endpoint (Ubuntu/Mint - "Raistlin")
- **Attacker**: Parrot OS with Metasploit
- **Environment**: All components running **bare metal** on personal hardware (dual-boot Linux/Windows setup for realistic testing)

## Simulated Attack: SSH Brute-Force
- Used Metasploit's `auxiliary/scanner/ssh/ssh_login` module
- Targeted username: Raistlin
- Password file: RockYou first 500
- Settings: 20 threads, maximum speed, stop on success false
- Result: 500+ attempts generating hundreds of failed logins in seconds

## Detection Results
- Hundreds of authentication failures captured
- Key rules triggered: SSH/PAM login failures
- Mapped to MITRE ATT&CK **T1110.001** (Brute Force - Credential Access)
- Strong visual spike in Security Events → Authentication Failures

![Metasploit Terminal](screenshots/metasploit-terminal.png)  
*Metasploit console showing module configuration and attack execution on 192.168.0.9:22*

![Event JSON Details](screenshots/event-json-details.png)  
*Decoded event JSON from /var/log/auth.log matching the attack (srcip, failed user, PAM decoder)*

![Authentication Failure Logs](screenshots/auth-failure-logs.png)  
*Detailed logs of repeated failed login attempts*

## Lessons Learned
- Wazuh reliably detects and visualizes brute-force attempts from the same source IP, even with non-existent usernames
- Bare-metal dual-boot environments provide authentic testing conditions (e.g., realistic hardware interactions)
- Stock rules deliver strong baseline detection—ideal starting point for custom tuning in a production SOC

This lab runs entirely on personal bare-metal hardware. Built to demonstrate practical SOC analyst skills for junior roles.

**Contact**: John Gill | Security+ (SY0-701) | [LinkedIn](https://www.linkedin.com/in/jessemcgeejr/)

Last updated: December 2025
