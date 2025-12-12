# soc-homelab-wazuh
Home SIEM lab with Wazuh 

Wazuh SOC Homelab - Detection Lab
Home SIEM lab with Wazuh
A hands-on Wazuh SIEM homelab demonstrating threat detection in a real-world setup. This project simulates an SSH brute-force attack and shows how Wazuh detects and alerts on it.
Wazuh Dashboard
Wazuh Dashboard showing authentication failure spike
Lab Setup

Wazuh Manager + Dashboard: Ubuntu server
Agent: Linux endpoint (Ubuntu/Mint - "Raistlin")
Attacker: Parrot OS with Metasploit

Simulated Attack: SSH Brute-Force

Used Metasploit's auxiliary/scanner/ssh/ssh_login module
Targeted username: Raistlin
Password file: RockYou first 500
Settings: 20 threads, speed 5, stop on success false
Result: 500+ attempts, 656 authentication failures in <15 seconds

Detection Results

Alerts Generated: 656 auth failures
Key Rules: 5710 (SSH auth failed), 5503 (PAM login failed)
MITRE ATT&CK Mapping: T1110.001 (Credential Access - Brute Force)
Dashboard Spike: Clear red/orange peak in Security Events → Authentication Failures

Authentication Failures Spike
Top 10 alert groups showing massive spike
MITRE ATT&CK View
Events mapped to T1110.001
Event Details
JSON showing srcip (192.168.0.74), failed login, and log source (/var/log/auth.log)
Lessons Learned

Wazuh reliably detects brute-force even with fake usernames
Real-world clock drift in dual-boot lab affects timestamps slightly

This lab runs on my personal hardware. Built to showcase SOC skills for junior analyst roles.
Contact: John Gill | Security+ (SY0-701) | LinkedIn
Last updated: December 2025
