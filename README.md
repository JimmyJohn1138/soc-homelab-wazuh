Wazuh SOC Homelab - Detection Lab
Home SIEM lab with Wazuh
A hands-on Wazuh SIEM homelab demonstrating threat detection in a real-world setup. This project simulates an SSH brute-force attack and shows how Wazuh detects and alerts on it.
Wazuh Dashboard Overview
Wazuh Dashboard showing 962 total events, 656 authentication failures, and a clear spike in the alert groups graph
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

Alerts Generated: 962 total events, including 656 auth failures and 15 successes
Key Rules: 5710 (SSH auth failed), 5503 (PAM login failed)
MITRE ATT&CK Mapping: T1110.001 (Credential Access - Brute Force)
Dashboard Spike: Red/orange peak in Security Events → Authentication Failures, with no level 12+ alerts (realistic tuning scenario)

MITRE ATT&CK Events Table
MITRE view listing 414 hits with timestamps, agent "Raistlin", rules 5503/5710, and descriptions like "PAM: User login failed" and "sshd: Attempt to login using a non-existent user"
Metasploit Terminal Execution
Metasploit console showing module setup, run command, and brute-force start on 192.168.0.9:22
Event JSON Details
Decoded JSON from /var/log/auth.log showing PAM authentication failure for user "Raistlin", srcip 192.168.0.74, rule ID 1765460001.3794635, and decoder "pam"
Lessons Learned

Wazuh reliably detects brute-force even with fake usernames and maps to MITRE tactics
Real-world clock drift in dual-boot lab affects timestamps (e.g., Dec 11, 2025 variations)
Stock rules caught failures at level 5 but didn't escalate to brute-force (5715)—opportunity for custom tuning

This lab runs on my personal hardware. Built to showcase SOC skills for junior analyst roles.
Contact: John Gill | Security+ (SY0-701) | LinkedIn
Last updated: December 2025
