# Intrusion Detection System (IDS) Using Snort

## 📌 Introduction
Intrusion Detection Systems (IDS) are essential for monitoring and analyzing network traffic to detect suspicious activities. This project focuses on setting up and configuring Snort for real-time network intrusion detection using three virtual machines:

- **Ubuntu (Snort IDS System)**  
- **Metasploitable 2 (Victim Machine)**  
- **Kali Linux (Attacker Machine)**

---

## 💡 Setup & Installation
### 🔧 Prerequisites
- A computer running VirtualBox with at least **8GB RAM and 50GB disk space**.
- Three virtual machines:  
  - **Ubuntu (Snort IDS System)**  
  - **Metasploitable 2 (Victim Machine)**  
  - **Kali Linux (Attacker Machine)**
- Administrative/root privileges on all VMs.

### 📶 Network Configuration
| VM             | Adapter 1         | Adapter 2           |
|----------------|-------------------|---------------------|
| **Snort IDS (Ubuntu)**     | NAT (eth0)          | Internal Network: SnortLab (eth1) |
| **Metasploitable 2 (Victim)** | Internal Network: SnortLab (eth0) | None                |
| **Kali Linux (Attacker)**    | Internal Network: SnortLab (eth0) | None                |

**Network Configuration Screenshot:**
![Network Configuration](./images/network_configuration.png)

---

## 🚀 Installing and Configuring Snort (Ubuntu IDS System)
### 📥 Installing Dependencies
```bash
sudo apt-get update
```

### 📥 Installing Snort
```bash
sudo apt-get install snort -y
```

### 🔍 Verifying Installation
```bash
snort -V
```

### 🔧 Configuring Snort Network Interfaces
Configure static IP for monitoring interface (`eth1`):  
Ensure all VMs (Kali and Metasploitable 2) are on the same network.

---

## ✍️ Creating Custom Snort Rules
Create and edit rule file:
```bash
sudo vim /etc/snort/rules/local.rules
```
Add the following rules:
- **ICMP Detection Rule (Ping):**  
```bash
alert icmp any any -> any any (msg:"ALERT! ICMP Ping Detected"; sid:100001; rev:1;)
```
- **Nmap Scan Detection Rule (SYN Scan):**  
```bash
alert tcp any any -> any any (msg:"ALERT! Nmap SYN Scan Detected"; flags:S; sid:100002;)
```
- **SSH Authentication Detection Rule:**  
```bash
alert tcp any any -> any 22 (msg:"ALERT! SSH Authentication Attempt Detected"; sid:100003;)
```
Save the file.

**Snort Rules Configuration Screenshot:**
![Snort Rules Configuration](./images/snort_rules_configuration.png)

---

## 📢 Running Snort to Monitor Traffic
```bash
sudo snort -q -l /var/log/snort -i enp0s8 -A console -c /etc/snort/snort.test
```

---

## 🔨 Testing Snort Rules (Kali Linux Attacker Machine)
| Attack Type | Command |
|-------------|---------|
| **ICMP Ping** | `ping 192.168.1.10` |
| **Nmap SYN Scan** | `nmap -sS 192.168.1.10` |
| **SSH Authentication** | `ssh msfadmin@<Metasploitable_IP>` |

**Attack Attempts from Kali Linux Screenshots:**
- **ICMP Ping Attempt**  
  ![Ping Attempt](./images/ping_attempt.png)
- **Nmap SYN Scan Attempt**  
  ![Nmap Scan Attempt](./images/nmap_scan_attempt.png)
- **SSH Authentication Attempt**  
  ![SSH Attempt](./images/ssh_attempt.png)

---

## 📖 Analyzing Snort Alerts
Check alerts using:
```bash
cat /var/log/snort/alert
```

**Snort Alerts Output Screenshot:**
![Snort Alerts](./images/snort_alerts_output.png)

Verify alerts for:
- **ICMP Ping Detection**
- **Nmap SYN Scan Detection**
- **SSH Brute Force Detection**

---

## 🔐 Mitigation Strategies
- **ICMP Attacks (Ping Floods):**  
  - Disable ICMP echo requests on sensitive systems.  
  - Use firewalls to limit ICMP requests per second.

- **Nmap Scans (Port Scanning):**  
  - Implement rate limiting with firewalls.  
  - Block suspicious IPs automatically using Snort inline mode or tools like Fail2Ban.

- **SSH Brute Force Attacks:**  
  - Use strong passwords and change default SSH port.  
  - Implement IP blocking mechanisms (e.g., iptables, DenyHosts, or Fail2Ban).  
  - Implement two-factor authentication for SSH.

---

## 📚 References
- Snort Documentation: [https://www.snort.org/](https://www.snort.org/)

---

