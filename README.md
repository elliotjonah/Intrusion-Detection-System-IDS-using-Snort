# Intrusion Detection System (IDS) Using Snort

## 📌 Introduction
Intrusion Detection Systems (IDS) are essential for monitoring and analyzing network traffic to detect suspicious activities. This project focuses on setting up and configuring Snort for real-time network intrusion detection using three virtual machines:

- **Ubuntu (Snort IDS System)**  
- **Metasploitable 2 (Victim Machine)**  
- **Kali Linux (Attacker Machine)**

---

## 💡 Setup & Installation
### 🔧 Prerequisites
- A computer running VirtualBox with at least **8GB RAM and 100GB disk space**.
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

---

## 🚀 Installing and Configuring Snort (Ubuntu IDS System)
### 📥 Installing Dependencies
```bash
sudo apt-get update
```
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-02%20020753.png>

### 📥 Installing Snort
```bash
sudo apt-get install snort -y
```
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-02%20020913.png>

### 🔍 Verifying Installation
```bash
snort -V
```
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-20%20210627.png>

### 🔧 Configuring Snort Network Interfaces
Configure static IP for monitoring interface (`eth1`):  
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-02%20041340.png>
This is the interface where  snort is going to listen on. 
Also we have to make sure that our other VMs( Kali and Metasploitable 2) should be on the same network.


---
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-02%20233401.png>
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-02%20233521.png>

---

## ✍️ Creating Custom Snort Rules
Create and edit rule file:
```bash
sudo vim /etc/snort/rules/local.rules
```
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-02%20224626.png>
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
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-03%20002801.png>
Save the file.

**Snort Rules Configuration Screenshot:**
Edit the configuration file: sudo vim /etc/snort/snort.test
Note: By default, snort configuration files are located in snort.conf but a made a copy of it and save it in snort.test 

<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-02%20221549.png>
Specify the network you want to monitor
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-02%20222547.png>
include $RULE_PATH/local.rules

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
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-03%20005022.png> 
  ![Ping Attempt](./images/ping_attempt.png)
- **Nmap SYN Scan Attempt**
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/2f4d843a3b2cbdcc6a0103f7f335760828f23950/Screenshot%202025-03-03%20001511.png>
  ![Nmap Scan Attempt](./images/nmap_scan_attempt.png)
- **SSH Authentication Attempt**
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-20%20233444.png>
  ![SSH Attempt](./images/ssh_attempt.png)

---

## 📖 Analyzing Snort Alerts
Check alerts using:
```bash
cat /var/log/snort/alert
```
<img src = >

**Snort Alerts Output Screenshot:**
![Snort Alerts](./images/snort_alerts_output.png)

Verify alerts for:
- **ICMP Ping Detection**
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-21%20000734.png>
- **Nmap SYN Scan Detection**
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-21%20000757.png>
- **SSH Brute Force Detection**
<img src = https://github.com/elliotjonah/Intrusion-Detection-System-IDS-using-Snort/blob/36bd925297264e946552129901cec56ab7043d7f/Screenshot%202025-03-21%20002040.png>

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

