# CyberSecurity_Internship-Elevate_labs-Project

---

# 🔒 Personal Firewall using Python

## 📌 Project Description

This project is a **lightweight personal firewall** built using **Python**, designed to monitor and filter network traffic based on customizable rule sets. It provides users with the ability to **allow or block traffic** by IP address, port, and protocol while also logging suspicious packets for auditing purposes.

The firewall works at two levels:

1. **Packet Monitoring & Filtering** – Uses **Scapy** to sniff incoming and outgoing traffic in real-time, applying filtering rules defined by the user.
2. **System-Level Enforcement** – Optionally integrates with **iptables** (Linux) to enforce rules at the kernel level for stronger security.

Additionally, a **PyQt5-based GUI** is included to provide live monitoring of network traffic and easy rule management, making the tool user-friendly for both technical and non-technical users.

This project can serve as an **educational tool** to understand firewalls, packet filtering, and system-level networking, as well as a **basic security layer** for personal systems.

---

## ⚙️ Features

* ✅ Real-time packet sniffing (incoming/outgoing traffic)
* ✅ Customizable rule sets (allow/block IPs, ports, and protocols)
* ✅ Suspicious packet logging with timestamps
* ✅ Optional **iptables integration** for system-level rule enforcement (Linux only)
* ✅ GUI built with **PyQt5** for live monitoring and rule management
* ✅ Lightweight and extensible for research or learning purposes

---

## 🛠 Tools & Technologies Used

### 1. **Python**

* The core language for implementing the firewall.
* Provides flexibility and powerful libraries for networking and GUI development.

### 2. **Scapy**

* A Python library for packet manipulation and sniffing.
* Used to **capture, analyze, and filter packets** in real time.
* Enables creation of custom filtering logic based on IP, port, and protocol.

### 3. **iptables** (Linux only)

* A built-in firewall utility in Linux.
* Allows system-level packet filtering and rule enforcement.
* Integrated with Python scripts for **advanced traffic blocking** beyond application level.

### 4. **PyQt5**

* Python bindings for the Qt framework.
* Used to build a **modern GUI** for live monitoring of traffic.
* Provides interactive components for rule creation, visualization of logs, and system alerts.

### 5. **Logging (Python’s logging module)**

* Used to maintain audit trails of suspicious packets.
* Logs include details like timestamp, source/destination IP, port, and protocol.

---

## 🚀 Deliverables

* **CLI Version** – Command-line firewall for advanced users.
* **GUI Version (PyQt5)** – User-friendly interface for rule customization, traffic visualization, and live packet monitoring.
* **Log Files** – Records of blocked/suspicious packets for security auditing.

---

🔐 This project demonstrates the **fundamentals of network security**, packet sniffing, and firewall design in a **practical, hands-on way**. It is ideal for students, researchers, and cybersecurity enthusiasts who want to learn how firewalls work under the hood.

---
