# HoneyPot-System
Multi-protocol honeypot for detecting and analyzing cyber attacks with real-time alerts and dashboard visualization.


# 🛡️ Advanced Multi-Protocol Honeypot System

## 📌 Overview
This project is a **multi-protocol honeypot system** designed to detect, log, and analyze cyber attacks in real-time.  
It simulates multiple services such as SSH, FTP, HTTP, Telnet, and databases to attract attackers.

---

## 🚀 Features

- 🔍 Multi-port monitoring (SSH, HTTP, FTP, Telnet, etc.)
- 🧠 Attack classification (SQLi, XSS, Brute Force, RCE, etc.)
- 🌍 IP Geolocation tracking
- 📊 Web dashboard (Flask-based)
- 📩 Real-time Telegram alerts
- 🛡️ MITRE ATT&CK mapping
- 🔐 Credential capture (SSH login simulation)

---

## 🏗️ Technologies Used

- **Backend:** Python
- **Networking:** Socket Programming
- **Database:** SQLite
- **Frontend:** HTML, Flask
- **Alerts:** Telegram Bot API
- **Security Concepts:** Honeypot, Intrusion Detection

---

## 📂 Project Structure
honeypot/
│── honeypot.py
│── app.py
│── templates/
│── static/
│── logs/
│── README.md
│── requirements.txt


---

## ⚙️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/advanced-honeypot-system.git
cd advanced-honeypot-system
pip install -r requirements.txt
