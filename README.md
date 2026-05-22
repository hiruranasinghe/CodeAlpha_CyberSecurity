<div align="center">

# 🛡️ CodeAlpha Cybersecurity Internship
### Hiruni Ranasinghe · [@hiruranasinghe](https://github.com/hiruranasinghe)

![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red?style=for-the-badge&logo=hackthebox&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white)
![HTML](https://img.shields.io/badge/HTML-CSS-orange?style=for-the-badge&logo=html5&logoColor=white)
![Status](https://img.shields.io/badge/Status-Completed-green?style=for-the-badge)

> *"Security is not a product, but a process."* — Bruce Schneier

</div>

---

## 👩‍💻 About This Repository

This repository documents my hands-on cybersecurity internship projects completed at **CodeAlpha** — one of the leading software development companies dedicated to building secure and resilient systems.

Over the course of this internship I built three real-world cybersecurity projects covering **network analysis**, **security awareness training**, and **secure code auditing** — all core skills used by professional security engineers every day.

---

## 📁 Projects Completed

---

### 🔍 Task 1 - Basic Network Sniffer
#### [`CodeAlpha_NetworkSniffer`](https://github.com/hiruranasinghe/CodeAlphaSniffer)

A Python-based live network packet analyser built with **Scapy** that captures and decodes real network traffic in real time.

**What it does:**
- Captures live packets from any network interface
- Detects and labels protocols — TCP, UDP, ICMP, ARP, DNS
- Displays source & destination IPs, ports, TTL values
- Shows TCP flags (SYN, ACK, PSH, FIN, RST)
- Previews packet payload data
- Automatically saves a full capture log to a `.txt` file
- Shows a colour-coded protocol summary report after capture
- Flags suspicious ports (Telnet, FTP, backdoor ports)
- Supports BPF filters and custom interface selection

**Tech stack:**
```
Python 3.x · Scapy · Npcap (Windows)
```

**Run it:**
```bash
# Install dependency
pip install scapy

# Capture 20 packets
python sniffer.py -c 20

# Capture DNS traffic only
python sniffer.py -f "udp port 53" -c 10

# Capture TCP on specific interface
python sniffer.py -i Wi-Fi -f "tcp" -c 50
```

**Key concepts learned:**
- How network packets are structured at the IP, TCP, and UDP layers
- Protocol identification and packet parsing
- BPF (Berkeley Packet Filter) syntax
- Raw socket programming in Python

---

### 🎣 Task 2 - Phishing Awareness Training Module
#### [`CodeAlpha_PhishingAwareness`](https://github.com/hiruranasinghe/CodeAlpha-Task 02(Phishing Awareness Training)

A fully interactive browser-based phishing awareness training module built with pure **HTML, CSS, and JavaScript** — no frameworks, no installation, runs in any browser.

**What it covers:**
- What phishing is - types, tactics, and real-world scale
- How to identify red flags in suspicious emails
- Annotated real phishing email with interactive clues (hover to reveal)
- Social engineering psychology — fear, authority, urgency, pretexting
- Best practices and actionable defences
- 8-question interactive quiz with real-world scenarios and scored results

**Features:**
- Animated UI with smooth page transitions and scroll reveals
- Progress bar tracking across all 6 modules
- Circular score ring on quiz completion
- Fully responsive - works on mobile and desktop
- Zero dependencies - single HTML file

**Tech stack:**
```
HTML5 · CSS3 · Vanilla JavaScript
```

**Run it:**
```bash
# Just open the file in any browser — no setup needed
index.html → double click → opens in browser
```

**Key concepts learned:**
- Social engineering tactics and psychological manipulation
- Phishing detection techniques — homoglyph attacks, URL analysis
- Security awareness training design
- Interactive educational content development

---

### 🔐 Task 3 — Secure Coding Review
#### [`CodeAlpha_SecureCodingReview`](https://github.com/hiruranasinghe/CodeAlpha_Secure Coding Review)

A professional security audit of a Python Flask web application — identifying, documenting, and remediating **10 real-world vulnerabilities** mapped to the **OWASP Top 10**.

**Files included:**

| File | Description |
|---|---|
| `vulnerable_app.py` | Flask app with 10 intentional security vulnerabilities |
| `secure_app.py` | Same app with every vulnerability fixed |
| `code_review_report.md` | Full professional audit report |

**Vulnerabilities found and fixed:**

| # | Vulnerability | Severity | OWASP |
|---|---|---|---|
| 01 | Hardcoded Secret Key | 🔴 Critical | A02 |
| 02 | SQL Injection — Login | 🔴 Critical | A03 |
| 03 | Broken Access Control | 🔴 Critical | A01 |
| 04 | SQL Injection — Search | 🟠 High | A03 |
| 05 | Sensitive Data Exposure | 🟠 High | A02 |
| 06 | OS Command Injection | 🟠 High | A03 |
| 07 | Plaintext Password Storage | 🟠 High | A02 |
| 08 | Insecure Deserialization (RCE) | 🟠 High | A08 |
| 09 | Path Traversal | 🟡 Medium | A01 |
| 10 | Predictable Reset Token | 🟡 Medium | A07 |

**Tech stack:**
```
Python 3.x · Flask · bcrypt · SQLite · Bandit (static analysis)
```

**Key concepts learned:**
- OWASP Top 10 vulnerability categories
- SQL injection and parameterised query defences
- Password hashing with bcrypt
- Secure session management
- Input validation and output encoding
- Professional security audit report writing

---

## 🧠 Skills Gained

```
Network Analysis          ████████████  Packet capture & protocol parsing
Threat Detection          ████████████  Suspicious traffic identification  
Security Awareness        ████████████  Phishing & social engineering
Vulnerability Assessment  ████████████  OWASP Top 10 identification
Secure Coding             ████████████  Remediation & best practices
Technical Writing         ████████████  Professional audit reporting
```

---

## 🏢 About CodeAlpha

CodeAlpha is a leading software development company dedicated to building
secure and resilient systems. This internship program provides hands-on
experience in cybersecurity principles, ethical hacking, encryption,
network security, and threat detection through real-world projects.

🌐 Website: [www.codealpha.tech](https://www.codealpha.tech)

---

## 📬 Connect

<div align="center">

[![GitHub](https://img.shields.io/badge/GitHub-hiruranasinghe-black?style=for-the-badge&logo=github)](https://github.com/hiruranasinghe)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Hiruni_Ranasinghe-blue?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/hiruranasinghe)
[![CodeAlpha](https://img.shields.io/badge/Internship-CodeAlpha-red?style=for-the-badge)](https://www.codealpha.tech)

</div>

---

<div align="center">
<sub>Built with 💙 during CodeAlpha Cybersecurity Internship · Hiruni Ranasinghe · 2024</sub>
</div>
