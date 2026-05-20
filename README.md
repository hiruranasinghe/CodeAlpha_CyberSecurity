# 🔍 CodeAlpha — Task 1: Basic Network Sniffer

A Python-based network packet sniffer built with **Scapy** that captures live
network traffic and displays source/destination IPs, protocols, ports, TCP flags,
DNS queries, payload previews, and saves everything to a log file.

---

## Features

- ✅ Captures live network packets in real time
- ✅ Detects protocols - TCP, UDP, ICMP, ARP, DNS
- ✅ Displays source/destination IPs, ports, TTL
- ✅ Shows TCP flags (SYN, ACK, PSH, FIN, RST)
- ✅ Previews packet payload data
- ✅ Saves full capture log to a `.txt` file automatically
- ✅ Shows protocol summary report after capture
- ✅ Detects suspicious ports (Telnet, FTP, backdoors)
- ✅ Colour - coded terminal output
- ✅ BPF filter support

---

## Requirements

- Python 3.8+
- Scapy 2.5+
- Npcap (Windows) — https://npcap.com

```
pip install scapy
```

---

## Usage

> ⚠️ Must be run as Administrator (Windows) or with sudo (Linux/Mac)

```bash
# Capture 20 packets
python sniffer.py -c 20

# Capture only DNS traffic
python sniffer.py -f "udp port 53" -c 10

# Capture TCP only on specific interface
python sniffer.py -i Wi-Fi -f "tcp" -c 50

# Run unlimited until Ctrl+C
python sniffer.py
```

---

## Sample Output

```
  ╔══════════════════════════════════════════════════════╗
  ║        CodeAlpha — Basic Network Sniffer             ║
  ║        Task 1  |  Cybersecurity Internship           ║
  ╚══════════════════════════════════════════════════════╝

─────────────────────────────────────────────────────────
#0001  10:45:27.780  TCP
  IP      192.168.8.191 → 162.220.163.154   TTL=128
  TCP  Port 55376 → 443  [ACK]

─────────────────────────────────────────────────────────
#0002  10:45:28.044  DNS
  IP      192.168.8.191 → 8.8.8.8           TTL=128
  UDP  Port 54210 → 53  Len=45
  DNS  Query  www.google.com.

═══════════════════════════════════════════════════════════
  PROTOCOL SUMMARY
═══════════════════════════════════════════════════════════
  TCP      :   14 packets  ██████████████
  DNS      :    3 packets  ███
  UDP      :    2 packets  ██
  ARP      :    1 packets  █
─────────────────────────────────────────────────────────
  TOTAL    :   20 packets
  Log saved → capture_20241014_104527.txt
```

---

## Author

R.H.T Liyanage — CodeAlpha Cybersecurity Internship
