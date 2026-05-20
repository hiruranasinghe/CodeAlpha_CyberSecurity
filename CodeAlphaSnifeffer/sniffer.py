
"""
CodeAlpha Cybersecurity Internship — Task 1
Basic Network Sniffer
Author: [Your Name]
Description: Captures live network packets, displays protocol info,
             saves logs to file, and shows a summary report.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
from datetime import datetime
from collections import defaultdict
import argparse
import sys
import os

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"

PROTO_COLORS = {
    "TCP":   Colors.GREEN,
    "UDP":   Colors.BLUE,
    "ICMP":  Colors.YELLOW,
    "ARP":   Colors.MAGENTA,
    "DNS":   Colors.CYAN,
    "OTHER": Colors.WHITE,
}


packet_count   = 0
proto_counter  = defaultdict(int)
suspicious     = []
log_lines      = []
LOG_FILE       = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"


SUSPICIOUS_PORTS = {
    23:   "Telnet (unencrypted)",
    21:   "FTP (unencrypted)",
    4444: "Common backdoor port",
    1337: "Common hacker port",
    8080: "Alternate HTTP",
    3389: "RDP (remote desktop)",
}


def get_protocol(packet):
    if packet.haslayer(DNS):  return "DNS"
    if packet.haslayer(TCP):  return "TCP"
    if packet.haslayer(UDP):  return "UDP"
    if packet.haslayer(ICMP): return "ICMP"
    if packet.haslayer(ARP):  return "ARP"
    return "OTHER"


def get_flags(packet):
    if not packet.haslayer(TCP): return ""
    flags    = packet[TCP].flags
    flag_map = {"F":"FIN","S":"SYN","R":"RST","P":"PSH","A":"ACK","U":"URG"}
    active   = [name for char, name in flag_map.items() if char in str(flags)]
    return "[" + "|".join(active) + "]" if active else ""


def get_payload(packet, max_bytes=64):
    if packet.haslayer(Raw):
        raw = packet[Raw].load
        try:
            decoded = raw[:max_bytes].decode("utf-8", errors="replace")
            return "".join(c if c.isprintable() else "." for c in decoded)
        except:
            return raw[:max_bytes].hex()
    return None


def check_suspicious(packet, proto):
    """Flag packets on known suspicious ports."""
    port = None
    if packet.haslayer(TCP):
        port = packet[TCP].dport
    elif packet.haslayer(UDP):
        port = packet[UDP].dport

    if port and port in SUSPICIOUS_PORTS:
        src = packet[IP].src if packet.haslayer(IP) else "unknown"
        msg = f"[!] Suspicious port {port} ({SUSPICIOUS_PORTS[port]}) from {src}"
        if msg not in suspicious:
            suspicious.append(msg)


def format_packet(packet, num):
    ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto = get_protocol(packet)
    color = PROTO_COLORS.get(proto, Colors.WHITE)

    lines      = [f"{Colors.BOLD}{'─'*65}{Colors.RESET}"]
    log_plain  = ["─"*65]

    header = f"#{num:04d}  {ts}  {proto:5s}"
    lines.append(f"{Colors.BOLD}#{num:04d}{Colors.RESET}  {Colors.WHITE}{ts}{Colors.RESET}  {color}{proto:5s}{Colors.RESET}")
    log_plain.append(header)

    if packet.haslayer(IP):
        ip_line = f"  IP   {packet[IP].src:>16} → {packet[IP].dst:<16}  TTL={packet[IP].ttl}"
        lines.append(f"  IP   {Colors.CYAN}{packet[IP].src:>16}{Colors.RESET} → {Colors.RED}{packet[IP].dst:<16}{Colors.RESET}  TTL={packet[IP].ttl}")
        log_plain.append(ip_line)
    elif packet.haslayer(ARP):
        arp     = packet[ARP]
        op      = "Request" if arp.op == 1 else "Reply"
        arp_line = f"  ARP  {op}  {arp.psrc} → {arp.pdst}"
        lines.append(f"  {Colors.MAGENTA}ARP{Colors.RESET}  {op}  {arp.psrc} → {arp.pdst}")
        log_plain.append(arp_line)

    if packet.haslayer(TCP):
        tcp      = packet[TCP]
        flags    = get_flags(packet)
        tcp_line = f"  TCP  Port {tcp.sport} → {tcp.dport}  {flags}"
        lines.append(f"  TCP  Port {Colors.CYAN}{tcp.sport}{Colors.RESET} → {Colors.RED}{tcp.dport}{Colors.RESET}  {flags}")
        log_plain.append(tcp_line)
    elif packet.haslayer(UDP):
        udp      = packet[UDP]
        udp_line = f"  UDP  Port {udp.sport} → {udp.dport}  Len={udp.len}"
        lines.append(f"  UDP  Port {Colors.CYAN}{udp.sport}{Colors.RESET} → {Colors.RED}{udp.dport}{Colors.RESET}  Len={udp.len}")
        log_plain.append(udp_line)

    if packet.haslayer(DNS) and packet[DNS].qd:
        qr       = "Response" if packet[DNS].qr else "Query"
        name     = packet[DNS].qd.qname.decode(errors="replace")
        dns_line = f"  DNS  {qr}  {name}"
        lines.append(f"  {Colors.CYAN}DNS{Colors.RESET}  {qr}  {name}")
        log_plain.append(dns_line)

    payload = get_payload(packet)
    if payload:
        pay_line = f"  DATA {payload[:60]}"
        lines.append(f"  {Colors.YELLOW}DATA{Colors.RESET} {payload[:60]}")
        log_plain.append(pay_line)

    # Save plain text version to log
    log_lines.extend(log_plain)
    log_lines.append("")

    return "\n".join(lines)


def packet_callback(packet):
    global packet_count
    packet_count += 1
    proto = get_protocol(packet)
    proto_counter[proto] += 1
    check_suspicious(packet, proto)
    print(format_packet(packet, packet_count))


def save_log():
    """Save all captured packets to a text file."""
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"CodeAlpha Network Sniffer — Capture Log\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*65 + "\n\n")
        f.write("\n".join(log_lines))
        f.write("\n\n" + "="*65 + "\n")
        f.write("PROTOCOL SUMMARY\n")
        f.write("="*65 + "\n")
        for proto, count in sorted(proto_counter.items(), key=lambda x: -x[1]):
            f.write(f"  {proto:<8} : {count} packets\n")
        f.write(f"\n  TOTAL    : {packet_count} packets\n")
        if suspicious:
            f.write("\nSUSPICIOUS ACTIVITY DETECTED\n")
            f.write("="*65 + "\n")
            for s in suspicious:
                f.write(f"  {s}\n")


def print_summary():
    """Print coloured summary to terminal."""
    print(f"\n{Colors.BOLD}{'═'*65}{Colors.RESET}")
    print(f"  {Colors.CYAN}PROTOCOL SUMMARY{Colors.RESET}")
    print(f"{Colors.BOLD}{'═'*65}{Colors.RESET}")
    for proto, count in sorted(proto_counter.items(), key=lambda x: -x[1]):
        color = PROTO_COLORS.get(proto, Colors.WHITE)
        bar   = "█" * count
        print(f"  {color}{proto:<8}{Colors.RESET} : {Colors.BOLD}{count:>4}{Colors.RESET} packets  {color}{bar[:40]}{Colors.RESET}")
    print(f"{Colors.BOLD}{'─'*65}{Colors.RESET}")
    print(f"  {'TOTAL':<8} : {Colors.BOLD}{packet_count:>4}{Colors.RESET} packets")

    if suspicious:
        print(f"\n{Colors.RED}{Colors.BOLD}  ⚠ SUSPICIOUS ACTIVITY DETECTED{Colors.RESET}")
        for s in suspicious:
            print(f"  {Colors.RED}{s}{Colors.RESET}")

    print(f"\n  {Colors.GREEN}Log saved → {LOG_FILE}{Colors.RESET}")
    print(f"{Colors.BOLD}{'═'*65}{Colors.RESET}\n")


def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
  ╔══════════════════════════════════════════════════════╗
  ║        CodeAlpha — Basic Network Sniffer             ║
  ║        Task 1  |  Cybersecurity Internship           ║
  ╚══════════════════════════════════════════════════════╝
{Colors.RESET}""")


def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Network Sniffer")
    parser.add_argument("-i", "--interface", default=None,  help="Network interface (e.g. Wi-Fi, Ethernet)")
    parser.add_argument("-c", "--count",     type=int, default=0, help="Packets to capture (0=unlimited)")
    parser.add_argument("-f", "--filter",    default="",    help='BPF filter e.g. "tcp" or "udp port 53"')
    args = parser.parse_args()

    print_banner()
    print(f"  Interface : {Colors.CYAN}{args.interface or 'default'}{Colors.RESET}")
    print(f"  Count     : {Colors.CYAN}{args.count or 'unlimited'}{Colors.RESET}")
    print(f"  Filter    : {Colors.CYAN}{args.filter or 'none'}{Colors.RESET}")
    print(f"  Log file  : {Colors.CYAN}{LOG_FILE}{Colors.RESET}")
    print(f"\n  {Colors.YELLOW}Press Ctrl+C to stop...{Colors.RESET}\n")

    try:
        sniff(iface=args.interface, count=args.count,
              filter=args.filter, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(f"\n{Colors.RED}[ERROR] Run as Administrator!{Colors.RESET}")
        sys.exit(1)
    finally:
        print_summary()
        save_log()


if __name__ == "__main__":
    main()