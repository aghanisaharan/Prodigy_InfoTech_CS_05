from scapy.all import *
from collections import defaultdict
from colorama import Fore, init
import os
import time

init(autoreset=True)

packet_count = 0
protocol_stats = {"TCP":0,"UDP":0,"ICMP":0,"Other":0}
talkers = defaultdict(int)
alerts = []

port_scan_tracker = defaultdict(set)
dns_tracker = defaultdict(int)

capture_filter = None


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def dashboard():

    clear()

    print(Fore.CYAN + "="*70)
    print("        NETWORK PACKET ANALYZER - LIVE SOC DASHBOARD")
    print("="*70)

    print(Fore.GREEN + f"\nTotal Packets Captured: {packet_count}")

    print(Fore.YELLOW + "\nProtocol Distribution")
    print("-"*30)

    for proto, count in protocol_stats.items():
        print(f"{proto}: {count}")

    print(Fore.MAGENTA + "\nTop Talkers")
    print("-"*30)

    sorted_ips = sorted(talkers.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips[:5]:
        print(f"{ip} -> {count} packets")

    print(Fore.RED + "\nSecurity Alerts")
    print("-"*30)

    if not alerts:
        print("No suspicious activity detected")

    else:
        for alert in alerts[-5:]:
            print(alert)

    print("\nPress CTRL+C to stop capture")


def detect_http(packet):

    if packet.haslayer(Raw):

        try:
            payload = packet[Raw].load.decode(errors="ignore")

            if payload.startswith("GET") or payload.startswith("POST"):
                alerts.append("HTTP Request Detected")

        except:
            pass


def detect_dns(packet):

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):

        query = packet[DNSQR].qname.decode()

        alerts.append(f"DNS Query: {query}")

        src = packet[IP].src
        dns_tracker[src] += 1

        if dns_tracker[src] > 20:
            alerts.append(f"⚠ Possible DNS Tunneling from {src}")


def detect_port_scan(packet):

    if packet.haslayer(TCP):

        src = packet[IP].src
        port = packet[TCP].dport

        port_scan_tracker[src].add(port)

        if len(port_scan_tracker[src]) > 15:
            alerts.append(f"⚠ Port Scan Detected from {src}")


def detect_large_payload(packet):

    if packet.haslayer(Raw):

        size = len(packet[Raw].load)

        if size > 1000:
            alerts.append(f"⚠ Large Payload Transfer ({size} bytes)")


def analyze_packet(packet):

    global packet_count
    packet_count += 1

    if packet.haslayer(IP):

        src = packet[IP].src
        talkers[src] += 1

        if packet.haslayer(TCP):
            protocol_stats["TCP"] += 1

        elif packet.haslayer(UDP):
            protocol_stats["UDP"] += 1

        elif packet.haslayer(ICMP):
            protocol_stats["ICMP"] += 1

        else:
            protocol_stats["Other"] += 1

        detect_http(packet)
        detect_dns(packet)
        detect_port_scan(packet)
        detect_large_payload(packet)

    if packet_count % 5 == 0:
        dashboard()


def choose_interface():

    interfaces = get_if_list()

    print("Available Interfaces:\n")

    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")

    choice = int(input("\nSelect interface: "))

    return interfaces[choice]


def choose_filter():

    global capture_filter

    print("\nCapture Filters\n")

    print("1 → Capture Everything")
    print("2 → HTTP Traffic")
    print("3 → DNS Traffic")
    print("4 → TCP Traffic")
    print("5 → UDP Traffic")

    choice = input("\nSelect filter: ")

    if choice == "2":
        capture_filter = "tcp port 80"

    elif choice == "3":
        capture_filter = "udp port 53"

    elif choice == "4":
        capture_filter = "tcp"

    elif choice == "5":
        capture_filter = "udp"

    else:
        capture_filter = None


def main():

    print(Fore.CYAN + "\nAdvanced Network Packet Analyzer")
    print("Educational SOC Monitoring Tool\n")

    interface = choose_interface()

    choose_filter()

    print("\nStarting capture...")
    time.sleep(2)

    dashboard()

    try:

        sniff(
            iface=interface,
            prn=analyze_packet,
            store=False,
            filter=capture_filter
        )

    except KeyboardInterrupt:

        print("\nCapture stopped.")


if __name__ == "__main__":
    main()
