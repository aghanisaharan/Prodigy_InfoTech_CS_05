# Network Packet Analyzer

This repository contains my Python program for Task 05 of the Cyber Security Internship at **Prodigy InfoTech**. 

The objective of this project is to develop a packet sniffer tool that captures and analyzes network packets. It is designed to display relevant information such as source and destination IP addresses, protocols, and payload data. 

**⚠️ Disclaimer:** This tool was created strictly for educational purposes. Ensure the ethical use of the tool for educational purposes and only capture traffic on networks where you have explicit authorization.

## Features
* **Live SOC Dashboard:** Provides a real-time, color-coded terminal interface displaying packet statistics.
* **Protocol & Talker Tracking:** Maps protocol distributions (TCP, UDP, ICMP) and identifies the top IP addresses communicating on the network.
* **Security Alerts:** Features custom detection logic to flag potential port scans, large payload transfers, and suspicious HTTP/DNS traffic.
* **Capture Filters:** Allows the user to apply BPF (Berkeley Packet Filter) rules to isolate specific traffic (e.g., HTTP, DNS, TCP, UDP).

## Requirements
* Python 3.x
* `scapy` library (`pip install scapy`)
* `colorama` library (`pip install colorama`)
* **Note:** The script may require administrator/root privileges to capture raw packets from the network interface.
