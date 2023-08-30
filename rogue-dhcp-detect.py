#!/usr/bin/python3
from scapy.all import *

APPROVED_DHCP_SERVERS = [
    '10.4.0.2', 
    '10.4.0.1',
]

def detect_rogue_packet(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 2:  # check if it's a DHCP Offer packet
        server_ip = pkt[IP].src
        if server_ip not in APPROVED_DHCP_SERVERS:
            print(f"ALERT: Detected rogue DHCP server with IP {server_ip}")

print("Listening for rogue DHCP servers...")

# Start sniffing the network
sniff(filter="udp and (port 67 or port 68)", prn=detect_rogue_packet)
