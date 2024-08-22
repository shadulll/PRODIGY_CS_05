# Packet Sniffer Script

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest  # Import HTTP packet
import time

def print_banner():
    banner = r"""
     __     _                      _        ___           _        _       _               _                    
  /\ \ \___| |___      _____  _ __| | __   / _ \__ _  ___| | _____| |_    /_\  _ __   __ _| |_   _ _______ _ __ 
 /  \/ / _ \ __\ \ /\ / / _ \| '__| |/ /  / /_)/ _` |/ __| |/ / _ \ __|  //_\\| '_ \ / _` | | | | |_  / _ \ '__|
/ /\  /  __/ |_ \ V  V / (_) | |  |   <  / ___/ (_| | (__|   <  __/ |_  /  _  \ | | | (_| | | |_| |/ /  __/ |   
\_\ \/ \___|\__| \_/\_/ \___/|_|  |_|\_\ \/    \__,_|\___|_|\_\___|\__| \_/ \_/_| |_|\__,_|_|\__, /___\___|_|   
                                                                                             |___/              
    """
    print(banner)
    print("Created by Muhammed Shadul\n")

def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Initialize a flag to check if the packet has meaningful data
        has_data = False

        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            print(f"\n[+] HTTP Request captured at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"    Source IP: {src_ip}")
            print(f"    Destination IP: {dst_ip}")
            print(f"    Host: {http_layer.Host.decode()}")
            print(f"    URL: {http_layer.Path.decode()}")
            print(f"    Method: {http_layer.Method.decode()}")
            has_data = True
        
        if protocol == 6:  # TCP
            tcp_layer = packet[TCP]
            print(f"    Source Port: {tcp_layer.sport}")
            print(f"    Destination Port: {tcp_layer.dport}")
            has_data = True
        
        elif protocol == 17:  # UDP
            udp_layer = packet[UDP]
            print(f"    Source Port: {udp_layer.sport}")
            print(f"    Destination Port: {udp_layer.dport}")
            has_data = True
        
        elif protocol == 1:  # ICMP
            icmp_layer = packet[ICMP]
            print(f"    ICMP Type: {icmp_layer.type}")
            print(f"    ICMP Code: {icmp_layer.code}")
            has_data = True
        
        # Extracting the payload and attempting to decode it as plaintext
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            if payload:  # Check if payload is not empty
                try:
                    decoded_payload = payload.decode('utf-8')
                    print(f"    Payload: {decoded_payload}")
                    has_data = True
                except UnicodeDecodeError:
                    # Skip encrypted or non-plaintext payloads
                    pass

        # Print if there's no meaningful data
        if not has_data:
            print("    No meaningful data in packet.")

def capture_packets(interface):
    print(f"[*] Starting packet capture on interface {interface}...")
    scapy.sniff(iface=interface, prn=analyze_packet, store=False)

def main():
    print_banner()
    interface = input("Enter the network interface to sniff on (e.g., eth0, wlan0): ")
    capture_packets(interface)

if __name__ == "__main__":
    main()
