from scapy.all import sniff, wrpcap
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import ARP, Ether, srp
from collections import defaultdict
from datetime import datetime
import csv

# Packet capture and logging variables
packets = []
packet_count = defaultdict(int)
bandwidth_usage = defaultdict(int)
device_appearance = {}
threshold = 5
time_limit = 3600  # Set a 1-hour connection time limit
log_file_path = 'packet_log.txt'
csv_log_path = 'packet_log.csv'

# Blacklist
blacklist = ["192.168.1.100"]  # You can keep this if you want to block certain IPs

# Discover devices on the network
def discover_devices(ip_range="192.168.0.1/24"):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered_list = srp(arp_request, timeout=2, verbose=False)[0]
    devices = [{'IP': received.psrc, 'MAC': received.hwsrc} for _, received in answered_list]
    return devices

# Log packets to a text file
def log_packet(packet):
    try:
        with open(log_file_path, 'a') as log_file:
            log_entry = f"TCP Packet: {packet[IP].src} -> {packet[IP].dst}\n" if packet.haslayer(TCP) else f"Packet: {packet.summary()}\n"
            log_file.write(log_entry)
    except Exception as e:
        print(f"Error logging packet: {e}")

# Log packets to a CSV file
def log_packet_csv(packet):
    try:
        with open(csv_log_path, mode='a', newline='') as csv_file:
            log_writer = csv.writer(csv_file)
            timestamp = datetime.now().isoformat()
            protocol = "TCP" if packet.haslayer(TCP) else "OTHER"
            src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
            log_writer.writerow([timestamp, protocol, src_ip, dst_ip])
    except Exception as e:
        print(f"Error logging packet to CSV: {e}")

# Packet callback function
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Blacklist check
        if src_ip in blacklist:
            print(f"Blocked packet from blacklisted IP: {src_ip}")
            return

        # Logging all packets for analysis
        log_packet(packet)
        log_packet_csv(packet)

        print(f"Captured packet from {src_ip} to {dst_ip}")

    packets.append(packet)

# Create CSV log file with headers
with open(csv_log_path, mode='w', newline='') as csv_file:
    log_writer = csv.writer(csv_file)
    log_writer.writerow(["Timestamp", "Protocol", "Source IP", "Destination IP"])

# Start sniffing packets (capturing all traffic)
print("Starting packet capture...")
sniff(iface="Ethernet", prn=packet_callback, count=20)  # Remove 'filter' to capture all traffic

# Save captured packets
wrpcap('captured_packets.pcap', packets)
print(f"Captured packets saved to 'captured_packets.pcap'")
print(f"Packet log saved to '{log_file_path}'")
print(f"CSV packet log saved to '{csv_log_path}'")

# Discover devices
devices = discover_devices()
print("Connected devices:", devices)
