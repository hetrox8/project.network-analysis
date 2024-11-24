from scapy.all import sniff, wrpcap
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.l2 import srp
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

# Blacklist and Whitelist
blacklist = ["192.168.1.100"]
whitelist = ["192.168.1.200"]  # This can be kept for future use

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

        # Bandwidth tracking
        packet_size = len(packet)
        bandwidth_usage[src_ip] += packet_size
        print(f"Bandwidth usage for {src_ip}: {bandwidth_usage[src_ip]} bytes")

        # Check connection time limit
        if src_ip not in device_appearance:
            device_appearance[src_ip] = datetime.now()
        time_connected = (datetime.now() - device_appearance[src_ip]).total_seconds()
        if time_connected > time_limit:
            print(f"Device {src_ip} has exceeded the time limit.")
            return

        # Log packet and count DoS attack attempts
        packet_count[src_ip] += 1
        if packet_count[src_ip] > threshold:
            print(f"ALERT: Potential DoS attack from {src_ip} (Packets: {packet_count[src_ip]})")

        log_packet(packet)
        log_packet_csv(packet)

    packets.append(packet)

# Create CSV log file with headers
with open(csv_log_path, mode='w', newline='') as csv_file:
    log_writer = csv.writer(csv_file)
    log_writer.writerow(["Timestamp", "Protocol", "Source IP", "Destination IP"])

# Start sniffing packets
print("Starting packet capture...")
sniff(iface="Ethernet", filter="", prn=packet_callback, count=20)

# Save captured packets
wrpcap('captured_packets.pcap', packets)
print(f"Captured packets saved to 'captured_packets.pcap'")
print(f"Packet log saved to '{log_file_path}'")
print(f"CSV packet log saved to '{csv_log_path}'")

# Discover devices
devices = discover_devices()
print("Connected devices:", devices)
