from scapy.all import sniff, wrpcap
from scapy.layers.inet import TCP, IP  # Specific import for TCP and IP
from collections import defaultdict
import csv
from datetime import datetime

# List to store captured packets
packets = []
packet_count = defaultdict(int)  # Dictionary to track packet counts by source IP
threshold = 5  # Alert threshold for packet counts
log_file_path = 'packet_log.txt'  # File to log packet details
csv_log_path = 'packet_log.csv'  # CSV file for packet details

# Function to log packet details to a text file
def log_packet(packet):
    with open(log_file_path, 'a') as log_file:
        if packet.haslayer(TCP):
            log_entry = f"TCP Packet: {packet[IP].src} -> {packet[IP].dst}\n"
        else:
            log_entry = f"Packet: {packet.summary()}\n"
        log_file.write(log_entry)

# Function to log packet details to a CSV file
def log_packet_csv(packet):
    with open(csv_log_path, mode='a', newline='') as csv_file:
        log_writer = csv.writer(csv_file)
        timestamp = datetime.now().isoformat()
        protocol = "TCP" if packet.haslayer(TCP) else "OTHER"
        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
        
        log_writer.writerow([timestamp, protocol, src_ip, dst_ip])

# Function to process each captured packet
def packet_callback(packet):
    # Debug print: Show we're processing a packet
    print("Processing a packet...")
    
    # Check if the packet is a TCP packet
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Print the source and destination IPs of the packet
        print(f"TCP Packet: {src_ip} -> {dst_ip}")

        # Increment packet count for the source IP
        packet_count[src_ip] += 1

        # Trigger an alert if packet count from a source IP exceeds the threshold
        if packet_count[src_ip] > threshold:
            print(f"ALERT: Potential DoS attack from {src_ip} (Packets: {packet_count[src_ip]})")

        # Log packet details to the text file and CSV file
        log_packet(packet)
        log_packet_csv(packet)

    else:
        # Print a summary of other types of packets
        print(packet.summary())
        # Log non-TCP packets to the file
        log_packet(packet)
        log_packet_csv(packet)

    # Add the packet to our list for future saving
    packets.append(packet)

# Create the CSV file and write the header
with open(csv_log_path, mode='w', newline='') as csv_file:
    log_writer = csv.writer(csv_file)
    log_writer.writerow(["Timestamp", "Protocol", "Source IP", "Destination IP"])

# Sniff packets with a broader filter (capture all TCP packets)
print("Starting packet capture...")
sniff(filter="tcp", prn=packet_callback, count=20)

# Save the captured packets to a PCAP file
wrpcap('captured_packets.pcap', packets)

print(f"Captured packets saved to 'captured_packets.pcap'")
print(f"Packet log saved to '{log_file_path}'")
print(f"CSV packet log saved to '{csv_log_path}'")
