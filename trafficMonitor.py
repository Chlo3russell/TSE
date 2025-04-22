from scapy.all import sniff, IP
from collections import defaultdict
import time
from database.databaseScript import Database
from firewallMonitor import Firewall
from logger import setup_logger
from datetime import timedelta, datetime

# Threshold configuration - packets per second 
THRESHOLD = 150

# Setup
defense = Firewall()
db = Database()
logger = setup_logger(__name__)

# Packet tracking 
packet_counts = defaultdict(lambda: {"count": 0, "timestamp": time.time()})
logger.info("Traffic Monitor Initialised")

def commit_to_db(ip_address, value, metric_type="DoS Detected"):
    # Commit location
    # Commit to IP table
    # Log flagged metric
    pass

def process_packets(packet):
    """
    Process each captured packet, if an IP sends more packets than the threshold they are blocked.
    """
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        current_time = time.time()
        packet_data = packet_counts[source_ip]

        if current_time - packet_data["timestamp"] > 1:
            packet_data["count"] = 0
            packet_data["timestamp"] = current_time
        packet_data["count"] += 1

        if packet_data["count"] > THRESHOLD and not db._get_blocked_ips(source_ip):
            logger.warning(f"Potential DoS attack detected from IP: {source_ip}")
            commit_to_db(source_ip, "DoS Detected")
            defense.block_ip(source_ip, "DoS Detected")

        db._clear_records()

logger.info("Starting packet sniffing...")
sniff(prn=process_packets, store=False)