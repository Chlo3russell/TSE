from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
from Database.databaseScript import Database
from firewallMonitor import Firewall
#from logger import setup_logger
from datetime import timedelta, datetime

# Threshold configuration - packets per second
THRESHOLD = 150

# Configuration
TARGET_WEBSITE_IP = "127.0.0.1"  # Replace with the actual IP address of your target website VM!

# Setup
defense = Firewall()
db = Database()
#logger = setup_logger(__name__)

# Packet tracking
packet_counts = defaultdict(lambda: {"count": 0, "timestamp": time.time()})
#logger.info("Traffic Monitor Initialised")

def commit_to_db(ip_address, value, metric_type="DoS Detected"):
    """
    Commit location
    Commit to IP table
    Log flagged metric
    """
    try:
        # Ensure the IP exists in the ip_list table
        ip_info = db._get_ip(ip_address=ip_address)
        if not ip_info:
            ip_id = db._add_ip(ip_address)
            if not ip_id:
                #logger.error(f"Failed to add IP {ip_address} to the database")
                return
        else:
            ip_id = ip_info['id']

        # Log the flagged metric
        #db._add_flagged_metric(ip_id, metric_type, value)
        #logger.info(f"Flagged metric: IP: {ip_address}, Metric: {metric_type}, Value: {value}")

    except Exception as e:
        #logger.error(f"Error committing to database: {e}")
        pass

def process_packets(packet):
    """
    Process each captured packet, if an IP sends more packets than the threshold they are blocked.
    """
    if IP in packet:
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst  # Get destination IP
        protocol = packet[IP].proto # Get protocol

        # Filter traffic to the target website
        if dest_ip == TARGET_WEBSITE_IP:
            # Filter for TCP traffic (HTTP/HTTPS)
            if TCP in packet or UDP in packet:

                # Ensure the source IP exists in the ip_list table
                ip_info = db._get_ip(ip_address=source_ip)
                if not ip_info:
                    ip_id = db._add_ip(source_ip)
                    if not ip_id:
                        #logger.error(f"Failed to add IP {source_ip} to the database")
                        return
                else:
                    ip_id = ip_info['id']

                # Log traffic to the database
                try:
                    db._c.execute("INSERT INTO traffic_logs (source_ip_id, destination_ip, protocol_type) VALUES (?, ?, ?)", (ip_id, dest_ip, protocol))
                    db._conn.commit()
                    #logger.info(f"Logged traffic: Source IP: {source_ip}, Destination IP: {dest_ip}, Protocol: {protocol}")
                except Exception as e:
                    #logger.error(f"Error logging traffic to database: {e}")
                    pass

        current_time = time.time()
        packet_data = packet_counts[source_ip]

        if current_time - packet_data["timestamp"] > 1:
            packet_data["count"] = 0
            packet_data["timestamp"] = current_time
        packet_data["count"] += 1

        if packet_data["count"] > THRESHOLD and not defense.db._get_blocked_ips(source_ip):
            #logger.warning(f"Potential DoS attack detected from IP: {source_ip}")
            commit_to_db(source_ip, "DoS Detected")
            defense.block_ip(source_ip, "DoS Detected")

#logger.info("Starting packet sniffing...")
sniff(prn=process_packets, store=False)