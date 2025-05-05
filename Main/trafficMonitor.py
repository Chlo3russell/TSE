from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, deque
import time
import threading
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
import subprocess
import shlex
import os

from database.databaseScript import Database
from logs.logger import setup_logger
from firewallMonitor import Firewall
from config import Config
from database.databaseScript import Database
from logs.logger import setup_logger

import warnings
from cryptography.utils import CryptographyDeprecationWarning

# Suppress Scapy deprecation warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

logger = setup_logger('traffic_monitor')

# Configuration
THRESHOLD = Config.THRESHOLD
BURST_THRESHOLD = Config.BURST_THRESHOLD
LONG_TERM_THRESHOLD = Config.LONG_TERM_THRESHOLD
PORT_SCAN_THRESHOLD = Config.PORT_SCAN_THRESHOLD
SYN_FLOOD_RATIO = Config.SYN_FLOOD_RATIO
ANOMALY_DETECTION_SAMPLES = Config.ANOMALY_DETECTION_SAMPLES

# Initialize components
defense = Firewall()
db = Database()

# Packet tracking structure
packet_counts = defaultdict(lambda: {
    "count": 0,
    "timestamp": time.time(),
    "ports": set(),
    "syn_count": 0,
    "tcp_count": 0,
    "history": deque(maxlen=60),
    "hourly_count": 0,
    "last_hour_check": time.time()
})

def train_ml_model():
    """Periodically retrain the ML model"""
    while True:
        time.sleep(3600)  # Retrain every hour
        try:
            if len(packet_features) > ANOMALY_DETECTION_SAMPLES:
                ml_model.fit(np.array(packet_features))
                logger.info("ML model retrained with new data")
        except Exception as e:
            logger.error(f"ML training failed: {str(e)}")

def generate_traffic_report():
    """Generate periodic traffic reports"""
    while True:
        time.sleep(86400)  # Daily reports
        try:
            top_ips = sorted(
                packet_counts.items(),
                key=lambda x: x[1]["hourly_count"],
                reverse=True
            )[:10]
            
            report = {
                "date": datetime.now().strftime("%Y-%m-%d"),
                "top_sources": [
                    {"ip": ip, "count": data["hourly_count"]} 
                    for ip, data in top_ips
                ],
                "total_packets": sum(data["hourly_count"] for data in packet_counts.values()),
                "blocked_ips": len(db._get_blocked_ips())
            }
            
            db._add_rate_limit_action(
                action="Daily Traffic Report",
                config=report
            )
            logger.info(f"Generated daily report: {report}")
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")

def analyze_traffic_patterns():
    """Periodic analysis of traffic patterns"""
    while True:
        try:
            current_time = time.time()
            for ip, data in packet_counts.items():
                # Long-term traffic analysis
                if current_time - data["last_hour_check"] > 3600:
                    if data["hourly_count"] > LONG_TERM_THRESHOLD:
                        flag_metric(ip, data["hourly_count"], "Sustained High Traffic")
                    data["hourly_count"] = 0
                    data["last_hour_check"] = current_time
                
                # Port scan detection
                if len(data["ports"]) > PORT_SCAN_THRESHOLD:
                    flag_metric(ip, len(data["ports"]), "Port Scan Detected")
                    data["ports"].clear()
                
                # SYN flood detection
                if data["tcp_count"] > 50 and (data["syn_count"] / data["tcp_count"]) > SYN_FLOOD_RATIO:
                    flag_metric(ip, data["syn_count"] / data["tcp_count"], "SYN Flood Detected")
                
                # ML anomaly detection
                if len(packet_features) > ANOMALY_DETECTION_SAMPLES:
                    features = np.array([
                        data["count"],
                        len(data["ports"]),
                        data["syn_count"],
                        np.mean(data["history"]) if data["history"] else 0
                    ]).reshape(1, -1)
                    if ml_model.predict(features)[0] == -1:
                        flag_metric(ip, "Anomalous pattern", "ML Detected Anomaly")
                        
            time.sleep(300)  # Run every 5 minutes
            
        except Exception as e:
            logger.error(f"Traffic analysis error: {str(e)}")
            time.sleep(60)  # Wait 1 minute before retrying

def log_packet(packet):
    """Log packet information to the central log"""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = ""
        
        if packet.haslayer(TCP):
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
        elif packet.haslayer(UDP):
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            flags = ""
        else:
            protocol = "OTHER"
            sport = ""
            dport = ""
            flags = ""
        
        logger.info(f"Packet: {src_ip}:{sport} -> {dst_ip}:{dport} {protocol} {flags}")

def process_packets(packet):
    """Packet processing with logging"""
    log_packet(packet)
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = time.time()
        ip_data = packet_counts[src_ip]
        
        # Update counters
        ip_data["count"] += 1
        ip_data["hourly_count"] += 1
        
        # Rest of the processing logic...
        # [Keep all your existing processing code]
        
        # Example logging for detected events
        if ip_data["count"] > THRESHOLD:
            logger.warning(f"High traffic detected from {src_ip}: {ip_data['count']} packets/sec")

def start_sniffing():
    """Main entry point with logging"""
    logger.info("Starting network monitoring system")
    
    # Start background threads
    threading.Thread(target=analyze_traffic_patterns, daemon=True).start()
    threading.Thread(target=train_ml_model, daemon=True).start()
    threading.Thread(target=generate_traffic_report, daemon=True).start()
    
    # Start sniffing
    try:
        sniff(
            prn=process_packets,
            store=False,
            filter="ip and (tcp or udp or icmp)"
        )
    except Exception as e:
        logger.error(f"Sniffing failed: {str(e)}")

# Initialize components
db = Database()
logger = setup_logger('traffic_monitor')

def flag_metric(ip_address, value, metric_type="DoS Detected"):
    """Record flagged metrics to database and log security events.
    
    Args:
        ip_address (str): Suspicious IP address
        value (int/float/str): Measured threat value (e.g., packet count)
        metric_type (str): Threat classification
    """
    try:
        # Get IP info from WHOIS or set defaults
        ip_info = db._get_ip_info_whois(ip_address) or {
            'country': 'Unknown',
            'city': 'Unknown',
            'isp_name': 'Unknown'
        }

        # Add IP to database
        ip_id = db._add_ip(
            ip_address,
            location_id=db._add_location(
                ip_info.get('country', 'Unknown'),
                ip_info.get('city', 'Unknown'),
                ip_info.get('region', 'Unknown')
            ),
            isp_id=db._add_isp(
                ip_info.get('isp_name', 'Unknown'),
                ip_info.get('contact', 'No contact')
            )
        )

        # Store the flagged metric
        db._add_flagged_metric(ip_id, metric_type, value)

        # Log warning
        logger.warning(
            f"Flagged {metric_type} from {ip_address} "
            f"({ip_info.get('country', 'Unknown')}) - Value: {value}"
        )

        # Optional: Auto-block if threshold exceeded
        if metric_type in ["DoS Detected", "Port Scan Detected"]:
            defense = Firewall()
            defense.block_ip(ip_address, f"Autoblock: {metric_type}")

    except Exception as e:
        logger.error(f"Error in flag_metric: {str(e)}")

if __name__ == "__main__":
    start_sniffing()
