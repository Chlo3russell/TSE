from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, deque
import time
import threading
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest

# Import custom components
from Database.databaseScript import Database  #complete database class
from logs.logger import setupLogger  # configured logger
from firewallMonitor import Firewall  #firewall control

# Configuration
THRESHOLD = 150
BURST_THRESHOLD = 300
LONG_TERM_THRESHOLD = 10000
PORT_SCAN_THRESHOLD = 20
SYN_FLOOD_RATIO = 0.8
ANOMALY_DETECTION_SAMPLES = 1000

# Initialize components
defense = Firewall()
db = Database()
logger = setupLogger(__name__)  # Using logger setup

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

# Machine Learning setup
packet_features = []
ml_model = IsolationForest(contamination=0.01, random_state=42)

def flag_metric(ip_address, value, metric_type="DoS Detected"):
    """Record flagged metrics using database class"""
    try:
        # Get basic IP info
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
        
        logger.warning(
            f"Flagged {metric_type} from {ip_address} "
            f"({ip_info.get('country', 'Unknown')}) - Value: {value}"
        )
        
    except Exception as e:
        logger.error(f"Error in flag_metric: {str(e)}")

def analyze_traffic_patterns():
    """Periodic analysis using database for storage"""
    while True:
        #time.sleep(300)  # 5 minutes
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
                        
        except Exception as e:
            logger.error(f"Traffic analysis error: {str(e)}")

def train_ml_model():
    """Model training with logger"""
    while True:
        time.sleep(3600)
        try:
            if len(packet_features) > ANOMALY_DETECTION_SAMPLES:
                ml_model.fit(np.array(packet_features))
                logger.info("ML model retrained with new data")
        except Exception as e:
            logger.error(f"ML training failed: {str(e)}")

def generate_traffic_report():
    """Daily reporting using database"""
    while True:
        time.sleep(86400)
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
            
            # Store using your database method
            db._add_rate_limit_action(
                action="Daily Traffic Report",
                config=report
            )
            
            logger.info(f"Generated daily report: {report}")
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")

def process_packets(packet):
    """Packet processing focused on web application security"""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        # Only process packets destined for our web app
        if dst_port == 5000:
            current_time = time.time()
            ip_data = packet_counts[src_ip]
            
            # Update counters
            ip_data["count"] += 1
            ip_data["hourly_count"] += 1
            
            # Web-specific attack detection
            if ip_data["count"] > THRESHOLD:
                # Potential DoS on web server
                alert_type = "Web DoS Attack" if ip_data["count"] > BURST_THRESHOLD else "High Web Traffic"
                flag_metric(src_ip, ip_data["count"], alert_type)
                defense.block_ip(src_ip, alert_type)
                logger.warning(f"Blocking {src_ip} for {alert_type} on web server")

def start_sniffing():
    """Main entry point with logging"""
    logger.info("Starting network monitoring system for web application on port 5000")
    
    # Start background threads
    threading.Thread(target=analyze_traffic_patterns, daemon=True).start()
    
    # Modified filter to capture web traffic on port 5000
    sniff(
        prn=process_packets,
        store=False,
        filter="tcp port 5000"  # Only capture traffic to/from port 5000
    )

if __name__ == "__main__":
    start_sniffing()
