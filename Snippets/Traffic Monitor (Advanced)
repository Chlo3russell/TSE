# Import necessary libraries
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether  # Packet sniffing and processing
from collections import defaultdict, deque  # Data structures for tracking
import time  # Time-related functions
import threading  # Multi-threading support
import numpy as np  # Numerical operations
from database.databaseScript import Database  # Custom database module
from firewallMonitor import Firewall  # Custom firewall module
from logger import setup_logger  # Custom logging setup
from datetime import datetime, timedelta  # Date/time handling
import socket  # Low-level networking interface
import geoip2.database  # IP geolocation
import matplotlib.pyplot as plt  # Visualization (not currently used in main flow)
from sklearn.ensemble import IsolationForest  # Anomaly detection algorithm

# Configuration Constants
THRESHOLD = 150  # packets per second baseline for normal traffic
BURST_THRESHOLD = 300  # packets per second threshold for burst detection
LONG_TERM_THRESHOLD = 10000  # packets per hour threshold for sustained traffic
PORT_SCAN_THRESHOLD = 20  # unique ports per minute to detect port scanning
SYN_FLOOD_RATIO = 0.8  # SYN to total TCP packets ratio for SYN flood detection
ANOMALY_DETECTION_SAMPLES = 1000  # number of samples needed for ML model training

# Initialize system components
defense = Firewall()  # Firewall control instance
db = Database()  # Database connection
logger = setup_logger(__name__)  # Configured logger instance
# GeoIP database reader for IP geolocation (requires GeoLite2 database file)
geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')

# Advanced Packet Tracking Structure
# Dictionary to store per-IP traffic statistics with nested structure
packet_counts = defaultdict(lambda: {
    "count": 0,  # Current packet count
    "timestamp": time.time(),  # Last update time
    "ports": set(),  # Set of destination ports seen
    "syn_count": 0,  # Count of SYN packets (TCP)
    "tcp_count": 0,  # Count of all TCP packets
    "history": deque(maxlen=60),  # Rolling window of last 60 seconds of activity
    "hourly_count": 0,  # Count of packets in current hour
    "last_hour_check": time.time()  # Last hourly reset time
})

# Machine Learning Setup
packet_features = []  # Storage for features used in anomaly detection
# Isolation Forest model for anomaly detection
ml_model = IsolationForest(contamination=0.01, random_state=42)

def get_ip_info(ip_address):
    """Get geographical and ASN information for an IP address
    
    Args:
        ip_address (str): IP address to look up
        
    Returns:
        dict: Contains country, city, ASN, and organization info
    """
    try:
        response = geoip_reader.city(ip_address)
        return {
            "country": response.country.name,
            "city": response.city.name,
            "asn": response.traits.autonomous_system_number,
            "org": response.traits.autonomous_system_organization
        }
    except:
        return {"country": "Unknown", "city": "Unknown", "asn": 0, "org": "Unknown"}

def flag_metric(ip_address, value, metric_type="DoS Detected"):
    """Record flagged metrics with additional context in database
    
    Args:
        ip_address (str): Source IP of suspicious activity
        value: The metric value that triggered the flag
        metric_type (str): Description of the flagged activity
    """
    try:
        # Get geographical info for the IP
        ip_info = get_ip_info(ip_address)
        # Add IP to database or get existing ID
        ip_id = db._add_ip(ip_address, ip_info["country"], ip_info["city"], 
                          ip_info["asn"], ip_info["org"])
        # Record the flagged metric
        db._add_flagged_metric(ip_id, metric_type, value)
        logger.warning(f"Flagged {metric_type} from IP: {ip_address} ({ip_info['country']}) - Value: {value}")
    except Exception as e:
        logger.error(f"Error storing flagged metric: {e}")

def analyze_traffic_patterns():
    """Periodic analysis of traffic patterns for advanced detection
    
    Runs every 5 minutes to check for:
    - Long-term high traffic
    - Port scanning activity
    - SYN flood patterns
    - Machine learning detected anomalies
    """
    while True:
        time.sleep(300)  # Run every 5 minutes
        try:
            current_time = time.time()
            for ip, data in packet_counts.items():
                # Long-term traffic analysis (hourly)
                if current_time - data["last_hour_check"] > 3600:
                    if data["hourly_count"] > LONG_TERM_THRESHOLD:
                        flag_metric(ip, data["hourly_count"], "Sustained High Traffic")
                    data["hourly_count"] = 0
                    data["last_hour_check"] = current_time
                
                # Port scan detection
                if len(data["ports"]) > PORT_SCAN_THRESHOLD:
                    flag_metric(ip, len(data["ports"]), "Port Scan Detected")
                    data["ports"].clear()  # Reset after detection
                
                # SYN flood detection (high ratio of SYN packets)
                if data["tcp_count"] > 50 and (data["syn_count"] / data["tcp_count"]) > SYN_FLOOD_RATIO:
                    flag_metric(ip, data["syn_count"] / data["tcp_count"], "SYN Flood Detected")
                
                # Machine learning anomaly detection
                if len(packet_features) > ANOMALY_DETECTION_SAMPLES:
                    # Create feature vector for this IP
                    features = np.array([
                        data["count"],  # Current count
                        len(data["ports"]),  # Unique ports
                        data["syn_count"],  # SYN packets
                        np.mean(data["history"]) if data["history"] else 0  # Historical average
                    ]).reshape(1, -1)
                    # Predict anomaly (-1 indicates anomaly)
                    prediction = ml_model.predict(features)
                    if prediction[0] == -1:
                        flag_metric(ip, "Anomalous traffic pattern", "ML Detected Anomaly")
        
        except Exception as e:
            logger.error(f"Error in traffic analysis: {e}")

def train_ml_model():
    """Periodically train the machine learning model with new data
    
    Runs hourly to retrain the anomaly detection model
    """
    while True:
        time.sleep(3600)  # Train every hour
        try:
            if len(packet_features) > ANOMALY_DETECTION_SAMPLES:
                ml_model.fit(np.array(packet_features))
                logger.info("Machine learning model retrained")
        except Exception as e:
            logger.error(f"Error training ML model: {e}")

def generate_traffic_report():
    """Generate periodic traffic reports and store in database
    
    Creates daily reports with:
    - Top traffic sources
    - Total packet counts
    - Blocked IP statistics
    """
    while True:
        time.sleep(86400)  # Daily reports
        try:
            # Get top 10 IPs by hourly count
            top_ips = sorted(packet_counts.items(), key=lambda x: x[1]["hourly_count"], reverse=True)[:10]
            report = {
                "date": datetime.now().strftime("%Y-%m-%d"),
                "top_sources": [{"ip": ip, "count": data["hourly_count"]} for ip, data in top_ips],
                "total_packets": sum(data["hourly_count"] for data in packet_counts.values()),
                "blocked_ips": db.get_blocked_ips_count()
            }
            db.store_daily_report(report)
            logger.info(f"Daily report generated: {report}")
        except Exception as e:
            logger.error(f"Error generating traffic report: {e}")

def process_packets(packet):
    """Process each captured packet and perform real-time analysis
    
    Args:
        packet: Scapy packet object
    """
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        current_time = time.time()
        packet_data = packet_counts[source_ip]
        
        # Update basic counters
        packet_data["count"] += 1
        packet_data["hourly_count"] += 1
        
        # Reset counters if more than 1 second has passed
        if current_time - packet_data["timestamp"] > 1:
            packet_data["history"].append(packet_data["count"])
            packet_data["count"] = 0
            packet_data["timestamp"] = current_time
        
        # Protocol-specific analysis
        if packet.haslayer(TCP):
            packet_data["tcp_count"] += 1
            if packet[TCP].flags == "S":  # SYN packet
                packet_data["syn_count"] += 1
            if packet.haslayer(TCP) and packet[TCP].dport:
                packet_data["ports"].add(packet[TCP].dport)
        
        elif packet.haslayer(UDP) and packet[UDP].dport:
            packet_data["ports"].add(packet[UDP].dport)
        
        # Feature collection for ML (if we haven't collected enough samples)
        if len(packet_features) < ANOMALY_DETECTION_SAMPLES * 2:
            packet_features.append([
                packet_data["count"],
                len(packet_data["ports"]),
                packet_data["syn_count"],
                np.mean(packet_data["history"]) if packet_data["history"] else 0
            ])
        
        # Real-time detection (only for non-blocked IPs)
        if not db._get_blocked_ips(source_ip):
            # Basic DoS detection
            if packet_data["count"] > THRESHOLD:
                if packet_data["count"] > BURST_THRESHOLD:
                    logger.critical(f"Burst attack detected from IP: {source_ip}")
                    flag_metric(source_ip, packet_data["count"], "Burst Attack")
                else:
                    logger.warning(f"High traffic detected from IP: {source_ip}")
                    flag_metric(source_ip, packet_data["count"], "High Traffic")
                
                defense.block_ip(source_ip, "DoS Detected")
            
            # DNS amplification detection (large DNS responses)
            if packet.haslayer(UDP) and packet[UDP].sport == 53 and len(packet) > 1000:
                flag_metric(source_ip, len(packet), "DNS Amplification Attempt")
                defense.block_ip(source_ip, "DNS Amplification")

def start_sniffing():
    """Start the advanced packet sniffing system
    
    Initializes background threads and begins packet capture
    """
    logger.info("Starting advanced packet sniffing system")
    
    # Start background threads for various monitoring tasks
    threading.Thread(target=analyze_traffic_patterns, daemon=True).start()
    threading.Thread(target=train_ml_model, daemon=True).start()
    threading.Thread(target=generate_traffic_report, daemon=True).start()
    
    # Start sniffing with BPF filter for better performance
    bpf_filter = "ip and (tcp or udp or icmp)"  # Filter for IP traffic with these protocols
    sniff(prn=process_packets, store=False, filter=bpf_filter)

if __name__ == "__main__":
    start_sniffing()
