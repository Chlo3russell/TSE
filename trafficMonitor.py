'''
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict, deque
import time
import threading
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest
import warnings

from database.databaseScript import Database
from logs.logger import setup_logger
from firewallMonitor import Firewall

# Suppress all warnings since we removed cryptography
warnings.filterwarnings("ignore")

logger = setup_logger('traffic_monitor')

# Configuration 
# Configuration 
THRESHOLD = 150
BURST_THRESHOLD = 300
LONG_TERM_THRESHOLD = 10000
PORT_SCAN_THRESHOLD = 20
SYN_FLOOD_RATIO = 0.8
ANOMALY_DETECTION_SAMPLES = 1000
FLASK_PORT = 5001

# Web security thresholds
LOGIN_ATTEMPT_THRESHOLD = 5
API_RATE_LIMIT = 100
LOGIN_ENDPOINTS = ['/login', '/logout']
FLASK_PORT = 5001

# Web security thresholds
LOGIN_ATTEMPT_THRESHOLD = 5
API_RATE_LIMIT = 100
LOGIN_ENDPOINTS = ['/login', '/logout']

# Initialize components
defense = Firewall()
db = Database()

# Unified tracking structure
# Unified tracking structure
packet_counts = defaultdict(lambda: {
    "count": 0,
    "timestamp": time.time(),
    "ports": set(),
    "syn_count": 0, 
    "syn_count": 0, 
    "tcp_count": 0,
    "history": deque(maxlen=60),
    "hourly_count": 0,
    "last_hour_check": time.time(),
    # Web security metrics
    "login_attempts": 0,
    "last_login_time": time.time(),
    "api_calls": deque(maxlen=60),
    "blocked_until": None,
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
        
        # Optional: Auto-block if threshold exceeded
        if metric_type in ["DoS Detected", "Port Scan Detected"]:
            defense.block_ip(ip_address, f"Autoblock: {metric_type}")
        
    except Exception as e:
        logger.error(f"Error in flag_metric: {str(e)}")

def analyze_traffic_patterns():
    """Periodic analysis of traffic patterns"""
    while True:
        try:
            current_time = time.time()
            for ip, data in packet_counts.items():
                # Cleanup old blocks
                if data["blocked_until"] and current_time > data["blocked_until"]:
                    data["blocked_until"] = None
                    defense.unblock_ip(ip)
                    continue

                # Regular traffic analysis
                if current_time - data["last_hour_check"] > 3600:
                    if data["hourly_count"] > LONG_TERM_THRESHOLD:
                        flag_metric(ip, data["hourly_count"], "Sustained High Traffic")
                    data["hourly_count"] = 0
                    data["last_hour_check"] = current_time

                # Port scan detection
                if len(data["ports"]) > PORT_SCAN_THRESHOLD:
                    flag_metric(ip, len(data["ports"]), "Port Scan Detected")
                    data["ports"].clear()

                # SYN flood detection with improved ratio check
                if data["tcp_count"] >= 50:  # Minimum sample size
                    syn_ratio = data["syn_count"] / data["tcp_count"]
                    if syn_ratio > SYN_FLOOD_RATIO:
                        flag_metric(ip, syn_ratio, "SYN Flood Detected")
                        data["syn_count"] = 0  # Reset after detection
                        data["tcp_count"] = 0

                # ML-based anomaly detection
                if len(packet_features) > ANOMALY_DETECTION_SAMPLES:
                    features = np.array([
                        data["count"],
                        len(data["ports"]),
                        data["syn_count"],
                        np.mean(list(data["history"]))
                    ]).reshape(1, -1)
                    if ml_model.predict(features)[0] == -1:
                        flag_metric(ip, "Anomalous pattern", "ML Detected Anomaly")

            time.sleep(300)  # Run every 5 minutes
            
        except Exception as e:
            logger.error(f"Traffic analysis error: {str(e)}")
            time.sleep(60)

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
    """Enhanced packet processing with web security focus"""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        # Monitor Flask web traffic
        if dst_port == FLASK_PORT:
            current_time = time.time()
            ip_data = packet_counts[src_ip]
            
            # Update counters
            ip_data["count"] += 1
            ip_data["hourly_count"] += 1
            
            # Check if IP is temporarily blocked
            if ip_data["blocked_until"] and current_time < ip_data["blocked_until"]:
                defense.block_ip(src_ip, "Temporary Web Block")
                return
            
            # Rate limiting for API calls
            ip_data["api_calls"].append(current_time)
            recent_calls = sum(1 for t in ip_data["api_calls"] if current_time - t <= 60)
            
            if recent_calls > API_RATE_LIMIT:
                flag_metric(src_ip, recent_calls, "API Rate Limit Exceeded")
                ip_data["blocked_until"] = current_time + 300  # Block for 5 minutes
                defense.block_ip(src_ip, "API Rate Limit")
            
            # Basic DoS protection
            if ip_data["count"] > THRESHOLD:
                alert_type = "Web DoS Attack" if ip_data["count"] > BURST_THRESHOLD else "High Web Traffic"
                flag_metric(src_ip, ip_data["count"], alert_type)
                defense.block_ip(src_ip, alert_type)

def monitor_login_attempts(ip_address):
    """Monitor and handle login attempts"""
    current_time = time.time()
    session_data = packet_counts[ip_address]
    
    # Reset login attempts if more than 30 minutes have passed
    if current_time - session_data["last_login_time"] > 1800:
        session_data["login_attempts"] = 0
    
    session_data["login_attempts"] += 1
    session_data["last_login_time"] = current_time
    
    if session_data["login_attempts"] >= LOGIN_ATTEMPT_THRESHOLD:
        flag_metric(ip_address, session_data["login_attempts"], "Excessive Login Attempts")
        session_data["blocked_until"] = current_time + 900  # Block for 15 minutes
        defense.block_ip(ip_address, "Login Attempts")
        return False
    
    return True

def start_sniffing():
    """Main entry point with enhanced web monitoring"""
    logger.info(f"Starting network monitoring system for web application on port {FLASK_PORT}")
    
    # Capture all web traffic to Flask port
    threading.Thread(target=analyze_traffic_patterns, daemon=True).start()
    threading.Thread(target=train_ml_model, daemon=True).start()
    threading.Thread(target=generate_traffic_report, daemon=True).start()
    
    # Capture all web traffic to Flask port
    sniff(
        prn=process_packets,
        store=False,
        filter=f"tcp port {FLASK_PORT}"
    )

if __name__ == "__main__":
    start_sniffing()
'''
from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.all import get_if_list  # Ensure this is imported
from collections import defaultdict, deque
import time
import threading
from datetime import datetime
import warnings
import re

from database.databaseScript import Database
from logs.logger import setup_logger
from firewallMonitor import Firewall

# Suppress all warnings
warnings.filterwarnings("ignore")

logger = setup_logger('traffic_monitor')

# Configuration 
THRESHOLD = 150
BURST_THRESHOLD = 300
LONG_TERM_THRESHOLD = 10000
PORT_SCAN_THRESHOLD = 20
SYN_FLOOD_RATIO = 0.8
HTTP_FLOOD_THRESHOLD = 500  # Requests per minute
UDP_FLOOD_THRESHOLD = 1000  # Packets per minute
FLASK_PORT = 5001

# Initialize components
defense = Firewall()
db = Database()

# Unified tracking structure with enhanced attack detection
packet_counts = defaultdict(lambda: {
    "count": 0,
    "timestamp": time.time(),
    "ports": set(),
    "syn_count": 0,
    "tcp_count": 0,
    "udp_count": 0,
    "http_count": 0,
    "history": deque(maxlen=60),
    "hourly_count": 0,
    "last_hour_check": time.time(),
    "last_request_time": time.time(),
    "request_rate": 0,
    "blocked_until": None
})

def detect_http_flood(ip_address):
    """Detect HTTP flood attacks based on request rate"""
    ip_data = packet_counts[ip_address]
    current_time = time.time()
    
    # Calculate requests per minute
    time_elapsed = current_time - ip_data["last_request_time"]
    if time_elapsed > 0:
        request_rate = ip_data["http_count"] / (time_elapsed / 60)
        ip_data["request_rate"] = request_rate
        
        if request_rate > HTTP_FLOOD_THRESHOLD:
            flag_metric(ip_address, request_rate, "HTTP Flood Detected")
            defense.block_ip(ip_address, f"HTTP Flood Attack ({int(request_rate)} req/min)")
            return True
    
    return False

def detect_syn_flood(ip_address):
    """Detect SYN flood attacks based on SYN packet ratio"""
    ip_data = packet_counts[ip_address]
    
    # Only check if we have enough TCP packets for meaningful ratio
    if ip_data["tcp_count"] >= 50:
        syn_ratio = ip_data["syn_count"] / ip_data["tcp_count"]
        if syn_ratio > SYN_FLOOD_RATIO:
            flag_metric(ip_address, syn_ratio, "SYN Flood Detected")
            defense.block_ip(ip_address, f"SYN Flood Attack (ratio: {syn_ratio:.2f})")
            return True
    
    return False

def detect_udp_flood(ip_address):
    """Detect UDP flood attacks based on packet rate"""
    ip_data = packet_counts[ip_address]
    current_time = time.time()
    
    # Calculate UDP packets per minute
    time_elapsed = current_time - ip_data["timestamp"]
    if time_elapsed > 0:
        udp_rate = ip_data["udp_count"] / (time_elapsed / 60)
        
        if udp_rate > UDP_FLOOD_THRESHOLD:
            flag_metric(ip_address, udp_rate, "UDP Flood Detected")
            defense.block_ip(ip_address, f"UDP Flood Attack ({int(udp_rate)} pkt/min)")
            return True
    
    return False

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

def is_http_request(payload):
    """Check if packet contains HTTP request"""
    try:
        if payload:
            decoded = payload.decode('utf-8', errors='ignore')
            return any(method in decoded for method in ['GET ', 'POST ', 'PUT ', 'DELETE '])
    except:
        return False
    return False

def process_packets(packet):
    """Enhanced packet processing with attack detection"""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = time.time()
        ip_data = packet_counts[src_ip]
        
        # Update counters
        ip_data["count"] += 1
        ip_data["hourly_count"] += 1
        ip_data["timestamp"] = current_time
        
        # Check if IP is temporarily blocked
        if ip_data["blocked_until"] and current_time < ip_data["blocked_until"]:
            return
        
        # TCP packet processing
        if packet.haslayer(TCP):
            ip_data["tcp_count"] += 1
            
            # Check for SYN flag
            if packet[TCP].flags & 0x02:  # SYN flag
                ip_data["syn_count"] += 1
            
            # Check for HTTP traffic
            if packet.haslayer(Raw) and is_http_request(packet[Raw].load):
                ip_data["http_count"] += 1
                ip_data["last_request_time"] = current_time
        
        # UDP packet processing
        elif packet.haslayer(UDP):
            ip_data["udp_count"] += 1
            
        # Track destination ports
        if packet.haslayer(TCP):
            ip_data["ports"].add(packet[TCP].dport)
        elif packet.haslayer(UDP):
            ip_data["ports"].add(packet[UDP].dport)
        
        # Basic DoS protection
        if ip_data["count"] > THRESHOLD:
            alert_type = "Web DoS Attack" if ip_data["count"] > BURST_THRESHOLD else "High Web Traffic"
            flag_metric(src_ip, ip_data["count"], alert_type)
            defense.block_ip(src_ip, alert_type)

def analyze_traffic_patterns():
    """Periodic analysis of traffic patterns"""
    while True:
        try:
            current_time = time.time()
            for ip, data in packet_counts.items():
                # Cleanup old blocks
                if data["blocked_until"] and current_time > data["blocked_until"]:
                    data["blocked_until"] = None
                    defense.unblock_ip(ip)
                    continue

                # Regular traffic analysis
                if current_time - data["last_hour_check"] > 3600:
                    if data["hourly_count"] > LONG_TERM_THRESHOLD:
                        flag_metric(ip, data["hourly_count"], "Sustained High Traffic")
                    data["hourly_count"] = 0
                    data["last_hour_check"] = current_time

                # Port scan detection
                if len(data["ports"]) > PORT_SCAN_THRESHOLD:
                    flag_metric(ip, len(data["ports"]), "Port Scan Detected")
                    data["ports"].clear()

                # Attack detection
                detect_syn_flood(ip)
                detect_http_flood(ip)
                detect_udp_flood(ip)

            time.sleep(60)  # Run every minute
            
        except Exception as e:
            logger.error(f"Traffic analysis error: {str(e)}")
            time.sleep(30)


def start_sniffing():
    """Main entry point with enhanced monitoring"""
    logger.info(f"Starting enhanced network monitoring system on port {FLASK_PORT}")

    # Start analysis thread
    threading.Thread(target=analyze_traffic_patterns, daemon=True).start()

    # Fetch interfaces and log them
    interfaces = get_if_list()
    logger.info(f"Available interfaces: {interfaces}")

    # Prioritize known loopback-compatible interfaces (Npcap)
    possible_interfaces = [
        iface for iface in interfaces
        if "loopback" in iface.lower() or "npcap" in iface.lower() or "\\Device\\NPF_Loopback" in iface
    ] + interfaces  # Fallback to all

    for iface in possible_interfaces:
        try:
            logger.info(f"Trying to sniff on interface: {iface}")
            sniff(
                iface=iface,
                prn=lambda pkt: [logger.debug(f"Captured packet: {pkt.summary()}"), process_packets(pkt)],
                store=False,
                filter=f"tcp port {FLASK_PORT} or udp port {FLASK_PORT}",
                promisc=True
            )
            return  # Exit loop on successful sniff
        except Exception as e:
            logger.warning(f"Failed to sniff on interface {iface}: {e}")

    logger.error("Failed to start sniffing on any known interface. Please check permissions and interface names.")



if __name__ == "__main__":
    start_sniffing()