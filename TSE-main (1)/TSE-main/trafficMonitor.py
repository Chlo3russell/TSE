from scapy.all import sniff, IP, TCP, UDP, Raw
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
    
    # Capture all traffic to Flask port
    sniff(
        prn=process_packets,
        store=False,
        filter=f"tcp port {FLASK_PORT} or udp port {FLASK_PORT}"
    )

if __name__ == "__main__":
    start_sniffing()
