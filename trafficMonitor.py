from scapy.all import sniff, IP
from collections import defaultdict
import time
import os
import mysql.connector

# Threshold for detecting potential DoS attacks
THRESHOLD = 100  # Number of packets per second from a single IP
BLOCK_DURATION = 300  # Duration (in seconds) to block an IP

# Dictionary to track packet counts and timestamps
packet_counts = defaultdict(lambda: {"count": 0, "timestamp": time.time()})
blocked_ips = {}

# Connect to MySQL database
db = mysql.connector.connect(
    host="localhost",
    user="root",  # Replace with your MySQL username
    password="password",  # Replace with your MySQL password
    database="traffic_monitoring"
)
cursor = db.cursor()

def log_to_database(ip, alert_type, protocol="TCP", user_agent="Unknown", country="Unknown", city="Unknown", region="Unknown"):
    """
    Logs the detected attack to the MySQL database.
    """
    # Insert location data
    location_query = """
        INSERT INTO Location (Country, City, Region)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE Location_ID=LAST_INSERT_ID(Location_ID)
    """
    cursor.execute(location_query, (country, city, region))
    location_id = cursor.lastrowid

    # Insert IP traffic data
    ip_traffic_query = """
        INSERT INTO IP_Traffic (IP_Address, Protocol_Type, User_Agent, Location_Location_ID)
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE IP_Address=IP_Address
    """
    cursor.execute(ip_traffic_query, (ip, protocol, user_agent, location_id))

    # Insert flagged metrics
    flagged_metrics_query = """
        INSERT INTO Flagged_Metrics (Connection_Frequency, Failed_Login_Attempts, Data_Transfer_Volume, IP_Traffic_IP_Address)
        VALUES (%s, %s, %s, %s)
    """
    connection_frequency = f"{packet_counts[ip]['count']} packets/sec"
    failed_login_attempts = 0  # Placeholder, update if you track login attempts
    data_transfer_volume = 0  # Placeholder, update if you track data volume
    cursor.execute(flagged_metrics_query, (connection_frequency, failed_login_attempts, data_transfer_volume, ip))

    db.commit()
    print(f"[INFO] Logged to database: {ip} - {alert_type}")

def block_ip(ip):
    """
    Blocks the given IP address using Windows Firewall (or iptables for Linux).
    """
    if os.name == "nt":  # Windows
        os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
    else:  # Linux
        os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')
    blocked_ips[ip] = time.time()
    log_to_database(ip, "Blocked")
    print(f"[ALERT] Blocked IP: {ip}")

def unblock_expired_ips():
    """
    Unblocks IPs after the block duration has expired.
    """
    current_time = time.time()
    for ip, block_time in list(blocked_ips.items()):
        if current_time - block_time > BLOCK_DURATION:
            if os.name == "nt":  # Windows
                os.system(f'netsh advfirewall firewall delete rule name="Block {ip}"')
            else:  # Linux
                os.system(f'sudo iptables -D INPUT -s {ip} -j DROP')
            del blocked_ips[ip]
            log_to_database(ip, "Unblocked")
            print(f"[INFO] Unblocked IP: {ip}")

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = time.time()

        # Update packet count and timestamp
        packet_data = packet_counts[src_ip]
        if current_time - packet_data["timestamp"] > 1:  # Reset count every second
            packet_data["count"] = 0
            packet_data["timestamp"] = current_time
        packet_data["count"] += 1

        # Check if the IP exceeds the threshold
        if packet_data["count"] > THRESHOLD and src_ip not in blocked_ips:
            print(f"[ALERT] Potential DoS attack detected from IP: {src_ip}")
            log_to_database(src_ip, "DoS Detected")
            block_ip(src_ip)

        # Unblock expired IPs
        unblock_expired_ips()

# Start sniffing packets
print("[INFO] Starting packet sniffing...")
sniff(prn=packet_callback, store=False)
