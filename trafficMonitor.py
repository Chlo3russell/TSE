from scapy.all import sniff, IP
from collections import defaultdict
import time
import os
import sqlite3

THRESHOLD = 150  # packets per second threshold for DoS detection
BLOCK_DURATION = 300  # seconds to block an IP

packet_counts = defaultdict(lambda: {"count": 0, "timestamp": time.time()})
blocked_ips = {}

# Ensure we're connecting to the same database as dashboard.py
sqlite_db = sqlite3.connect("database.db", check_same_thread=False)
sqlite_db.row_factory = sqlite3.Row
cursor = sqlite_db.cursor()

# Initialize the database schema (if not already present)
cursor.executescript("""
    CREATE TABLE IF NOT EXISTS Location (
        Location_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Country VARCHAR(100),
        City VARCHAR(100),
        Region VARCHAR(100)
    );
    CREATE TABLE IF NOT EXISTS IP_Traffic (
        IP_Address TEXT PRIMARY KEY,
        Protocol_Type VARCHAR(10),
        User_Agent VARCHAR(255),
        Location_Location_ID INTEGER,
        FOREIGN KEY (Location_Location_ID) REFERENCES Location(Location_ID)
    );
    CREATE TABLE IF NOT EXISTS Flagged_Metrics (
        Metric_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Connection_Frequency VARCHAR(45),
        Failed_Login_Attempts INTEGER,
        Data_Transfer_Volume INTEGER,
        Time_of_Activity DATETIME DEFAULT CURRENT_TIMESTAMP,
        IP_Traffic_IP_Address TEXT,
        FOREIGN KEY (IP_Traffic_IP_Address) REFERENCES IP_Traffic(IP_Address)
    );
""")
sqlite_db.commit()

def log_to_database(ip, alert_type, protocol="TCP", user_agent="Unknown"):
    """
    Logs the detected attack to the SQLite database.
    """
    # Ensure a Location record exists (using default 'Unknown')
    cursor.execute("""
        INSERT OR IGNORE INTO Location (Country, City, Region)
        VALUES ('Unknown', 'Unknown', 'Unknown')
    """)
    sqlite_db.commit()
    cursor.execute("""
        SELECT Location_ID FROM Location
        WHERE Country='Unknown' AND City='Unknown' AND Region='Unknown'
    """)
    location_row = cursor.fetchone()
    location_id = location_row[0] if location_row else 1

    # Upsert IP_Traffic record
    cursor.execute("""
        INSERT OR REPLACE INTO IP_Traffic (IP_Address, Protocol_Type, User_Agent, Location_Location_ID)
        VALUES (?, ?, ?, ?)
    """, (ip, protocol, user_agent, location_id))

    # Log flagged metric
    connection_frequency = f"{packet_counts[ip]['count']} packets/sec"
    failed_login_attempts = 0
    data_transfer_volume = 0
    cursor.execute("""
        INSERT INTO Flagged_Metrics (Connection_Frequency, Failed_Login_Attempts, Data_Transfer_Volume, IP_Traffic_IP_Address)
        VALUES (?, ?, ?, ?)
    """, (connection_frequency, failed_login_attempts, data_transfer_volume, ip))

    sqlite_db.commit()
    print(f"[INFO] Logged to database: {ip} - {alert_type}")

def block_ip(ip):
    """
    Blocks the given IP address.
    """
    if os.name == "nt":
        os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
    else:
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
            if os.name == "nt":
                os.system(f'netsh advfirewall firewall delete rule name="Block {ip}"')
            else:
                os.system(f'sudo iptables -D INPUT -s {ip} -j DROP')
            del blocked_ips[ip]
            log_to_database(ip, "Unblocked")
            print(f"[INFO] Unblocked IP: {ip}")

def packet_callback(packet):
    """
    Process each captured packet.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = time.time()
        packet_data = packet_counts[src_ip]
        if current_time - packet_data["timestamp"] > 1:
            packet_data["count"] = 0
            packet_data["timestamp"] = current_time
        packet_data["count"] += 1

        if packet_data["count"] > THRESHOLD and src_ip not in blocked_ips:
            print(f"[ALERT] Potential DoS attack detected from IP: {src_ip}")
            log_to_database(src_ip, "DoS Detected")
            block_ip(src_ip)

        unblock_expired_ips()

print("[INFO] Starting packet sniffing...")
sniff(prn=packet_callback, store=False)

