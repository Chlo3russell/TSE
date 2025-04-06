from scapy.all import sniff, IP
from collections import defaultdict
import time
from database.databaseScript import Database
from defense.defenseScript import Blocker
import logging
from datetime import timedelta, datetime

THRESHOLD = 150
BLOCK_DURATION = 300

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

packet_counts = defaultdict(lambda: {"count": 0, "timestamp": time.time()})
blocked_ips = {}

db = Database()
blocker = Blocker(block_duration=300)
logging.info("RunDefense Class Initalised")

def block_ip(ip_address, reason='') -> bool:
        '''
        Block an IP and log the action to the database
        Args: 
            ip_address: IP address to block
            reason: Reason for blocking (optional)
        Returns:
            bool: True if successful, False if unsuccessful
        '''
        try:
            ip_info = db._get_ip(ip_address)
            if not ip_info:
                ip_id = db._add_ip(ip_address)
                if not ip_id:
                    logging.error(f"Failed to add IP {ip_address} to the database")
                    return False
            else:
                ip_id = ip_info['id']
            
            # Block the IP using the Blocker object
            blocker.block_ip(ip_address)

            # Calculate the block times
            block_time = datetime.now()
            unblock_time = block_time + datetime.timedelta(seconds=blocker.block_duration)

            # Log the block in the database
            block_logged = db._add_blocked_ip(
                ip_id=ip_id,
                block_time=block_time,
                unblock_time=unblock_time,
                reason=reason
            )

            if block_logged:
                logging.info(f"Successfully logged the block of IP {ip_address} to the database")
                return True
            else:
                logging.error(f"Failed to log the block of IP {ip_address} to the database")
                # If the block cannot be logged, rollback
                blocker.manual_unblock(ip_address)
                return False
            
        except Exception as e: 
            logging.error(f"Error blocking IP {ip_address} | {e}")

def unblock_ip(ip_address) -> bool:
    '''
    Unblock an IP and remove it from the database
    Args:
        ip_address: IP address to unblock
    Returns:
        bool: True if successful, False if unsuccessful
    '''
    try:
        ip_info = db._get_ip(ip_address)
        if not ip_info:
            logging.warning(f"IP {ip_address} cannot be found in the database")
            return False
        
        ip_id = ip_info['id']

        # Unblock the IP using the Blocker object
        blocker.manual_unblock(ip_address)

        # Update the blocked Ips table - (need to ask about this method)
        db._c.execute('''
            UPDATE blocked_ips 
            SET unblock_time = ?
            WHERE ip_id = ? AND unblock_time > ?
        ''', (datetime.now(), ip_id, datetime.now())
        )

        # Log the unblock action
        db._add_admin_action(
            ip_id=ip_id,
            action=f"Manually unblocked IP {ip_address}"
        )

        db._conn.commit()
        logging.info(f"Successfully logged the unblocking of IP {ip_address} to the database")
        return True

    except Exception as e:
        logging.error(f"Error unblocking IP {ip_address} | {e}")

def commit_to_db():
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
            logging.warning(f"Potential DoS attack detected from IP: {source_ip}")
            commit_to_db(source_ip, "DoS Detected")
            block_ip(source_ip, "DoS Detected")

        db._clear_records()

logging.info("Starting packet sniffing...")
sniff(prn=process_packets, store=False)