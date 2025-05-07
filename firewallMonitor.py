from datetime import datetime, timedelta
import time
from defense.defenseScript import Blocker
from database.databaseScript import Database
from logs.logger import setup_logger  # Changed from setupLogger

logger = setup_logger(__name__)  # Changed from setupLogger

class Firewall: 
    def __init__(self):
        '''
        Initalises the Defense class, the class that conjoins the database script with the defense script.
        '''
        try:
            self.db = Database()
            self.blocker = Blocker()
            self.block_duration = 300
            logger.info("Successfully initalised Firewall")
        except Exception as e:
            logger.exception(f"Failed to initalised Firewall: {e}")

    def block_ip(self, ip_address, reason='') -> bool:
        '''
        Block an IP and log the action to the database\n
        Args: 
            ip_address: IP address to block
            reason: Reason for blocking (optional)\n
        Returns:
            bool: True if successful, False if unsuccessful
        '''
        try:
            # Block the IP using the Blocker object
            if not self.blocker.block_ip(ip_address):
                logger.error(f"Failed to block IP at monitor level: {ip_address}")
                return False
            
            # Check if the IP is already in the database
            ip_info = self.db._get_ip(ip_address)
            # If IP isn't in the database, add the IP and get the IP ID
            if not ip_info:
                ip_id = self.db._add_ip(ip_address)
                if not ip_id:
                    logger.error(f"Failed to add IP {ip_address} to the database")
                    return False
            else:
                ip_id = ip_info['id']

            # Calculate the block times
            block_time = datetime.now()
            unblock_time = block_time + timedelta(seconds=self.block_duration)

            # Log the block in the database
            block_logged = self.db._add_blocked_ip(
                ip_id=ip_id,
                block_time=block_time,
                unblock_time=unblock_time,
                reason=reason
            )

            if block_logged:
                logger.info(f"Successfully logged the block of IP {ip_address} to the database")
                return True
            else:
                logger.error(f"Failed to log the block of IP {ip_address} to the database")
                # If the block cannot be logged, rollback
                self.blocker.unblock_ip(ip_address)
                return False
            
        except Exception as e: 
            logger.exception(f"Error blocking IP: {ip_address} | {e}")
            return False

    def unblock_ip(self, ip_address) -> bool:
        '''
        Unblock an IP and remove it from the database\n
        Args:
            ip_address: IP address to unblock\n
        Returns:
            bool: True if successful, False if unsuccessful
        '''
        try:
            # Unblock the IP using the Blocker object
            if not self.blocker.unblock_ip(ip_address):
                logger.error(f"Blocker failed to unblock IP: {ip_address}")
                return False
            
            # Try to get the IP from the database
            ip_info = self.db._get_ip(ip_address)
            # If you cannot find the IP, throw and error
            if not ip_info:
                logger.warning(f"IP: {ip_address} cannot be found in the database")
                return False
            
            # Get IP ID
            ip_id = ip_info['id']
            
            # Log the unblock action
            self.db._add_admin_action(
                ip_id=ip_id,
                action=f"Manually unblocked IP {ip_address}"
            )

            logger.info(f"Successfully logged the unblocking of IP {ip_address} to the database")
            return True
    
        except Exception as e:
            logger.exception(f"Error unblocking IP: {ip_address} | {e}")
            return False


    def add_rate_limit(self, protocol, port=None, per_second=150, burst_limit=50) -> bool:
        '''
        Add a rate limit and add the action to the database\n
        Args:
            protocol: Protocol to apply the rate limit to
            port: Port to apply the rate limit to
            per_second: How many packets per second are allowed before rate limit applied
            burst_limit: How many instances before rate limit applied
        Returns:
            bool: True if successful, False if unsuccessful
        '''
        try: 
            if not self.blocker.add_rate_limit(protocol, port, per_second, burst_limit):
                logger.error(f"Blocker failed to add rate limit for Protocol: {protocol}, Port: {port}")
                return False
            
            self.db._add_rate_limit_action("Add rate limit", {
                'protocol': protocol,
                'port': port,
                'limit': per_second,
                'burst': burst_limit
            })
            logger.info(f"Added rate limit for Protocol: {protocol}, Port: {port}")
            return True
        except Exception as e:
            logger.exception(f"Error adding rate limit for Protocol: {protocol}, Port: {port} | {e}")
            return False

    def remove_rate_limit(self, protocol, port=None, per_second=150, burst_limit=50) -> bool:
        '''
        Remove a rate limit and add the action to the database\n
        Args:
            protocol: Protocol to remove the rate limit from
            port: Port to remove the rate limit from
            per_second: How many packets per second are allowed before rate limit applied
            burst_limit: How many instances before rate limit applied
        Returns:
            bool: True if successful, False if unsuccessful
        '''
        try: 
            if not self.blocker.remove_rate_limit(protocol, port, per_second, burst_limit):
                logger.error(f"Blocker failed to remove rate limit for Protocol: {protocol}, Port: {port}")
                return False
            
            self.db._add_rate_limit_action("Remove rate limit", {
                'protocol': protocol,
                'port': port,
                'limit': per_second,
                'burst': burst_limit
            })
            logger.info(f"Removed rate limit for Protocol: {protocol}, Port: {port}")
            return True
        except Exception as e:
            logger.exception(f"Error removing rate limit for Protocol: {protocol}, Port: {port} | {e}")
            return False
    
    def cleanup_loop(self, interval=300, days_to_keep=30):
        while True:
            try:
                self.db._clear_records(days_to_keep=days_to_keep) # DB cleanup
                logger.info("Periodic cleanup complete")
            except Exception as e:
                logger.exception(f"Unexpected exception when cleaning records: {e}") 
            time.sleep(interval) # Run every 5 mins