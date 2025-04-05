from datetime import datetime, timedelta
from defense.defenseScript import Blocker
from database.databaseScript import Database
import logging

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class RunDefense: 
    def __init__(self):
        '''
        Initalises the RunDefense class, the class that conjoins the database script with the defense script
        Args:
            db: Database instance from databaseScript.py
            block_duration: Duration in seconds that the blocker script needs to block each IP
        '''

        self.db = Database()
        self.blocker = Blocker(block_duration=300)
        logging.info("RunDefense Class Initalised")

    def block_ip(self, ip_address, reason='') -> bool:
        '''
        Block an IP and log the action to the database
        Args: 
            ip_address: IP address to block
            reason: Reason for blocking (optional)
        Returns:
            bool: True if successful, False if unsuccessful
        '''
        try:
            ip_info = self.db._get_ip(ip_address)
            if not ip_info:
                ip_id = self.db._add_ip(ip_address)
                if not ip_id:
                    logging.error(f"Failed to add IP {ip_address} to the database")
                    return False
            else:
                ip_id = ip_info['id']
            
            # Block the IP using the Blocker object
            self.blocker.block_ip(ip_address)

            # Calculate the block times
            block_time = datetime.now()
            unblock_time = block_time + timedelta(seconds=self.blocker.block_duration)

            # Log the block in the database
            block_logged = self.db._add_blocked_ip(
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
                self.blocker.manual_unblock(ip_address)
                return False
            
        except Exception as e: 
            logging.error(f"Error blocking IP {ip_address} | {e}")

    def unblock_ip(self, ip_address) -> bool:
        '''
        Unblock an IP and remove it from the database
        Args:
            ip_address: IP address to unblock
        Returns:
            bool: True if successful, False if unsuccessful
        '''
        try:
            ip_info = self.db._get_ip(ip_address)
            if not ip_info:
                logging.warning(f"IP {ip_address} cannot be found in the database")
                return False
            
            ip_id = ip_info['id']

            # Unblock the IP using the Blocker object
            self.blocker.manual_unblock(ip_address)

            # Update the blocked Ips table - (need to ask about this method)
            self.db._c.execute('''
                UPDATE blocked_ips 
                SET unblock_time = ?
                WHERE ip_id = ? AND unblock_time > ?
            ''', (datetime.now(), ip_id, datetime.now())
            )

            # Log the unblock action
            self.db._add_admin_action(
                ip_id=ip_id,
                action=f"Manually unblocked IP {ip_address}"
            )

            self.db._conn.commit()
            logging.info(f"Successfully logged the unblocking of IP {ip_address} to the database")
            return True
    
        except Exception as e:
            logging.error(f"Error unblocking IP {ip_address} | {e}")


    def add_rate_limit(self, protocol, port=None, per_second=150, burst_limit=50) -> bool:
        '''
        Add a rate limit and add the action to the database
        Args:
            protocol: Protocol to apply the rate limit to
            port: Port to apply the rate limit to
            per_second: How many packets per second are allowed before rate limit applied
            burst_limit: How many instances before rate limit applied
        Returns:
            bool: True if successful, False if unsuccessful
        '''
        pass

    def remove_rate_limit(self, protocol, port=None, per_second=150, burst_limit=50) -> bool:
        '''
        Remove a rate limit and add the action to the database
        Args:
            protocol: Protocol to remove the rate limit from
            port: Port to remove the rate limit from
            per_second: How many packets per second are allowed before rate limit applied
            burst_limit: How many instances before rate limit applied
        Returns:
            bool: True if successful, False if unsuccessful
        '''
        pass