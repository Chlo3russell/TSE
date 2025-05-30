import whois
import sqlite3
from datetime import datetime, timedelta
from scapy.all import IP, ICMP, sr1
from logs.logger import setup_logger
import os
import random

# Add a dictionary of UK cities
UK_CITIES = {
    "London": {"region": "England", "country": "United Kingdom"},
    "Manchester": {"region": "England", "country": "United Kingdom"},
    "Edinburgh": {"region": "Scotland", "country": "United Kingdom"},
    "Cardiff": {"region": "Wales", "country": "United Kingdom"},
    "Belfast": {"region": "Northern Ireland", "country": "United Kingdom"},
    "Birmingham": {"region": "England", "country": "United Kingdom"},
    "Glasgow": {"region": "Scotland", "country": "United Kingdom"},
    "Leeds": {"region": "England", "country": "United Kingdom"},
    "Liverpool": {"region": "England", "country": "United Kingdom"},
    "Bristol": {"region": "England", "country": "United Kingdom"}
}

# Add a dictionary of ISPs
UK_ISPS = {
    "BT": {"contact_information": "support@bt.com"},
    "Virgin Media": {"contact_information": "support@virginmedia.com"},
    "Sky Broadband": {"contact_information": "support@sky.com"},
    "TalkTalk": {"contact_information": "support@talktalk.com"},
    "Vodafone": {"contact_information": "support@vodafone.com"},
    "Plusnet": {"contact_information": "support@plus.net"},
    "EE": {"contact_information": "support@ee.co.uk"},
    "Hyperoptic": {"contact_information": "support@hyperoptic.com"},
    "Zen Internet": {"contact_information": "support@zen.co.uk"},
    "Gigaclear": {"contact_information": "support@gigaclear.com"}
}

# iniliase logger
logger = setup_logger(__name__)

# Create a simple table
class Database:
    def __init__(self):
        # Protected methods
        db_path = os.path.join(os.path.dirname(__file__), 'database.db')
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute('PRAGMA foreign_keys = ON')
        self._c = self._conn.cursor()

        # Call private method to setup db & create indexes
        self.__setup_db()
        self.__create_indexes()
        #logger.info("Database initialised successfully.")
    
    def __setup_db(self):
        
        try:
            # create IP table
            self._c.execute('''
                CREATE TABLE IF NOT EXISTS ip_list (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address VARCHAR(40) UNIQUE NOT NULL,
                    location_id INTEGER,
                    isp_id INTEGER,
                    FOREIGN KEY (location_id) REFERENCES location(id),
                    FOREIGN KEY (isp_id) REFERENCES isp(id)
                )
            ''')
            #logger.info("Table 'ip_list' created successfully.")

            # Create Blocked IP table
            self._c.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_id INTEGER NOT NULL,
                    block_time TIMESTAMP NOT NULL,
                    unblock_time TIMESTAMP,
                    reason TEXT,
                    FOREIGN KEY (ip_id) REFERENCES ip_list(id) ON DELETE CASCADE
                )
            ''')
            #logger.info("Table 'blocked_ips' created successfully.")

            # Create Traffic table
            self._c.execute('''
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip_id INTEGER NOT NULL,
                    destination_ip VARCHAR(40) NOT NULL,
                    protocol_type INTEGER NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    FOREIGN KEY (source_ip_id) REFERENCES ip_list(id) ON DELETE CASCADE
                )
            ''')
            #logger.info("Table 'traffic_logs' created successfully.")

            # Create Rate limiting events table
            self._c.execute('''
                CREATE TABLE IF NOT EXISTS rate_limit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    action TEXT NOT NULL,
                    config TEXT
                )
            ''')
            #logger.info("Table 'rate_limit_logs' created successfully.")

            # Create Admin events table
            self._c.execute('''
                CREATE TABLE IF NOT EXISTS admin_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_id INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    action TEXT NOT NULL,
                    FOREIGN KEY (ip_id) REFERENCES ip_list(id) ON DELETE CASCADE
                )
            ''')
            #logger.info("Table 'admin_logs' created successfully.")

            # Create flagged metrics table
            self._c.execute('''
                CREATE TABLE IF NOT EXISTS flagged_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_id INTEGER NOT NULL,
                    metric_type TEXT NOT NULL,
                    value FLOAT NOT NULL,
                    time_of_activity DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    FOREIGN KEY (ip_id) REFERENCES ip_list(id) ON DELETE CASCADE
                )
            ''')
            #logger.info("Table 'flagged_metrics' created successfully.")

            # Create Location table
            self._c.execute('''
                CREATE TABLE IF NOT EXISTS location (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    country VARCHAR(100),
                    city VARCHAR(100),
                    region VARCHAR(100)
                )
            ''')
            #logger.info("Table 'location' created successfully.")

            # Create ISP table
            self._c.execute('''
                CREATE TABLE IF NOT EXISTS isp (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    isp_name VARCHAR(100),
                    contact_information VARCHAR(255)
                )
            ''')
            #logger.info("Table 'isp' created successfully.")

        except sqlite3.Error as e:
            logger.error(f"Error creating tables: {e}")
            raise

### INDEX
    def __create_indexes(self):
        
        #Create database indexes for some tables for performance.
        
        try:
            # Index for frequently queried columns
            self._c.execute('CREATE INDEX IF NOT EXISTS index_ip_address ON ip_list(ip_address)')
            #logger.info("Index 'index_ip_address' created successfully.")

            self._c.execute('CREATE INDEX IF NOT EXISTS index_blocked_ips_id ON blocked_ips(ip_id)')
            
            #logger.info("Index 'index_ip_address' created successfully.")
            self._c.execute('CREATE INDEX IF NOT EXISTS index_traffic_logs_timestamp ON traffic_logs(timestamp)')
            
            #logger.info("Index 'index_ip_address' created successfully.")
            self._c.execute('CREATE INDEX IF NOT EXISTS index_admin_logs_timestamp ON admin_logs(timestamp)')

            self._c.execute('CREATE INDEX IF NOT EXISTS index_flagged_metrics_time ON flagged_metrics(time_of_activity)')
            #logger.info("Index 'index_ip_address' created successfully.")
            
        except sqlite3.Error as e:
            self._conn.rollback()
            print(f"Error creating indexes: {e}")
            raise

### HELPER FUNCTIONS
    def _get_ip_info_whois(self, ip_address):
        
        #Helper function to get IP information using whois
        
        try:
            w = whois.whois(ip_address)
            country = w.country or "Unknown"
            city = "Unknown"  # whois often doesn't provide city
            region = "Unknown"
            isp_name = w.org or "Unknown"
            contact = w.emails[0] if w.emails else "No contact information"
            
            return {
                'country': country,
                'city': city,
                'region': region,
                'isp_name': isp_name,
                'contact': contact
            }
        except Exception as e:
            logger.error(f"Error getting whois information: {e}")
            return None

    def _get_ip_info_scapy(self, ip_address):
        
        #Helper function to get IP information using scapy
        
        try:
            # Send ICMP echo request
            packet = IP(dst=ip_address)/ICMP()
            reply = sr1(packet, timeout=2, verbose=False)
            
            if reply:
                # Get TTL and other information from reply
                ttl = reply.ttl
                source = reply.src
                
                return {
                    'source': source,
                    'ttl': ttl
                }
        except Exception as e:
            logger.error(f"Error getting scapy information: {e}")
            return None

### SETTER FUNCTIONS
    def _add_flagged_metric(self, ip_id, metric_type, value):
        '''
        Add flagged metrics to the database
        Args:
            ip_id: IP ID
            metric_type: Type of metric being flagged (SYN, UDP, etc)
            value: Value of suspicion
        '''
        try:
            self._c.execute('''
                INSERT INTO flagged_metrics (ip_id, metric_type, value)
                VALUES (?, ?, ?)
            ''', (ip_id, metric_type, value))
            self._conn.commit()
            logger.info(f"Flagged metric added: {metric_type} for IP ID {ip_id}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Error flagging metric: {e}")
            self._conn.rollback()
            return False

    def _add_location(self, country, city, region):
        
        #Add location information to the database. Can be called directly or used with IP lookup.
        
        #Args:
        #    country (str): Country name
        #    city (str): City name
        #    region (str): Region/state name
        
        #Returns:
        #    int: Location ID
        
        try:
            # Check if location exists
            self._c.execute('''
                SELECT id FROM location 
                WHERE country = ? AND city = ? AND region = ?
            ''', (country, city, region))
            
            existing_location = self._c.fetchone()
            if existing_location:
                logger.info(f"Location already exists: {country}, {city}, {region}")
                return existing_location[0]
            
            # Insert new location
            self._c.execute('''
                INSERT INTO location (country, city, region)
                VALUES (?, ?, ?)
            ''', (country, city, region))
            
            self._conn.commit()
            logger.info(f"Location added: {country}, {city}, {region}")
            return self._c.lastrowid
        
        except sqlite3.Error as e:
            logger.error(f"Error adding location: {e}")
            self._conn.rollback()
            return None

    def _add_isp(self, isp_name, contact_information):
        
        #Add ISP information to the database
        
        #Args:
        #    isp_name (str): Name of the ISP
        #    contact_information (str): Contact details for the ISP
        
        #Returns:
        #    int: ISP ID
        
        try:
            # Randomly select an ISP if none is provided
            if isp_name is None or contact_information is None:
                isp_name, details = random.choice(list(UK_ISPS.items()))
                contact_information = details["contact_information"]

            # Check if ISP exists
            self._c.execute('''
                SELECT id FROM isp 
                WHERE isp_name = ?
            ''', (isp_name,))
            
            existing_isp = self._c.fetchone()
            if existing_isp:
                logger.info(f"ISP already exists: {isp_name}")
                return existing_isp[0]
            
            # Insert new ISP
            self._c.execute('''
                INSERT INTO isp (isp_name, contact_information)
                VALUES (?, ?)
            ''', (isp_name, contact_information))
            
            self._conn.commit()
            logger.info(f"ISP added: {isp_name}")
            return self._c.lastrowid
        
        except sqlite3.Error as e:
            logger.error(f"Error adding ISP: {e}")
            self._conn.rollback()
            return None

    def _add_blocked_ip(self, ip_id, block_time=None, unblock_time=None, reason=""):
        
        #Add an IP to the blocked IPs list
        
        #Args:
        #    ip_id (str): ID of the IP to block
        #    block_time (datetime): Time when the block starts (default: current time)
        #    unblock_time (datetime): Time when the block ends (default: 24 hours from block_time)
        #    reason (str): Reason for blocking the IP
        
        #Returns:
        #    bool: True if successful, False otherwise
        
        try:
            # Set default block time to current time if not provided
            if block_time is None:
                block_time = datetime.now()
                
            # Set default unblock time to 24 hours from block time if not provided
            if unblock_time is None:
                unblock_time = block_time + timedelta(hours=24)
                
            # Check if IP is already blocked
            self._c.execute('''
                SELECT id FROM blocked_ips 
                WHERE ip_id = ? AND unblock_time > ?
            ''', (ip_id, datetime.now()))
            
            if self._c.fetchone():
                logger.warning(f"IP {ip_id} is already blocked.")
                return False
                
            # Insert new blocked IP
            self._c.execute('''
                INSERT INTO blocked_ips (ip_id, block_time, unblock_time, reason)
                VALUES (?, ?, ?, ?)
            ''', (ip_id, block_time, unblock_time, reason))
            
            # Log the blocking action in admin_logs
            self._c.execute('''
                INSERT INTO admin_logs (ip_id, action)
                VALUES (?, ?)
            ''', (ip_id, f"IP Blocked: {reason}"))
            
            self._conn.commit()
            logger.info(f"IP {ip_id} blocked successfully.")
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error blocking IP: {e}")
            self._conn.rollback()
            return False

    # Add/ log an admins action, did they change something e.g. add a new rate limit/ did they manually unblock someone/ change the value of a major metric i.e. the block duration
    def _add_admin_action(self, ip_id, action):
        # Log a rate limit change
        #db._add_admin_action(ip_id=123, action="Changed rate limit from 100 to 200 req/min")

        # Log an IP unblock
        #db._add_admin_action(ip_id=456, action="Manually unblocked IP")

        # Log a system configuration change
        #db._add_admin_action(ip_id=0, action="Updated default block duration to 48 hours")

        try:
            # Validate inputs
            if not isinstance(ip_id, (int, str)) or not action:
                logger.warning("Invalid input parameters for admin action.")
                return False
                
            # Insert the admin action
            self._c.execute('''
                INSERT INTO admin_logs (ip_id, action)
                VALUES (?, ?)
            ''', (ip_id, action))
            
            self._conn.commit()
            logger.info(f"Admin action logged: {action}")
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error logging admin action: {e}")
            self._conn.rollback()
            return False

    # Add/ log the changes to rate limiting - what was changed/ what port/ when etc.
    def _add_rate_limit_action(self, action, config):
        # Example usage:

        # Changing rate limit for a specific endpoint
        #config = {
        #    'endpoint': '/api/data',
        #    'old_limit': 100,
        #    'new_limit': 200,
        #    'time_window': '1 minute'
        #}
        #db._add_rate_limit_action(
        #    action="Modified API endpoint rate limit", 
        #    config=config
        #)

        # Adding new rate limit rule
        #config = {
        #    'ip_range': '192.168.1.0/24',
        #    'limit': 1000,
        #    'time_window': '1 hour',
        #    'priority': 1
        #}
        #db._add_rate_limit_action(
        #    action="Added new rate limit rule for internal network", 
        #    config=config
        #)

        # Modifying global rate limit
        #config = {
        #    'type': 'global',
        #    'old_limit': 5000,
        #    'new_limit': 10000,
        #    'time_window': '1 hour'
        #}
        #db._add_rate_limit_action(
        #    action="Increased global rate limit", 
        #    config=config
        #)

        try:
            # Validate inputs
            if not action or not isinstance(config, dict):
                logger.warning("Invalid input parameters for rate limit action.")
                return False
            
            # Convert config dict to string for storage
            config_str = str(config)
            
            # Insert the rate limit action
            self._c.execute('''
                INSERT INTO rate_limit_logs (action, config)
                VALUES (?, ?)
            ''', (action, config_str))
            
            # Log in admin_logs as well for auditing
            self._c.execute('''
                INSERT INTO admin_logs (ip_id, action)
                VALUES (?, ?)
            ''', (None, f"Rate Limit Change: {action}"))
            
            self._conn.commit()
            logger.info(f"Rate limit action logged: {action}")
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error logging rate limit action: {e}")
            self._conn.rollback()
            return False

    # Add an ip to the central ip table
    def _add_ip(self, ip_address, location_id=None, isp_id=None):

        # Add IP with location and ISP info
        #location_id = db._add_location('USA', 'New York', 'NY')
        #isp_id = db._add_isp('Example ISP', 'support@example.com')
        #ip_id = db._add_ip('192.168.1.2', location_id, isp_id)

        try:
            # Check if IP already exists
            self._c.execute('''
                SELECT id FROM ip_list 
                WHERE ip_address = ?
            ''', (ip_address,))
            
            existing_ip = self._c.fetchone()
            if existing_ip:
                logger.info(f"IP already exists: {ip_address}")
                return existing_ip[0]
            
            # Randomly select a UK city if location_id is not provided
            if location_id is None:
                city, details = random.choice(list(UK_CITIES.items()))
                location_id = self._add_location(details["country"], city, details["region"])
            
            # Randomly select an ISP if isp_id is not provided
            if isp_id is None:
                isp_name, details = random.choice(list(UK_ISPS.items()))
                isp_id = self._add_isp(isp_name, details["contact_information"])
        
            
            # Insert new IP
            self._c.execute('''
                INSERT INTO ip_list (ip_address, location_id, isp_id)
                VALUES (?, ?, ?)
            ''', (ip_address, location_id, isp_id))
            
            self._conn.commit()
            ip_id = self._c.lastrowid
            
            # Log the action in admin_logs
            self._c.execute('''
                INSERT INTO admin_logs (ip_id, action)
                VALUES (?, ?)
            ''', (ip_id, f"IP Added: {ip_address}"))
            
            self._conn.commit()
            logger.info(f"IP added successfully: {ip_address}")
            return ip_id
        
        except sqlite3.Error as e:
            logger.error(f"Error adding IP: {e}")
            self._conn.rollback()
            return None


### GETTER FUNCTIONS
    # Query to get a list of blocked IPs, optionally filtered by a specific IP address
    def _get_blocked_ips(self, ip_address=None):
            try:
                if ip_address:
                    self._c.execute("""
                        SELECT bi.*, il.ip_address 
                        FROM blocked_ips AS bi
                        JOIN ip_list AS il ON bi.ip_id = il.id
                        WHERE il.ip_address = ?
                    """, (ip_address,))
                    logger.info(f"Retrieved blocked IPs for IP address: {ip_address}")
                else:
                    self._c.execute("""
                        SELECT bi.*, il.ip_address 
                        FROM blocked_ips AS bi
                        JOIN ip_list AS il ON bi.ip_id = il.id
                    """)
                    logger.info("Retrieved all blocked IPs.")
                return self._c.fetchall()
            except sqlite3.Error as e:
                logger.error(f"Error fetching blocked IPs: {e}")
                return []

    # Query to get traffic logs, optionally filtered by a start and end timestamp
    def _get_traffic_logs(self, start_time=None, end_time=None):
            try:
                if start_time and end_time:
                    self._c.execute("""
                        SELECT * FROM traffic_logs
                        WHERE timestamp BETWEEN ? AND ?
                    """, (start_time, end_time))
                    logger.info(f"Retrieved traffic logs between {start_time} and {end_time}.")
                else:
                    self._c.execute("SELECT * FROM traffic_logs")
                    logger.info("Retrieved all traffic logs.")
                return self._c.fetchall()
            except sqlite3.Error as e:
                logger.error(f"Error fetching traffic logs: {e}")
                return []

    # Query to get an ip/ ip id from the ips table
    def _get_ip(self, ip_address=None, ip_id=None):
        # Get IP by address
        #ip_info = db._get_ip(ip_address='192.168.1.1')

        # Get IP by ID
        #ip_info = db._get_ip(ip_id=1)

        # Example response structure:
        # {
        #     'id': 1,
        #     'ip_address': '192.168.1.1',
        #     'location': {
        #         'country': 'USA',
        #         'city': 'New York',
        #         'region': 'NY'
        #     },
        #     'isp': {
        #         'name': 'Example ISP',
        #         'contact': 'support@example.com'
        #     }
        # }

        try:
            query = """
                SELECT ip.id, ip.ip_address, ip.location_id, ip.isp_id,
                    l.country, l.city, l.region,
                    i.isp_name, i.contact_information
                FROM ip_list ip
                LEFT JOIN location l ON ip.location_id = l.id
                LEFT JOIN isp i ON ip.isp_id = i.id
                WHERE 1=1
            """
            params = []

            if ip_address:
                query += " AND ip.ip_address = ?"
                params.append(ip_address)
            elif ip_id:
                query += " AND ip.id = ?"
                params.append(ip_id)
            else:
                logger.warning("No IP address or IP ID provided for _get_ip query.")
                return None

            self._c.execute(query, params)
            row = self._c.fetchone()
            if row:
                logger.info(f"Retrieved IP details for IP: {ip_address or ip_id}.")
                return {
                    'id': row['id'],
                    'ip_address': row['ip_address'],
                    'location': {
                        'country': row['country'],
                        'city': row['city'],
                        'region': row['region']
                    },
                    'isp': {
                        'name': row['isp_name'],
                        'contact': row['contact_information']
                    }
                }
            logger.warning(f"No IP details found for IP: {ip_address or ip_id}.")
            return None

        except sqlite3.Error as e:
            logger.error(f"Error retrieving IP information: {e}")
            return None
        
    # Query to get the changes/ actions taken on rate limits
    def _get_rate_limit_actions(self) -> list:
        '''
        Gets all rate limit actions from the database
        Returns: 
            List of dicts containing timestamp, action and config if present
        '''
        try:
            self._c.execute('''
                SELECT timestamp, action, 
                CASE WHEN config IS NULL THEN '' ELSE config END as config
                FROM rate_limit_logs
                ORDER BY timestamp DESC
            ''')
            results = self._c.fetchall()
            #logger.info("Retrieved all rate limit actions.")
            return [{
                'timestamp': row['timestamp'],
                'action': row['action'],
                'config': row['config']
            } for row in results]
        except sqlite3.Error as e:
            logger.error(f"Error retrieving rate limit actions: {e}")
            return []

    # Query to get a records of the admins actions/ changes they've made 
    def _get_admin_actions(self, start_date=None, end_date=None, ip_id=None, limit=100):
        '''
        Get all admin actions (limited to 100)
        actions = db._get_admin_actions()

        Get actions for a specific IP
        actions = db._get_admin_actions(ip_id='123')

        Get actions within a date range
        from datetime import datetime, timedelta
        start = datetime.now() - timedelta(days=7)  # Last 7 days
        actions = db._get_admin_actions(start_date=start)
        '''
        try:
            query = """
                SELECT al.id, al.ip_id, al.timestamp, al.action, ip.ip_address
                FROM admin_logs al
                LEFT JOIN ip_list ip ON al.ip_id = ip.id
                WHERE 1=1
            """
            params = []

            if start_date:
                query += " AND al.timestamp >= ?"
                params.append(start_date)

            if end_date:
                query += " AND al.timestamp <= ?"
                params.append(end_date)

            if ip_id:
                query += " AND al.ip_id = ?"
                params.append(ip_id)

            query += " ORDER BY al.timestamp DESC LIMIT ?"
            params.append(limit)

            self._c.execute(query, params)
            rows = self._c.fetchall()
            logger.info("Retrieved admin actions.")
            return [{
                'id': row['id'],
                'ip_id': row['ip_id'],
                'ip_address': row['ip_address'],
                'timestamp': row['timestamp'],
                'action': row['action']
            } for row in rows]
        
        except sqlite3.Error as e:
            logger.error(f"Error retrieving admin actions: {e}")
            return []

    def get_whois_info(domain):
        try:
            # Remove 'https://' from the domain
            domain = domain.replace('https://', '').replace('http://', '')
            w = whois.whois(domain)
            logger.info(f"WHOIS data retrieved for domain: {domain}")
            return w
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

### DELETE FUNCTION
    def unblock_ip(self, ip_address):
        '''
        Remove an IP from the blocked_ips table after it has been unblocked from the firewall\n
        Args:
            ip_address: IP given to unblock
        Returns:
            bool: True or False depending on success of removal
        '''
        try:
            self._c.execute("""
                SELECT id from ip_list WHERE ip_address = ?
            """, (ip_address,))
            result = self._c.fetchone()

            if result == None:
                logger.warning(f"IP: {ip_address} not found in IP list")
                return False
            
            ip_id = result[0]

            self._c.execute("""
                DELETE FROM blocked_ips WHERE ip_id = ?
            """, (ip_id,))
            self._conn.commit()

            if self._c.rowcount == 0:
                logger.info(f"No blocked record found for IP: {ip_address}")
            else:
                logger.info(f"Unblocked IP: {ip_address}")

            return True
        except sqlite3.Error as e:
            logger.error(f"Error occurred whilst removing IP from blocked IPs table: {e}")
            return False

    def _clear_records(self, days_to_keep=30) -> dict:
        """
        Sets up automatic cleanup of old records and performs immediate cleanup.
        Args:
            days_to_keep (int): Number of days to keep records before deletion (default: 30)
        Returns:
            dict: Count of deleted records per table, or None if error occurs
        """

        try:
            # Create a table to store cleanup configuration
            self._c.execute('''
                CREATE TABLE IF NOT EXISTS cleanup_config (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    days_to_keep INTEGER NOT NULL,
                    last_cleanup TIMESTAMP
                )
            ''')
            logger.info("Cleanup configuration table created or already exists.")

            # Create trigger for automatic unblocking
            self._c.execute('''
                CREATE TRIGGER IF NOT EXISTS unblock_expired_ips
                AFTER UPDATE ON blocked_ips
                BEGIN
                    UPDATE blocked_ips 
                    SET unblock_time = CURRENT_TIMESTAMP,
                        reason = reason || ' (Auto-unblocked)'
                    WHERE unblock_time <= CURRENT_TIMESTAMP 
                    AND unblock_time IS NOT NULL;

                    INSERT INTO admin_logs (ip_id, action)
                    SELECT ip_id, 'IP Auto-unblocked: Block duration expired'
                    FROM blocked_ips
                    WHERE unblock_time <= CURRENT_TIMESTAMP;
                END;
            ''')
            logger.info("Trigger for auto-unblocking expired IPs created or already exists.")

            # Update or insert cleanup configuration
            self._c.execute('''
                INSERT OR REPLACE INTO cleanup_config (id, days_to_keep, last_cleanup)
                VALUES (1, ?, CURRENT_TIMESTAMP)
            ''', (days_to_keep,))
            logger.info(f"Cleanup configuration updated with days_to_keep={days_to_keep}.")
            

            # Define tables and their timestamp columns for cleanup
            tables = {
                'traffic_logs': 'timestamp',
                'rate_limit_logs': 'timestamp',
                'admin_logs': 'timestamp',
                'flagged_metrics': 'time_of_activity',
                'blocked_ips': 'unblock_time'
            }

            # Create triggers for automatic cleanup
            for table, timestamp_col in tables.items():
                self._c.execute(f'''
                    CREATE TRIGGER IF NOT EXISTS cleanup_{table}_trigger
                    AFTER INSERT ON {table}
                    BEGIN
                        DELETE FROM {table}
                        WHERE {timestamp_col} < datetime('now', '-' || (
                            SELECT days_to_keep FROM cleanup_config WHERE id = 1
                        ) || ' days');
                    END;
                ''')
                logger.info(f"Cleanup trigger created for table: {table}.")
                

            # Perform immediate cleanup
            deleted_counts = {}
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)

            for table, timestamp_col in tables.items():
                # Get count of records to be deleted
                self._c.execute(f'''
                    SELECT COUNT(*) FROM {table}
                    WHERE {timestamp_col} < ?
                ''', (cutoff_date,))
                count = self._c.fetchone()[0]

                if count > 0:
                    # Delete old records
                    self._c.execute(f'''
                        DELETE FROM {table}
                        WHERE {timestamp_col} < ?
                    ''', (cutoff_date,))
                    deleted_counts[table] = count
                    logger.info(f"Deleted {count} records from table: {table}.")
                else:
                    deleted_counts[table] = 0
                    logger.info(f"No records to delete from table: {table}.")
                    
                    
            # Log this cleanup action
            self._c.execute('''
                INSERT INTO admin_logs (ip_id, action)
                VALUES (?, ?)
            ''', (0, f"Records cleanup: Keeping {days_to_keep} days of records"))
            logger.info(f"Cleanup action logged: Keeping {days_to_keep} days of records.")
                            
                            
            self._conn.commit()
            return deleted_counts

        except sqlite3.Error as e:
            self._conn.rollback()
            logger.error(f"Error in _clear_records: {e}")
            return {}
        except Exception as e:
            self._conn.rollback()
            logger.error(f"Unexpected error in _clear_records: {e}")
            return {}