import whois
import sqlite3
from datetime import datetime, timedelta
from scapy.all import IP, ICMP, sr1

# Create a simple table
class Database:
    def __init__(self):
        # Protected methods
        self._conn = sqlite3.connect("database/database.db")
        self._conn.row_factory = sqlite3.Row
        self._conn.execute('PRAGMA foreign_keys = ON')
        self._c = self._conn.cursor() 

        # Call private method to setup db & create indexes
        self.__setup_db()
        self.__create_indexes()
    
    def __setup_db(self):
        
        #Creates all databases if they don't exist.
        
        # Create IPs table - reason: can add more ip metadata without changing other tables
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

        # Create Rate limiting events table - reason: good for tracking actions
        self._c.execute('''
            CREATE TABLE IF NOT EXISTS rate_limit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                action TEXT NOT NULL,
                config TEXT
            )
        ''')

        # Create Admin events table - reason: good for auditing 
        self._c.execute('''
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_id INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                action TEXT NOT NULL,
                FOREIGN KEY (ip_id) REFERENCES ip_list(id) ON DELETE CASCADE
            )
        ''')

        # Create flagged metrics table - for data visualization/ display purposes
        # Metric type i.e "Syn Flood", "Failed Login", "High data transfer", "Ping Attack" etc - these can be checked before parsed by creating another function to validate if the metric is valid/ useful/ something we're looking for 
        # Value i.e number of syn packets, login attempts, data transfer volume
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

        # Create Location table - reason: if you wanted to further add the the ip data 
        self._c.execute('''
            CREATE TABLE IF NOT EXISTS location (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                country VARCHAR(100),
                city VARCHAR(100),
                region VARCHAR(100)
                )
        ''')
    
        # Create ISP table - reason: if you wanted to further add the the ip data 
        self._c.execute('''
            CREATE TABLE IF NOT EXISTS isp (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                isp_name VARCHAR(100),
                contact_information VARCHAR(255)
            )
        ''')
    
### INDEX
    def __create_indexes(self):
        
        #Create database indexes for some tables for performance.
        
        try:
            # Index for frequently queried columns
            self._c.execute('CREATE INDEX IF NOT EXISTS index_ip_address ON ip_list(ip_address)')
            self._c.execute('CREATE INDEX IF NOT EXISTS index_blocked_ips_id ON blocked_ips(ip_id)')
            self._c.execute('CREATE INDEX IF NOT EXISTS index_traffic_logs_timestamp ON traffic_logs(timestamp)')
            self._c.execute('CREATE INDEX IF NOT EXISTS index_admin_logs_timestamp ON admin_logs(timestamp)')
            self._c.execute('CREATE INDEX IF NOT EXISTS index_flagged_metrics_time ON flagged_metrics(time_of_activity)')
            
            self._conn.commit()
            
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
            print(f"Error getting whois information: {e}")
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
            print(f"Error getting scapy information: {e}")
            return None

### SETTER FUNCTIONS
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
                return existing_location[0]
            
            # Insert new location
            self._c.execute('''
                INSERT INTO location (country, city, region)
                VALUES (?, ?, ?)
            ''', (country, city, region))
            
            self._conn.commit()
            return self._c.lastrowid
        
        except sqlite3.Error as e:
            print(f"Error adding location: {e}")
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
            # Check if ISP exists
            self._c.execute('''
                SELECT id FROM isp 
                WHERE isp_name = ?
            ''', (isp_name,))
            
            existing_isp = self._c.fetchone()
            if existing_isp:
                return existing_isp[0]
            
            # Insert new ISP
            self._c.execute('''
                INSERT INTO isp (isp_name, contact_information)
                VALUES (?, ?)
            ''', (isp_name, contact_information))
            
            self._conn.commit()
            return self._c.lastrowid
        
        except sqlite3.Error as e:
            print(f"Error adding ISP: {e}")
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
                print(f"IP {ip_id} is already blocked")
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
            return True
            
        except sqlite3.Error as e:
            print(f"Error blocking IP: {e}")
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
                print("Invalid input parameters")
                return False
                
            # Insert the admin action
            self._c.execute('''
                INSERT INTO admin_logs (ip_id, action)
                VALUES (?, ?)
            ''', (ip_id, action))
            
            self._conn.commit()
            return True
            
        except sqlite3.Error as e:
            print(f"Error logging admin action: {e}")
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
                print("Invalid input parameters")
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
            ''', (0, f"Rate Limit Change: {action}"))
            
            self._conn.commit()
            return True
            
        except sqlite3.Error as e:
            print(f"Error logging rate limit action: {e}")
            self._conn.rollback()
            return False

    # Add an ip to the central ip table
    def _add_ip(self, ip_address, location_id=None, isp_id=None):
        # Add IP with just address
        #ip_id = db._add_ip('192.168.1.1')

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
                return existing_ip[0]
            
            # Insert new IP
            self._c.execute('''
                INSERT INTO ip_list (ip_address, location_id, isp_id)
                VALUES (?, ?, ?)
            ''', (ip_address, location_id, isp_id))
            
            self._conn.commit()
            
            # Log the action in admin_logs
            self._c.execute('''
                INSERT INTO admin_logs (ip_id, action)
                VALUES (?, ?)
            ''', (self._c.lastrowid, f"IP Added: {ip_address}"))
            
            self._conn.commit()
            return self._c.lastrowid
        
        except sqlite3.Error as e:
            print(f"Error adding IP: {e}")
            self._conn.rollback()
            return None

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
            return True
        except sqlite3.Error as e:
            print(f"Error flagging suspicious metric: {e}")
            return False

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
                else:
                    self._c.execute("""
                        SELECT bi.*, il.ip_address 
                        FROM blocked_ips AS bi
                        JOIN ip_list AS il ON bi.ip_id = il.id
                    """)
                return self._c.fetchall()
            except sqlite3.Error as e:
                #error msg
                print(f"Error fetching blocked IPs: {e}")

    # Query to get traffic logs, optionally filtered by a start and end timestamp
    def _get_traffic_logs(self, start_time=None, end_time=None):
            try:
                if start_time and end_time:
                    self._c.execute("""
                        SELECT * FROM traffic_logs
                        WHERE timestamp BETWEEN ? AND ?
                    """, (start_time, end_time))
                else:
                    self._c.execute("SELECT * FROM traffic_logs")
                return self._c.fetchall()
            except sqlite3.Error as e:
                #error msg
                print(f"Error fetching traffic logs: {e}")

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
                    return None

                self._c.execute(query, params)
                row = self._c.fetchone()

                if row:
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
                return None

        except sqlite3.Error as e:
            print(f"Error retrieving IP information: {e}")
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

            return [{
                'timestamp': row[0],
                'action': row[1],
                'config': row[2]
            } for row in results
            ]
        except Exception as e:
            print(f"Error retrieving rate limit actions: {e}")
            return []

    # Query to get a records of the admins actions/ changes they've made 
    def _get_admin_actions(self, start_date=None, end_date=None, ip_id=None, limit=100) -> list:
        '''
        Get all admin actions (limited to 100)\n
        actions = db._get_admin_actions()

        Get actions for a specific IP\n
        actions = db._get_admin_actions(ip_id='123')

        Get actions within a date range\n
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

            return [{
                'id': row['id'],
                'ip_id': row['ip_id'],
                'ip_address': row['ip_address'],
                'timestamp': row['timestamp'],
                'action': row['action']
            } for row in rows]

        except sqlite3.Error as e:
            print(f"Error retrieving admin actions: {e}")
            return []

    def get_whois_info(domain):
        try:
            # Remove 'https://' from the domain
            domain = domain.replace('https://', '').replace('http://', '')
            w = whois.whois(domain)
            print(f"WHOIS data retrieved: {w}")
            return w
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

### DELETE FUNCTION

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

            # Update or insert cleanup configuration
            self._c.execute('''
                INSERT OR REPLACE INTO cleanup_config (id, days_to_keep, last_cleanup)
                VALUES (1, ?, CURRENT_TIMESTAMP)
            ''', (days_to_keep,))

            # Define tables and their timestamp columns
            tables = {
                'traffic_logs': 'timestamp',
                'rate_limit_logs': 'timestamp',
                'admin_logs': 'timestamp',
                'flagged_metrics': 'time_of_activity',
                'blocked_ips': 'unblock_time'
            }

            # Create cleanup triggers
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
                else:
                    deleted_counts[table] = 0
                    
            # Log cleanup action
            self._c.execute('''
                INSERT INTO admin_logs (ip_id, action)
                VALUES (?, ?)
            ''', (0, f"Records cleanup: Keeping {days_to_keep} days of records"))

            self._conn.commit()
            return deleted_counts

        except sqlite3.Error as e:
            self._conn.rollback()
            print(f"Error in _clear_records: {e}")
            return {}
        except Exception as e:
            self._conn.rollback()
            print(f"Unexpected error in _clear_records: {e}")
            return {}