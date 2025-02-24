import whois
import sqlite3

# Create/connect to a database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Create a simple table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS ISP (
        ISP_ID INT,
        ISP_Name VARCHAR(100),
        Contact_Information VARCHAR(255)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS Location (
        Location_ID INTEGER PRIMARY KEY,
        Region VARCHAR(100),
        Country VARCHAR(100),
        City VARCHAR(100)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS IP_Traffic (
        IP_Address VARCHAR(45) PRIMARY KEY,
        Protocol_Type VARCHAR(10),
        User_Agent VARCHAR(255),
        Location_Location_ID INTEGER,
        ISP_ISP_ID INTEGER,
        FOREIGN KEY (Location_Location_ID) REFERENCES Location(Location_ID),
        FOREIGN KEY (ISP_ISP_ID) REFERENCES ISP(ISP_ID)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS Flagged_Metrics (
        Metric_ID INT PRIMARY KEY,
        Connection_Frequency VARCHAR(45),
        Failed_Login_Attempts INT,
        Data_Transfer_Volume INTEGER,
        Time_Of_Activity DATETIME,
        IP_Traffic_IP_Address VARCHAR(45),
        FOREIGN KEY (IP_Traffic_IP_Address) REFERENCES IP_Traffic(IP_Address)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS Whois (
        Whois_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Website TEXT,
        Registering_Company TEXT,
        Date_Created TEXT,
        Date_Expires TEXT,
        DNS_Servers TEXT
    )
''')

# Always commit changes
conn.commit()

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

def save_to_db(domain, whois_info):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Handle potential list/tuple values for dates
        creation_date = whois_info.creation_date[0] if isinstance(whois_info.creation_date, (list, tuple)) else whois_info.creation_date
        expiration_date = whois_info.expiration_date[0] if isinstance(whois_info.expiration_date, (list, tuple)) else whois_info.expiration_date
        
        cursor.execute('''
            INSERT INTO Whois (Website, Registering_Company, Date_Created, Date_Expires, DNS_Servers)
            VALUES (?, ?, ?, ?, ?)''',
            (domain, 
             whois_info.registrar, 
             str(creation_date), 
             str(expiration_date), 
             ','.join(whois_info.name_servers)))
        
        conn.commit()
        print(f"WHOIS info for {domain} inserted into database.")
    except Exception as e:
        print(f"Error saving to database: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    domain = "youtube.com"  # Removed https://
    whois_info = get_whois_info(domain)
    
    if whois_info:
        save_to_db(domain, whois_info)
        print(f"WHOIS info for {domain} saved to database.")
    else:
        print(f"Could not retrieve WHOIS info for {domain}.")

    input("PRESS ENTER TO EXIT")
