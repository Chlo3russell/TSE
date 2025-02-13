import whois
import sqlite3

# Create/connect to a database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Create ISP table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS ISP (
        ISP_ID INT,
        ISP_Name VARCHAR(100),
        Contact_Information VARCHAR(255)
    )
''')

# Create Location table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS Location (
        Location_ID INTEGER PRIMARY KEY,
        Region VARCHAR(100),
        Country VARCHAR(100),
        City VARCHAR(100)
    )
''')

# Create IP_Traffic table
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

# Create Flagged_Metrics table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS Flagged_Metrics (
        Metric_ID INT PRIMARY KEY,
        Connection_Frequency VARCHAR(45),
        Failed_Login_Attempts INT,
        Data_Transfer_Volume BIGINT(100),
        Time_Of_Activity DATETIME,
        IP_Traffic_IP_Address VARCHAR(45),
        FOREIGN KEY (IP_Traffic_IP_Address) REFERENCES IP_Traffic(IP_Address)
    )
''')

#create a whois table
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

conn.commit()

#whois function
def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        print(f"WHOIS data retrieved: {w}")
        return w
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

#saving data
def save_to_db(domain, whois_info):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    #inserting data
    cursor.execute('''
        INSERT INTO Whois (Website, Registering_Company, Date_Created, Date_Expires, DNS)
        VALUES (?, ?, ?, ?, ?)''',
                   (domain, whois_info.registrar, whois_info.creation_date, whois_info.expiration_date, ','.join(whois_info.name_servers)))
    
    conn.commit()
    print(f"WHOIS info for {domain} inserted into database.")
    conn.close()

#main
if __name__ == "__main__":
    domain = "https://youtube.com"
    whois_info = get_whois_info(domain)
    
    if whois_info:
        save_to_db(domain, whois_info)
        print(f"WHOIS info for {domain} saved to database.")
    else:
        print(f"Could not retrieve WHOIS info for {domain}.")

    input("ENTER TO EXIT")
