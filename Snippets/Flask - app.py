from flask import Flask, request, jsonify
from datetime import datetime
import sqlite3
from cryptography.fernet import Fernet

app = Flask(__name__)

key = Fernet.generate_key()
cipher = Fernet(key)

def init_db():
    conn = sqlite3.connect('ip_traffic.db')
    c = conn.cursor()
    
    # Create Location table
    c.execute('''
        CREATE TABLE IF NOT EXISTS Location (
            Location_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Country VARCHAR(100),
            City VARCHAR(100),
            Region VARCHAR(100)
        )
    ''')
    
    # Create ISP table
    c.execute('''
        CREATE TABLE IF NOT EXISTS ISP (
            ISP_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            ISP_Name VARCHAR(100),
            Contact_Information VARCHAR(255)
        )
    ''')
    
    # Create IP_Traffic table
    c.execute('''
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
    c.execute('''
        CREATE TABLE IF NOT EXISTS Flagged_Metrics (
            Metric_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Connection_Frequency VARCHAR(45),
            Failed_Login_Attempts INTEGER,
            Data_Transfer_Volume BIGINT,
            Time_of_Activity DATETIME DEFAULT CURRENT_TIMESTAMP,
            IP_Traffic_IP_Address VARCHAR(45),
            FOREIGN KEY (IP_Traffic_IP_Address) REFERENCES IP_Traffic(IP_Address)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('ip_traffic.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/add_location', methods=['POST'])
def add_location():
    data = request.json
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
            INSERT INTO Location (Country, City, Region)
            VALUES (?, ?, ?)
        ''', (
            cipher.encrypt(data['country'].encode()).decode(),
            cipher.encrypt(data['city'].encode()).decode(),
            cipher.encrypt(data['region'].encode()).decode()
        ))
        
        location_id = cur.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Location added successfully", "location_id": location_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/add_isp', methods=['POST'])
def add_isp():
    data = request.json
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
            INSERT INTO ISP (ISP_Name, Contact_Information)
            VALUES (?, ?)
        ''', (
            cipher.encrypt(data['isp_name'].encode()).decode(),
            cipher.encrypt(data['contact_information'].encode()).decode()
        ))
        
        isp_id = cur.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({"message": "ISP added successfully", "isp_id": isp_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/monitor_traffic', methods=['POST'])
def monitor_traffic():
    data = request.json
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Insert IP traffic data
        cur.execute('''
            INSERT INTO IP_Traffic (IP_Address, Protocol_Type, User_Agent, Location_Location_ID, ISP_ISP_ID)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            cipher.encrypt(data['ip_address'].encode()).decode(),
            cipher.encrypt(data['protocol_type'].encode()).decode(),
            cipher.encrypt(data['user_agent'].encode()).decode(),
            data['location_id'],
            data['isp_id']
        ))
        
        # Insert flagged metrics if suspicious activity detected
        if data.get('flagged_metrics'):
            cur.execute('''
                INSERT INTO Flagged_Metrics (
                    Connection_Frequency, Failed_Login_Attempts, 
                    Data_Transfer_Volume, IP_Traffic_IP_Address
                )
                VALUES (?, ?, ?, ?)
            ''', (
                cipher.encrypt(data['flagged_metrics']['connection_frequency'].encode()).decode(),
                data['flagged_metrics']['failed_login_attempts'],
                data['flagged_metrics']['data_transfer_volume'],
                cipher.encrypt(data['ip_address'].encode()).decode()
            ))
        
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Traffic data logged successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_traffic_data', methods=['GET'])
def get_traffic_data():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
            SELECT t.*, f.*, l.*, i.*
            FROM IP_Traffic t
            LEFT JOIN Flagged_Metrics f ON t.IP_Address = f.IP_Traffic_IP_Address
            LEFT JOIN Location l ON t.Location_Location_ID = l.Location_ID
            LEFT JOIN ISP i ON t.ISP_ISP_ID = i.ISP_ID
        ''')
        
        rows = cur.fetchall()
        traffic_data = []
        
        for row in rows:
            decrypted_data = {
                "ip_address": cipher.decrypt(row['IP_Address'].encode()).decode(),
                "protocol_type": cipher.decrypt(row['Protocol_Type'].encode()).decode(),
                "user_agent": cipher.decrypt(row['User_Agent'].encode()).decode(),
                "location": {
                    "country": cipher.decrypt(row['Country'].encode()).decode(),
                    "city": cipher.decrypt(row['City'].encode()).decode(),
                    "region": cipher.decrypt(row['Region'].encode()).decode()
                },
                "isp": {
                    "name": cipher.decrypt(row['ISP_Name'].encode()).decode(),
                    "contact": cipher.decrypt(row['Contact_Information'].encode()).decode()
                }
            }
            
            if row['Metric_ID']:
                decrypted_data["flagged_metrics"] = {
                    "connection_frequency": cipher.decrypt(row['Connection_Frequency'].encode()).decode(),
                    "failed_login_attempts": row['Failed_Login_Attempts'],
                    "data_transfer_volume": row['Data_Transfer_Volume'],
                    "time_of_activity": row['Time_of_Activity']
                }
            
            traffic_data.append(decrypted_data)
        
        conn.close()
        return jsonify(traffic_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)