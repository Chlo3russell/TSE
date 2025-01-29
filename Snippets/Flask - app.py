from flask import Flask, request, jsonify # Flask: web framework, request: handles incoming http requests, jsonify: converts python dicts to json queries
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

app = Flask(__name__) # Initializes a flask web app instance

Base = declarative_base() # Creates a base class for defining database models

### Class for attack logs - represents a table in the MySQL database to store attack information
class AttackLog(Base):
    __tablename__ = 'attack_logs'
    id = Column(Integer, primary_key=True) # Unique attack identifier
    ip_address = Column(String(255)) # Attacker's IP
    attack_type = Column(String(255)) # Attack type 
    timestamp = Column(DateTime, default=datetime.utcnow) # Date & Time of attack (utcnow is deprecated so will need modifying)
    attack_data = Column(String(500)) # Additional information

### Connection to the database
DATABASE_URI = 'mysql+pymysql://username:password@localhost:3306/ddos_detection' # Connection string to the MySQL database
engine = create_engine(DATABASE_URI) # Connects the application to the MySQL database
Session = sessionmaker(bind=engine) # Creates a session to interact with the database/ execute queries
session = Session()

Base.metadata.create_all(engine) # Ensures the attack log table is created if it doesn't already exist

### Logging an attack
@app.route('/monitor', methods=['POST']) # Accepts JSON data to log an attack
def monitor_attack():
    ## Check if all required fields are provided
    ip_address = request.json.get('ip_address')
    attack_type = request.json.get('attack_type')
    attack_data = request.json.get('attack_data')
    ## Adds a new record to the database & commits it
    if ip_address and attack_type and attack_data:
        attack_log = AttackLog(ip_address=ip_address, attack_type=attack_type, attack_data=attack_data)
        session.add(attack_log)
        session.commit()
    ## Success or Error message depending on if the data is able to be committed to the DB
        return jsonify({"message": "Attack logged successfully!"}), 200 
    else:
        return jsonify({"error": "Invalid data"}), 400

### Retrieving attack logs
@app.route('/get_logs', methods=['GET']) # Fetches all stored attack logs from the database
def get_logs():
    logs = session.query(AttackLog).all()
    log_list = [{"ip_address": log.ip_address, "attack_type": log.attack_type, "timestamp": log.timestamp, "attack_data": log.attack_data} for log in logs]
    
    return jsonify(log_list), 200 # Converts the logs into JSON format

### Running application on local host
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
