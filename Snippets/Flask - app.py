from flask import Flask, request, jsonify
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)

key = Fernet.generate_key()  # Generate a new key; save it securely for production use!
cipher = Fernet(key)

Base = declarative_base()

class AttackLog(Base):
    __tablename__ = 'attack_logs'
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(255))
    attack_type = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow)
    attack_data = Column(String(500))

DATABASE_URI = 'mysql+pymysql://username:password@localhost:3306/ddos_detection'
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
session = Session()

Base.metadata.create_all(engine)

@app.route('/monitor', methods=['POST'])
def monitor_attack():
    ip_address = request.json.get('ip_address')
    attack_type = request.json.get('attack_type')
    attack_data = request.json.get('attack_data')

    if ip_address and attack_type and attack_data:
        encrypted_ip = cipher.encrypt(ip_address.encode()).decode()  # Encrypt IP address
        encrypted_attack_type = cipher.encrypt(attack_type.encode()).decode()  # Encrypt attack type
        encrypted_attack_data = cipher.encrypt(attack_data.encode()).decode()  # Encrypt attack data

        # Log attack data into the database
        attack_log = AttackLog(ip_address=encrypted_ip, attack_type=encrypted_attack_type, attack_data=encrypted_attack_data)
        session.add(attack_log)
        session.commit()

        return jsonify({"message": "Attack logged successfully!"}), 200
    else:
        return jsonify({"error": "Invalid data"}), 400

@app.route('/get_logs', methods=['GET'])
def get_logs():
    logs = session.query(AttackLog).all()
    log_list = []

    for log in logs:
        # Decrypt the data when retrieving from the database
        decrypted_ip = cipher.decrypt(log.ip_address.encode()).decode()  # Decrypt IP address
        decrypted_attack_type = cipher.decrypt(log.attack_type.encode()).decode()  # Decrypt attack type
        decrypted_attack_data = cipher.decrypt(log.attack_data.encode()).decode()  # Decrypt attack data

        log_list.append({
            "ip_address": decrypted_ip,
            "attack_type": decrypted_attack_type,
            "timestamp": log.timestamp,
            "attack_data": decrypted_attack_data
        })

    return jsonify(log_list), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
