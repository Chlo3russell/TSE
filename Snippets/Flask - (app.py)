from flask import Flask, request, jsonify
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)

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
        attack_log = AttackLog(ip_address=ip_address, attack_type=attack_type, attack_data=attack_data)
        session.add(attack_log)
        session.commit()

        return jsonify({"message": "Attack logged successfully!"}), 200
    else:
        return jsonify({"error": "Invalid data"}), 400

@app.route('/get_logs', methods=['GET'])
def get_logs():
    logs = session.query(AttackLog).all()
    log_list = [{"ip_address": log.ip_address, "attack_type": log.attack_type,
                 "timestamp": log.timestamp, "attack_data": log.attack_data} for log in logs]
    
    return jsonify(log_list), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
