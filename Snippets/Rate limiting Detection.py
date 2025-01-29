from collections import defaultdict
from time import time

ip_requests = defaultdict(list)

@app.before_request
def detect_suspicious_activity():
    ip = request.remote_addr
    current_time = time()
    ip_requests[ip].append(current_time)
    
    ip_requests[ip] = [t for t in ip_requests[ip] if current_time - t < 10]

    if len(ip_requests[ip]) > 100:
        log_attack(ip, "Rate Limiting", "More than 100 requests in the last 10 seconds")

def log_attack(ip_address, attack_type, attack_data):
    attack_log = AttackLog(ip_address=ip_address, attack_type=attack_type, attack_data=attack_data)
    session.add(attack_log)
    session.commit()
