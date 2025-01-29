### Rate limiting to detect suspicious activity 
from collections import defaultdict
from time import time

ip_requests = defaultdict(list) # Stores IP addresses with timestamps of their requests

# Before request hook for attack detection
@app.before_request # Runs this function before each request
def detect_suspicious_activity():
    ## Tracks request timestamps for each IP
    ip = request.remote_addr
    current_time = time()
    ip_requests[ip].append(current_time)
    
    ip_requests[ip] = [t for t in ip_requests[ip] if current_time - t < 10] # Removes timestamps older than 10 seconds

    ## Detects attacks if an IP sends more than 100 requests in 10 seconds
    if len(ip_requests[ip]) > 100:
        log_attack(ip, "Rate Limiting", "More than 100 requests in the last 10 seconds") # Logs attack when IP is flagged

### Logging detected attacks - creates attack entry and saves it to the database when suspicious activity is detected
def log_attack(ip_address, attack_type, attack_data):
    attack_log = AttackLog(ip_address=ip_address, attack_type=attack_type, attack_data=attack_data)
    session.add(attack_log)
    session.commit()
