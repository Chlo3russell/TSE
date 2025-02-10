import socket
import time
from collections import defaultdict

# Define firewall parameters
MAX_REQUESTS_PER_IP = 100  # Maximum number of requests per IP in a given time window
TIME_WINDOW = 10  # Time window in seconds
BLOCK_TIME = 60  # Time to block the IP (in seconds) once it exceeds the threshold

# Dictionary to store IP request counts and timestamps
request_counts = defaultdict(list)  # IP -> [list of request timestamps]
blocked_ips = defaultdict(float)  # IP -> timestamp when it will be unblocked

# Function to check and update request counts for each IP
def check_rate_limit(client_ip):
    current_time = time.time()
    
    # Remove outdated timestamps (older than TIME_WINDOW seconds)
    request_counts[client_ip] = [timestamp for timestamp in request_counts[client_ip] if current_time - timestamp <= TIME_WINDOW]

    # Check if this IP has exceeded the max requests within the time window
    if len(request_counts[client_ip]) >= MAX_REQUESTS_PER_IP:
        # Block IP if it exceeded the limit
        blocked_ips[client_ip] = current_time + BLOCK_TIME
        print(f"Blocking IP {client_ip} due to excessive requests.")
        return False

    # Otherwise, accept the connection and update the request count
    request_counts[client_ip].append(current_time)
    return True

# Function to block an IP
def is_blocked(client_ip):
    current_time = time.time()
    if client_ip in blocked_ips:
        # Check if the block time has expired
        if current_time < blocked_ips[client_ip]:
            return True  # IP is still blocked
        else:
            del blocked_ips[client_ip]  # Remove the IP from the blocked list after the block time has passed
    return False

# Set up a server socket to listen for incoming connections
server_ip = "0.0.0.0"  # Listen on all interfaces
server_port = 9999  # Arbitrary port for listening

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_ip, server_port))
server_socket.listen(5)
print(f"Listening for connections on {server_ip}:{server_port}...")

while True:
    try:
        # Accept incoming connections
        client_socket, client_address = server_socket.accept()
        client_ip, client_port = client_address
        
        # Check if the IP is blocked
        if is_blocked(client_ip):
            client_socket.send(b"Your IP is temporarily blocked due to excessive requests.")
            print(f"Connection from {client_ip} rejected: IP blocked.")
            client_socket.close()
            continue
        
        # Check if the IP exceeds rate limits
        if not check_rate_limit(client_ip):
            client_socket.send(b"Rate limit exceeded. Your IP has been blocked.")
            print(f"Connection from {client_ip} rejected: Rate limit exceeded.")
            client_socket.close()
            continue
        
        # If not blocked, allow the connection
        print(f"Connection from {client_ip}:{client_port} accepted.")
        client_socket.send(b"Connection accepted")
        client_socket.close()

    except Exception as e:
        print(f"Error: {e}")
