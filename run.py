'''
run.py - file that runs both the fake website and the traffic monitor in separate threads to populate the DB
'''
import threading
import os
import subprocess
from attacks import synack, httpflood, UDPFlood
from targetWebsite import targetWebsite
import platform

def run_flask():
    os.system("python targetWebsite/targetWebsite.py")  

def run_monitoring():
    os.system("python trafficMonitor.py")  

def run_dashboard():
    os.system("python dashboard.py")  

def run_attack(attack):
    if attack == "syn":
        syn = synack.SYNFlood()
        syn.startAttack()
    elif attack == "udp":
        udp = UDPFlood.UDPFloodAttack(target_ip="127.0.0.1", target_port=80)
        udp.start()
    elif attack == "http":
        http = httpflood.HTTPFlood()
        http.startAttack()

def run_node_server():
    # Get the directory containing login templates
    login_dir = os.path.join(os.path.dirname(__file__), 'templates', 'login')
    
    # Use node command on Windows, nodejs on some Linux systems
    node_cmd = 'node' if platform.system() == 'Windows' else 'nodejs'
    
    try:
        # Run npm install first to ensure dependencies
        subprocess.run(['npm', 'install'], cwd=login_dir, check=True)
        
        # Then start the server
        subprocess.run([node_cmd, 'server.js'], cwd=login_dir)
    except subprocess.CalledProcessError as e:
        print(f"Failed to start Node.js server: {e}")
    except FileNotFoundError:
        print("Node.js is not installed or not in PATH. Please install Node.js first.")

# Start all services
threading.Thread(target=run_dashboard).start()
threading.Thread(target=run_flask).start()
threading.Thread(target=run_monitoring).start()
threading.Thread(target=run_node_server).start()



