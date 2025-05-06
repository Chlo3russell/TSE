'''
run.py - file that runs both the fake website and the traffic monitor in separate threads to populate the DB
'''
import threading
import os
import time
import subprocess
from attacks import synack, httpflood, UDPFlood
from targetWebsite import targetWebsite

def run_flask():
    os.system("python targetWebsite/targetWebsite.py")  

def run_monitoring():
    os.system("python trafficMonitor.py")  

def run_dashboard():
    os.system("python dashboard.py")  

def run_attack():
    syn = synack.SYNFlood()
    syn.startAttack()

'''
def run_node_server():
    # Get the directory containing login templates
    login_dir = os.path.join(os.path.dirname(__file__), 'templates', 'login')
    print("Login directory exists:", os.path.exists(login_dir))
    # Use node command on Windows, nodejs on some Linux systems
    node_cmd = 'node' if os.name == 'nt' else 'nodejs'
    print("Login directory exists:", os.path.exists(login_dir))
    try:
        # Run npm install first to ensure dependencies
        subprocess.run(['npm', 'install'], cwd=login_dir, check=True)
        # Then start the server
        subprocess.run([node_cmd, 'server.js'], cwd=login_dir)
    except subprocess.CalledProcessError as e:
        print(f"Failed to start Node.js server: {e}")
    except FileNotFoundError:
        print("Node.js is not installed or not in PATH. Please install Node.js first.")
'''
        
# Start all services
threading.Thread(target=run_dashboard).start()
threading.Thread(target=run_flask).start()
threading.Thread(target=run_monitoring).start()
#threading.Thread(target=run_node_server).start()
time.sleep(20)
threading.Thread(target=run_attack).start()

