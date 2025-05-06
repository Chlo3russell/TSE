'''
run.py - file that runs both the fake website and the traffic monitor in separate threads to populate the DB
'''
import threading
import os
import time
import subprocess
import platform
#from Attacks import synack, httpflood, UDPFlood  # Import your attack classes

def run_flask():
    os.system("python targetWebsite/targetWebsite.py")  

def run_monitoring():
    os.system("python trafficMonitor.py")  

def run_dashboard():
    os.system("python dashboard.py")  

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
# time.sleep(20)
# threading.Thread(target=synack.syn_flood(packet_count=10000)).start()

