import threading
import os

def run_flask():
    os.system("python targetWebsite/targetWebsite.py")  # Runs your fake website

def run_monitoring():
    os.system("python trafficMonitor.py")  # Runs the traffic monitor

threading.Thread(target=run_flask).start()
threading.Thread(target=run_monitoring).start()
