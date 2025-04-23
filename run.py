'''
run.py - file that runs both the fake website and the traffic monitor in separate threads to populate the DB
'''
import threading
import os

def run_flask():
    os.system("python targetWebsite/targetWebsite.py")  # Runs your fake website

def run_monitoring():
    os.system("python trafficMonitor.py")  # Runs the traffic monitor

def run_attack():
    os.system("python attacks/synack.py")

def run_dashboard():
    os.system("python dashboard.py")  # Runs the dashboard

threading.Thread(target=run_flask).start()
threading.Thread(target=run_monitoring).start()
#threading.Thread(target=run_attack).start()
threading.Thread(target=run_dashboard).start()