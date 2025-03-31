import threading
import os

# This script runs two threads: one for the Flask web application 
# and another for the traffic monitoring script.

# This just reduces the amount of scrips we have to run manually.


def run_flask():
    os.system("python targetWebsite/targetWebsite.py") 

def run_monitoring():
    os.system("python trafficMonitor.py")  

threading.Thread(target=run_flask).start()
threading.Thread(target=run_monitoring).start()
