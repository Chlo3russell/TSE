import threading
import os
import time
import subprocess
import sys
from config import Config
import logging
from logs.logger import setup_logger

logger = setup_logger(__name__)

def run_command(command, wait=False):
    """Run a command with proper Windows handling"""
    try:
        # On Windows, we need to use shell=True for proper PATH resolution
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        if wait:
            process.wait()
        return process
    except Exception as e:
        logger.error(f"Failed to run command '{command}': {str(e)}")
        return None

def run_flask():
    """Run the target website"""
    cmd = f"{sys.executable} targetWebsite/targetWebsite.py"
    logger.info(f"Starting Flask: {cmd}")
    return run_command(cmd)

def run_monitoring():
    """Run the traffic monitor"""
    cmd = f"{sys.executable} trafficMonitor.py"
    logger.info(f"Starting traffic monitor: {cmd}")
    return run_command(cmd)

def run_attack():
    """Run attack simulation"""
    if not Config.DEBUG:
        logger.warning("Attack simulation disabled in production mode")
        return None
    
    cmd = f"{sys.executable} attacks/synack.py"
    logger.info(f"Starting attack simulation: {cmd}")
    return run_command(cmd)

def run_dashboard():
    """Run the dashboard"""
    if Config.DEBUG:
        cmd = f"{sys.executable} dashboard.py"
    else:
        cmd = f"gunicorn -w 4 -b :5001 dashboard:app"
    logger.info(f"Starting dashboard: {cmd}")
    return run_command(cmd)

def check_processes(processes):
    """Check if any processes have terminated unexpectedly"""
    for name, process in processes.items():
        if process and process.poll() is not None:
            logger.error(f"{name} process terminated with code {process.returncode}")
            # Optionally restart the process here

if __name__ == "__main__":
    # Start all components
    processes = {
        'flask': run_flask(),
        'monitor': run_monitoring(),
        'dashboard': run_dashboard()
    }
    
    # Start attack after a short delay to ensure systems are up
    time.sleep(5)
    processes['attack'] = run_attack()
    
    # Monitor processes
    try:
        while True:
            check_processes(processes)
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("Shutting down all components")
        for name, process in processes.items():
            if process:
                try:
                    process.terminate()
                except:
                    pass
        sys.exit(0)


print("Current directory:", os.getcwd())
print("Python executable:", sys.executable)
print("Files in directory:", os.listdir('.'))