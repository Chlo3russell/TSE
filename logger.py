import logging
from logging.handlers import RotatingFileHandler
import logging.handlers
import os
from datetime import datetime, timedelta
import re

# Constants - log directory and log file that all logs across all files will go into
LOG_DIRECTORY = "logs"
LOG_FILE = os.path.join(LOG_DIRECTORY, "app.log")


def setup_logger(name=__name__):
    '''
    Setter function to configure and ensure backups for the shared log file.
    '''
    # Creates the log directory if it doesn't exists yet
    if not os.path.exists(LOG_DIRECTORY):
        os.makedirs(LOG_DIRECTORY)
    
    # Creates a new logging instance depending on the file name
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Standard format that the log messages will be in
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Handling multiple log files - when a log file reaches a certain limit it will create backups (max of 3 of size 1MB)
    if not logger.handlers:
        handler = RotatingFileHandler('logs/app.log', maxBytes=1000000, backupCount=3, encoding='utf-8')
        handler.setLevel(logging.INFO)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger

def format_log_data(log_entry):
    '''
    Helper function to format the log entry into structured, user readable data using regular expressions.
    '''
    pattern = r"^(?P<timestamp>[\d\-]+\s[\d:,]+) - (?P<logger>[^ ]+) - (?P<level>[A-Z]+) - (?P<message>.*)"
    match = re.match(pattern, log_entry)
    if match:
        timestamp = datetime.strptime(match['timestamp'], '%Y-%m-%d %H:%M:%S,%f')
        return {
            'timestamp' : timestamp,
            'logger' : match['logger'],
            'level' : match['level'],
            'message' : match['message'].strip()
        }
    return None

def get_all():
    '''
    Retrieve all logs from the log file, call the formatter helper function and return structured log data.
    '''
    logs = []
    
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, 'r') as lf:
        for log in lf:
            log_data = format_log_data(log)
            if log_data:
                logs.append(log_data)
    lf.close()
    return logs