
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    THRESHOLD = int(os.getenv('THRESHOLD', 150))
    BURST_THRESHOLD = int(os.getenv('BURST_THRESHOLD', 300))
    LONG_TERM_THRESHOLD = int(os.getenv('LONG_TERM_THRESHOLD', 10000))
    PORT_SCAN_THRESHOLD = int(os.getenv('PORT_SCAN_THRESHOLD', 20))
    SYN_FLOOD_RATIO = float(os.getenv('SYN_FLOOD_RATIO', 0.8))
    ANOMALY_DETECTION_SAMPLES = int(os.getenv('ANOMALY_DETECTION_SAMPLES', 1000))

    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    DATABASE_URI = os.getenv('DATABASE_URI', 'database/database.db')
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '')
    DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')
    
    # Security
    SESSION_COOKIE_SECURE = not DEBUG
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Rate limiting
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"
    RATELIMIT_STORAGE_URI = "memory://"