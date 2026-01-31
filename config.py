import os
from datetime import timedelta

class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///wifi_ids.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    PACKET_CAPTURE_INTERFACE = 'Wi-Fi'
    PACKET_BUFFER_SIZE = 10000
    PACKET_TIMEOUT = 30
    
    MAX_SIGNATURE_DETECTIONS = 1000
    ANOMALY_THRESHOLD = 0.85
    AUTOENCODER_MODEL_PATH = 'models/autoencoder.h5'
    
    ALERT_LOG_PATH = 'logs/alerts/'
    FORENSIC_LOG_PATH = 'logs/forensics/'
    
    API_PORT = 5000
    API_HOST = '0.0.0.0'

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
