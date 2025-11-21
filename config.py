"""
Configuration management for OSINT Dashboard
Uses environment variables for sensitive data
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Base configuration class"""
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database
    DATABASE = os.getenv('DATABASE_URL', 'sqlite:///osint.db')
    DATABASE_FILE = DATABASE.replace('sqlite:///', '')
    
    # API Keys (from environment variables)
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
    GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '')
    GOOGLE_CSE_ID = os.getenv('GOOGLE_CSE_ID', '')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    CENSYS_API_ID = os.environ.get('CENSYS_API_ID')
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
    WHOISXML_API_KEY = os.environ.get('WHOISXML_API_KEY', '')
    
    # Authentication
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '')
    
    # Logging
    LOG_DIR = os.getenv('LOG_DIR', 'logs')
    LOG_FILE = os.path.join(LOG_DIR, 'osint_dashboard.log')
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # Security
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Rate limiting
    RATELIMIT_ENABLED = os.getenv('RATELIMIT_ENABLED', 'True').lower() == 'true'
    RATELIMIT_STORAGE_URL = os.getenv('RATELIMIT_STORAGE_URL', 'memory://')
    
    @staticmethod
    def get_config_dict():
        """Return configuration as dictionary (for backward compatibility)"""
        return {
            'shodan_api_key': Config.SHODAN_API_KEY,
            'google_api_key': Config.GOOGLE_API_KEY,
            'google_cse_id': Config.GOOGLE_CSE_ID,
            'virustotal_api_key': Config.VIRUSTOTAL_API_KEY,
            'censys_api_id': Config.CENSYS_API_ID,
            'gemini_api_key': Config.GEMINI_API_KEY,
            'whoisxml_api_key': Config.WHOISXML_API_KEY
        }


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True  # Requires HTTPS


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    DATABASE = 'sqlite:///:memory:'
    DATABASE_FILE = ':memory:'


# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get configuration based on FLASK_ENV"""
    env = os.getenv('FLASK_ENV', 'development')
    return config.get(env, config['default'])

