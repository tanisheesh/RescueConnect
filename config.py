import os
from datetime import timedelta

class Config:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-key-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # Database
    DATABASE_PATH = 'database.db'
    
    # Application
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    HOST = os.environ.get('FLASK_HOST', '0.0.0.0')  # Changed default for Render
    PORT = int(os.environ.get('FLASK_PORT', 5000))
    
    # Password validation
    MIN_PASSWORD_LENGTH = 8
    REQUIRE_SPECIAL_CHARS = True
    
    # File uploads (for skill verification documents) - Now using links
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Keep for future use
    UPLOAD_FOLDER = 'uploads'  # Keep for future use
    ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'}  # Keep for future use