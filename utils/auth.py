import bcrypt
import re
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from config import Config

def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def validate_password(password):
    """Validate password strength"""
    errors = []
    
    if len(password) < Config.MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters long")
    
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r"\d", password):
        errors.append("Password must contain at least one number")
    
    if Config.REQUIRE_SPECIAL_CHARS and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("Password must contain at least one special character")
    
    return errors

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def create_token(user_id):
    """Create JWT access token"""
    return create_access_token(identity=str(user_id))  # Convert to string

def get_current_user_id():
    """Get current user ID from JWT token"""
    identity = get_jwt_identity()
    return int(identity) if identity else None  # Convert back to int