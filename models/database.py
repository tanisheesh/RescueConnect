import sqlite3
import bcrypt
from datetime import datetime
from config import Config

class Database:
    def __init__(self):
        self.db_path = Config.DATABASE_PATH
        self.init_db()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Users table - Updated with state and district
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                phone TEXT,
                address TEXT,
                state TEXT,
                district TEXT,
                user_type TEXT NOT NULL CHECK(user_type IN ('volunteer', 'organization', 'admin')),
                is_verified BOOLEAN DEFAULT FALSE,
                verification_status TEXT DEFAULT 'pending' CHECK(verification_status IN ('pending', 'approved', 'rejected')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Organization details table - Additional info for organizations
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS organization_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                organization_type TEXT NOT NULL,
                registration_number TEXT,
                website TEXT,
                description TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Categories table - New table for disaster/skill categories
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                type TEXT NOT NULL CHECK(type IN ('skill', 'disaster')),
                is_approved BOOLEAN DEFAULT FALSE,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Skills table - Updated with approval system
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS skills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                category_id INTEGER NOT NULL,
                description TEXT,
                is_approved BOOLEAN DEFAULT FALSE,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # User skills table - Updated proficiency levels
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_skills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                skill_id INTEGER NOT NULL,
                proficiency_level TEXT CHECK(proficiency_level IN ('beginner', 'intermediate', 'expert')),
                is_verified BOOLEAN DEFAULT FALSE,
                verification_link TEXT,
                verification_notes TEXT,
                verified_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (skill_id) REFERENCES skills (id) ON DELETE CASCADE,
                UNIQUE(user_id, skill_id)
            )
        ''')
        
        # Emergency requests table - Updated with state/district and approval
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emergency_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                organization_id INTEGER NOT NULL,
                category_id INTEGER NOT NULL,
                state TEXT NOT NULL,
                district TEXT NOT NULL,
                priority_level TEXT NOT NULL CHECK(priority_level IN ('low', 'medium', 'high', 'critical')),
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'active', 'completed', 'cancelled', 'rejected')),
                volunteers_needed INTEGER DEFAULT 1,
                volunteers_assigned INTEGER DEFAULT 0,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                is_approved BOOLEAN DEFAULT FALSE,
                approved_by INTEGER,
                approved_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (organization_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE CASCADE,
                FOREIGN KEY (approved_by) REFERENCES users (id)
            )
        ''')
        
        # Required skills for emergency requests
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS request_skills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                skill_id INTEGER NOT NULL,
                required_proficiency TEXT CHECK(required_proficiency IN ('beginner', 'intermediate', 'expert')),
                FOREIGN KEY (request_id) REFERENCES emergency_requests (id) ON DELETE CASCADE,
                FOREIGN KEY (skill_id) REFERENCES skills (id) ON DELETE CASCADE
            )
        ''')
        
        # Volunteer applications table - New table for volunteer requests to organizations
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS volunteer_applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                volunteer_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
                message TEXT,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                responded_at TIMESTAMP,
                response_message TEXT,
                FOREIGN KEY (request_id) REFERENCES emergency_requests (id) ON DELETE CASCADE,
                FOREIGN KEY (volunteer_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE(request_id, volunteer_id)
            )
        ''')
        
        # Volunteer assignments table - Updated
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS volunteer_assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                volunteer_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'assigned' CHECK(status IN ('assigned', 'accepted', 'declined', 'completed')),
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                responded_at TIMESTAMP,
                completed_at TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (request_id) REFERENCES emergency_requests (id) ON DELETE CASCADE,
                FOREIGN KEY (volunteer_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE(request_id, volunteer_id)
            )
        ''')
        
        # Activity logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Insert default data
        self.insert_default_data()
    
    def insert_default_data(self):
        # Insert default categories and skills
        default_categories = [
            ('Natural Disasters', 'Earthquakes, floods, cyclones, etc.', 'disaster'),
            ('Medical Emergency', 'Health-related emergencies', 'disaster'),
            ('Fire Emergency', 'Fire-related disasters', 'disaster'),
            ('Healthcare', 'Medical and health-related skills', 'skill'),
            ('Emergency Response', 'Emergency response skills', 'skill'),
            ('Technical', 'Technical and engineering skills', 'skill'),
            ('Communication', 'Communication and coordination skills', 'skill'),
            ('Construction', 'Construction and repair skills', 'skill'),
            ('Support', 'General support skills', 'skill'),
            ('Management', 'Management and coordination skills', 'skill'),
            ('Logistics', 'Logistics and transportation skills', 'skill')
        ]
        
        default_skills = [
            ('Medical Care', 4, 'Basic medical assistance and first aid'),
            ('Emergency Medicine', 4, 'Advanced medical emergency response'),
            ('Nursing', 4, 'Professional nursing care'),
            ('Search and Rescue', 5, 'Search and rescue operations'),
            ('Fire Fighting', 5, 'Fire suppression and prevention'),
            ('Heavy Equipment Operation', 8, 'Operating bulldozers, excavators, etc.'),
            ('Electrical Work', 6, 'Electrical repairs and installations'),
            ('Plumbing', 6, 'Water and sewage system repairs'),
            ('Translation', 7, 'Language translation services'),
            ('IT Support', 6, 'Computer and network technical support'),
            ('Logistics Coordination', 10, 'Supply chain and resource coordination'),
            ('Food Preparation', 9, 'Large-scale food preparation and distribution'),
            ('Shelter Management', 10, 'Managing temporary shelters and facilities'),
            ('Counseling', 9, 'Psychological support and counseling'),
            ('Transportation', 11, 'Vehicle operation and transportation services')
        ]
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Create admin user first
        admin_password = bcrypt.hashpw('admin123!'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('''
            INSERT OR IGNORE INTO users (email, password_hash, full_name, user_type, is_verified, verification_status, state, district)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('admin@emergency.gov', admin_password, 'System Administrator', 'admin', True, 'approved', 'Delhi', 'New Delhi'))
        
        admin_id = cursor.lastrowid or 1
        
        # Insert categories (approved by admin)
        for name, description, cat_type in default_categories:
            cursor.execute('''
                INSERT OR IGNORE INTO categories (name, description, type, is_approved, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, description, cat_type, True, admin_id))
        
        # Insert skills (approved by admin)
        for skill_name, category_id, description in default_skills:
            cursor.execute('''
                INSERT OR IGNORE INTO skills (name, category_id, description, is_approved, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (skill_name, category_id, description, True, admin_id))
        
        conn.commit()
        conn.close()

# Global database instance
db = Database()