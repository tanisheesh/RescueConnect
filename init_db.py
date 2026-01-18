#!/usr/bin/env python3
"""
Database initialization script for Citizen Emergency Response Platform
"""

import os
import sys
import sqlite3
import bcrypt
from datetime import datetime

def main():
    """Initialize the database with tables and default data"""
    
    print("🔧 Initializing Citizen Emergency Response Platform Database...")
    
    try:
        # Import the database module to trigger initialization
        from models.database import db
        
        print("✅ Database tables created successfully")
        
        # Verify admin user exists
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE user_type = "admin"')
        admin_count = cursor.fetchone()['count']
        
        if admin_count == 0:
            print("⚠️ No admin user found, creating default admin...")
            
            # Create default admin
            admin_password = bcrypt.hashpw('admin123!'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute('''
                INSERT INTO users (email, password_hash, full_name, user_type, is_verified, verification_status, state, district)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', ('admin@emergency.gov', admin_password, 'System Administrator', 'admin', True, 'approved', 'Delhi', 'New Delhi'))
            
            conn.commit()
            print("✅ Default admin user created")
        
        # Create some demo data
        create_demo_data(conn, cursor)
        
        conn.close()
        
        print("\n🎉 Database initialization completed successfully!")
        print("\n📋 Demo Accounts:")
        print("   👤 Admin: admin@emergency.gov / admin123!")
        print("   🏢 Organization: disaster@redcross.org / org123!")
        print("   🙋 Volunteer: john.doe@email.com / volunteer123!")
        print("\n🚀 You can now start the application!")
        
        return 0
        
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return 1

def create_demo_data(conn, cursor):
    """Create demo organizations and volunteers"""
    
    print("📝 Creating demo data...")
    
    try:
        # Create demo organization
        org_password = bcrypt.hashpw('org123!'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('''
            INSERT OR IGNORE INTO users (email, password_hash, full_name, phone, address, state, district, user_type, is_verified, verification_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('disaster@redcross.org', org_password, 'Red Cross Disaster Relief', '+91-9876543210', 
              'Red Cross Bhawan, New Delhi', 'Delhi', 'New Delhi', 'organization', True, 'approved'))
        
        # Create demo volunteer
        vol_password = bcrypt.hashpw('volunteer123!'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('''
            INSERT OR IGNORE INTO users (email, password_hash, full_name, phone, address, state, district, user_type, is_verified, verification_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('john.doe@email.com', vol_password, 'John Doe', '+91-9876543211', 
              'Sector 15, Noida', 'Uttar Pradesh', 'Gautam Buddha Nagar', 'volunteer', True, 'approved'))
        
        # Get volunteer ID and add some skills
        cursor.execute('SELECT id FROM users WHERE email = ?', ('john.doe@email.com',))
        volunteer_result = cursor.fetchone()
        
        if volunteer_result:
            volunteer_id = volunteer_result['id']
            
            # Add medical care skill
            cursor.execute('SELECT id FROM skills WHERE name = ? AND is_approved = 1', ('Medical Care',))
            skill_result = cursor.fetchone()
            
            if skill_result:
                cursor.execute('''
                    INSERT OR IGNORE INTO user_skills (user_id, skill_id, proficiency_level, is_verified)
                    VALUES (?, ?, ?, ?)
                ''', (volunteer_id, skill_result['id'], 'intermediate', True))
        
        # Create a demo emergency request
        cursor.execute('SELECT id FROM users WHERE email = ?', ('disaster@redcross.org',))
        org_result = cursor.fetchone()
        
        cursor.execute('SELECT id FROM categories WHERE name = ? AND type = "disaster"', ('Natural Disasters',))
        category_result = cursor.fetchone()
        
        if org_result and category_result:
            cursor.execute('''
                INSERT OR IGNORE INTO emergency_requests 
                (title, description, organization_id, category_id, state, district, priority_level, volunteers_needed, is_approved, status, approved_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', ('Flood Relief - Delhi NCR', 
                  'Urgent need for volunteers to help with flood relief operations in Delhi NCR region. Medical assistance and logistics support required.',
                  org_result['id'], category_result['id'], 'Delhi', 'New Delhi', 'high', 5, True, 'approved', 1))
        
        conn.commit()
        print("✅ Demo data created successfully")
        
    except Exception as e:
        print(f"⚠️ Demo data creation failed: {e}")

if __name__ == '__main__':
    sys.exit(main())