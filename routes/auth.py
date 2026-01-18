from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models.database import db
from utils.auth import hash_password, get_current_user_id, verify_password, validate_password, validate_email, create_token
import sqlite3

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'full_name', 'user_type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        full_name = data['full_name'].strip()
        user_type = data['user_type']
        phone = data.get('phone', '').strip()
        address = data.get('address', '').strip()
        state = data.get('state', '').strip()
        district = data.get('district', '').strip()
        
        # Organization-specific fields
        organization_type = data.get('organization_type', '').strip()
        registration_number = data.get('registration_number', '').strip()
        website = data.get('website', '').strip()
        description = data.get('description', '').strip()
        
        # Validate email
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password
        password_errors = validate_password(password)
        if password_errors:
            return jsonify({'error': 'Password validation failed', 'details': password_errors}), 400
        
        # Validate user type
        if user_type not in ['volunteer', 'organization']:
            return jsonify({'error': 'Invalid user type'}), 400
        
        # Validate required fields for location
        if not state or not district:
            return jsonify({'error': 'State and district are required'}), 400
        
        # Additional validation for organizations
        if user_type == 'organization':
            if not organization_type or not description:
                return jsonify({'error': 'Organization type and description are required for organizations'}), 400
        
        # Hash password
        password_hash = hash_password(password)
        
        # Insert user into database
        conn = db.get_connection()
        cursor = conn.cursor()
        
        try:
            # Insert user with pending approval status
            cursor.execute('''
                INSERT INTO users (email, password_hash, full_name, phone, address, 
                                 state, district, user_type, verification_status, is_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (email, password_hash, full_name, phone, address, state, district, user_type, 'pending', False))
            
            user_id = cursor.lastrowid
            
            # If organization, store additional details
            if user_type == 'organization':
                cursor.execute('''
                    INSERT INTO organization_details (user_id, organization_type, registration_number, 
                                                    website, description)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, organization_type, registration_number, website, description))
            
            conn.commit()
            
            # Log registration activity
            cursor.execute('''
                INSERT INTO activity_logs (user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (user_id, 'user_registered', f'User type: {user_type}, Status: pending approval', request.remote_addr))
            
            conn.commit()
            
            return jsonify({
                'message': f'{user_type.title()} registration successful. Your account is pending admin approval.',
                'user': {
                    'id': user_id,
                    'email': email,
                    'full_name': full_name,
                    'user_type': user_type,
                    'verification_status': 'pending'
                }
            }), 201
            
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Email already exists'}), 409
        
        finally:
            conn.close()
            
    except Exception as e:
        return jsonify({'error': 'Registration failed', 'details': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Get user by email
        cursor.execute('''
            SELECT id, email, password_hash, full_name, user_type, is_verified, verification_status
            FROM users WHERE email = ?
        ''', (email,))
        
        user = cursor.fetchone()
        
        if not user or not verify_password(password, user['password_hash']):
            # Log failed login attempt
            if user:
                cursor.execute('''
                    INSERT INTO activity_logs (user_id, action, details, ip_address)
                    VALUES (?, ?, ?, ?)
                ''', (user['id'], 'login_failed', 'Invalid password', request.remote_addr))
                conn.commit()
            
            conn.close()
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Check if user is approved
        if user['verification_status'] != 'approved':
            conn.close()
            return jsonify({'error': 'Your account is pending admin approval'}), 403
        
        # Log successful login
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (user['id'], 'login_success', 'User logged in', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        # Create JWT token
        token = create_token(user['id'])
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user['full_name'],
                'user_type': user['user_type'],
                'is_verified': user['is_verified']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Login failed', 'details': str(e)}), 500

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, email, full_name, phone, address, state, district, 
                   user_type, is_verified, verification_status, created_at
            FROM users WHERE id = ?
        ''', (user_id,))
        
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': dict(user)
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get profile', 'details': str(e)}), 500

@auth_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    try:
        user_id = get_current_user_id()
        data = request.get_json()
        
        # Fields that can be updated
        updatable_fields = ['full_name', 'phone', 'address', 'state', 'district']
        updates = {}
        
        for field in updatable_fields:
            if field in data:
                updates[field] = data[field]
        
        if not updates:
            return jsonify({'error': 'No valid fields to update'}), 400
        
        # Build update query
        set_clause = ', '.join([f"{field} = ?" for field in updates.keys()])
        values = list(updates.values()) + [user_id]
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(f'''
            UPDATE users SET {set_clause}, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', values)
        
        # Log profile update
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (user_id, 'profile_updated', f'Updated fields: {", ".join(updates.keys())}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Profile updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to update profile', 'details': str(e)}), 500