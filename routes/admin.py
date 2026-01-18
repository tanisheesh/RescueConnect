from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models.database import db
from utils.auth import get_current_user_id, hash_password
import sqlite3

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_admin_stats():
    """Get system statistics for admin"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Get user counts
        cursor.execute('SELECT COUNT(*) as total FROM users')
        total_users = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM users WHERE user_type = "volunteer"')
        total_volunteers = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM users WHERE user_type = "organization"')
        total_organizations = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM emergency_requests WHERE is_approved = 1')
        total_requests = cursor.fetchone()['total']
        
        # Get pending approvals count
        cursor.execute('SELECT COUNT(*) as total FROM users WHERE verification_status = "pending"')
        pending_users = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM emergency_requests WHERE is_approved = 0')
        pending_requests = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM skills WHERE is_approved = 0')
        pending_skills = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM categories WHERE is_approved = 0')
        pending_categories = cursor.fetchone()['total']
        
        conn.close()
        
        return jsonify({
            'stats': {
                'totalUsers': total_users,
                'totalVolunteers': total_volunteers,
                'totalOrganizations': total_organizations,
                'totalRequests': total_requests,
                'pendingUsers': pending_users,
                'pendingRequests': pending_requests,
                'pendingSkills': pending_skills,
                'pendingCategories': pending_categories
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get stats', 'details': str(e)}), 500

@admin_bp.route('/pending-users', methods=['GET'])
@jwt_required()
def get_pending_users():
    """Get users pending approval"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        cursor.execute('''
            SELECT id, email, full_name, user_type, state, district, created_at
            FROM users 
            WHERE verification_status = 'pending'
            ORDER BY created_at DESC
        ''')
        
        pending_users = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'users': [dict(user) for user in pending_users]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get pending users', 'details': str(e)}), 500

@admin_bp.route('/approve-user/<int:user_id>', methods=['PUT'])
@jwt_required()
def approve_user(user_id):
    """Approve or reject user"""
    try:
        admin_id = get_current_user_id()
        data = request.get_json()
        action = data.get('action')  # 'approve' or 'reject'
        
        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Action must be approve or reject'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Update user status
        new_status = 'approved' if action == 'approve' else 'rejected'
        is_verified = True if action == 'approve' else False
        
        cursor.execute('''
            UPDATE users 
            SET verification_status = ?, is_verified = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (new_status, is_verified, user_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, f'user_{action}d', f'User ID: {user_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'User {action}d successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to {action} user', 'details': str(e)}), 500

@admin_bp.route('/create-organization', methods=['POST'])
@jwt_required()
def create_organization():
    """Create organization account (admin only)"""
    try:
        admin_id = get_current_user_id()
        data = request.get_json()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Validate required fields
        required_fields = ['email', 'password', 'full_name', 'state', 'district']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        full_name = data['full_name'].strip()
        phone = data.get('phone', '').strip()
        address = data.get('address', '').strip()
        state = data['state'].strip()
        district = data['district'].strip()
        
        # Hash password
        password_hash = hash_password(password)
        
        try:
            cursor.execute('''
                INSERT INTO users (email, password_hash, full_name, phone, address, 
                                 state, district, user_type, is_verified, verification_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (email, password_hash, full_name, phone, address, state, district, 
                  'organization', True, 'approved'))
            
            org_id = cursor.lastrowid
            
            # Log activity
            cursor.execute('''
                INSERT INTO activity_logs (user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (admin_id, 'organization_created', f'Organization ID: {org_id}, Name: {full_name}', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'message': 'Organization created successfully',
                'organization_id': org_id
            }), 201
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Email already exists'}), 409
        
    except Exception as e:
        return jsonify({'error': 'Failed to create organization', 'details': str(e)}), 500

@admin_bp.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    """Get all categories with approval status"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        cursor.execute('''
            SELECT c.*, u.full_name as created_by_name
            FROM categories c
            JOIN users u ON c.created_by = u.id
            ORDER BY c.type, c.is_approved, c.created_at DESC
        ''')
        
        categories = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'categories': [dict(cat) for cat in categories]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get categories', 'details': str(e)}), 500

@admin_bp.route('/categories', methods=['POST'])
@jwt_required()
def create_category():
    """Create new category (admin only)"""
    try:
        admin_id = get_current_user_id()
        data = request.get_json()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        cat_type = data.get('type', '').strip()
        
        if not name or not cat_type:
            return jsonify({'error': 'Name and type are required'}), 400
        
        if cat_type not in ['skill', 'disaster']:
            return jsonify({'error': 'Type must be skill or disaster'}), 400
        
        try:
            cursor.execute('''
                INSERT INTO categories (name, description, type, is_approved, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, description, cat_type, True, admin_id))
            
            category_id = cursor.lastrowid
            
            # Log activity
            cursor.execute('''
                INSERT INTO activity_logs (user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (admin_id, 'category_created', f'Category: {name}, Type: {cat_type}', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'message': 'Category created successfully',
                'category_id': category_id
            }), 201
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Category name already exists'}), 409
        
    except Exception as e:
        return jsonify({'error': 'Failed to create category', 'details': str(e)}), 500

@admin_bp.route('/approve-category/<int:category_id>', methods=['PUT'])
@jwt_required()
def approve_category(category_id):
    """Approve or reject category"""
    try:
        admin_id = get_current_user_id()
        data = request.get_json()
        action = data.get('action')  # 'approve' or 'reject'
        
        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Action must be approve or reject'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        if action == 'approve':
            cursor.execute('''
                UPDATE categories SET is_approved = 1 WHERE id = ?
            ''', (category_id,))
        else:
            cursor.execute('''
                DELETE FROM categories WHERE id = ?
            ''', (category_id,))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Category not found'}), 404
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, f'category_{action}d', f'Category ID: {category_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'Category {action}d successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to {action} category', 'details': str(e)}), 500

@admin_bp.route('/approve/skill/<int:skill_id>', methods=['POST'])
@jwt_required()
def approve_skill(skill_id):
    """Approve or reject skill"""
    try:
        admin_id = get_current_user_id()
        
        # Handle both JSON and form data, with default action
        try:
            data = request.get_json() or {}
        except:
            data = {}
        
        action = data.get('action', 'approve')  # Default to 'approve' if no action specified
        
        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Action must be approve or reject'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        if action == 'approve':
            cursor.execute('''
                UPDATE skills SET is_approved = 1 WHERE id = ?
            ''', (skill_id,))
        else:
            cursor.execute('''
                DELETE FROM skills WHERE id = ?
            ''', (skill_id,))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Skill not found'}), 404
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, f'skill_{action}d', f'Skill ID: {skill_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'Skill {action}d successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to process skill approval', 'details': str(e)}), 500

@admin_bp.route('/approve/category/<int:category_id>', methods=['POST'])
@jwt_required()
def approve_category_new(category_id):
    """Approve or reject category (new endpoint format)"""
    try:
        admin_id = get_current_user_id()
        data = request.get_json()
        action = data.get('action')  # 'approve' or 'reject'
        
        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Action must be approve or reject'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        if action == 'approve':
            cursor.execute('''
                UPDATE categories SET is_approved = 1 WHERE id = ?
            ''', (category_id,))
        else:
            cursor.execute('''
                DELETE FROM categories WHERE id = ?
            ''', (category_id,))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Category not found'}), 404
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, f'category_{action}d', f'Category ID: {category_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'Category {action}d successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to {action} category', 'details': str(e)}), 500

@admin_bp.route('/approve/user/<int:user_id>', methods=['POST'])
@jwt_required()
def approve_user_new(user_id):
    """Approve or reject user (new endpoint format)"""
    action = 'process'  # Default action for error messages
    try:
        admin_id = get_current_user_id()
        
        # Handle both JSON and form data
        try:
            data = request.get_json() or {}
        except:
            # If JSON parsing fails, try to get from form data or default to approve
            data = {}
        
        action = data.get('action', 'approve')  # Default to approve if no action specified
        
        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Action must be approve or reject'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Update user status
        new_status = 'approved' if action == 'approve' else 'rejected'
        is_verified = True if action == 'approve' else False
        
        cursor.execute('''
            UPDATE users 
            SET verification_status = ?, is_verified = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (new_status, is_verified, user_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, f'user_{action}d', f'User ID: {user_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'User {action}d successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to {action} user', 'details': str(e)}), 500

@admin_bp.route('/approve-skill/<int:skill_id>', methods=['PUT'])
@jwt_required()
def approve_skill_old_format(skill_id):
    """Approve or reject skill (old endpoint format for compatibility)"""
    try:
        admin_id = get_current_user_id()
        data = request.get_json()
        action = data.get('action')  # 'approve' or 'reject'
        
        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Action must be approve or reject'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        if action == 'approve':
            cursor.execute('''
                UPDATE skills SET is_approved = 1 WHERE id = ?
            ''', (skill_id,))
        else:
            cursor.execute('''
                DELETE FROM skills WHERE id = ?
            ''', (skill_id,))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Skill not found'}), 404
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, f'skill_{action}d', f'Skill ID: {skill_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'Skill {action}d successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to {action} skill', 'details': str(e)}), 500

@admin_bp.route('/approve-user_skill/<int:user_skill_id>', methods=['PUT'])
@jwt_required()
def approve_user_skill(user_skill_id):
    """Approve or reject user skill verification"""
    try:
        admin_id = get_current_user_id()
        
        # Handle both JSON and form data, with default action
        try:
            data = request.get_json() or {}
        except:
            data = {}
        
        action = data.get('action', 'approve')  # Default to 'approve' if no action specified
        
        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Action must be approve or reject'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        if action == 'approve':
            cursor.execute('''
                UPDATE user_skills SET is_verified = 1, verified_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (user_skill_id,))
        else:
            cursor.execute('''
                DELETE FROM user_skills WHERE id = ?
            ''', (user_skill_id,))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'User skill not found'}), 404
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, f'user_skill_{action}d', f'User Skill ID: {user_skill_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'User skill {action}d successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to process user skill verification', 'details': str(e)}), 500

@admin_bp.route('/approve-user/<int:user_id>', methods=['PUT'])
@jwt_required()
def approve_user_old_format(user_id):
    """Approve or reject user (old endpoint format for compatibility)"""
    try:
        admin_id = get_current_user_id()
        
        # Handle both JSON and form data, with default action
        try:
            data = request.get_json() or {}
        except:
            data = {}
        
        action = data.get('action', 'approve')  # Default to 'approve' if no action specified
        
        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Action must be approve or reject'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Update user status
        new_status = 'approved' if action == 'approve' else 'rejected'
        is_verified = True if action == 'approve' else False
        
        cursor.execute('''
            UPDATE users 
            SET verification_status = ?, is_verified = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (new_status, is_verified, user_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, f'user_{action}d', f'User ID: {user_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'User {action}d successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to process user approval', 'details': str(e)}), 500

@admin_bp.route('/skills', methods=['POST'])
@jwt_required()
def create_skill():
    """Create new skill (admin only)"""
    try:
        admin_id = get_current_user_id()
        data = request.get_json()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        name = data.get('name', '').strip()
        category_id = data.get('category_id')
        description = data.get('description', '').strip()
        
        if not name or not category_id:
            return jsonify({'error': 'Name and category_id are required'}), 400
        
        # Check if category exists and is approved
        cursor.execute('SELECT id FROM categories WHERE id = ? AND is_approved = 1 AND type = "skill"', (category_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Invalid or unapproved skill category'}), 400
        
        try:
            cursor.execute('''
                INSERT INTO skills (name, category_id, description, is_approved, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, category_id, description, True, admin_id))
            
            skill_id = cursor.lastrowid
            
            # Log activity
            cursor.execute('''
                INSERT INTO activity_logs (user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (admin_id, 'skill_created', f'Skill: {name}', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'message': 'Skill created successfully',
                'skill_id': skill_id
            }), 201
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Skill name already exists'}), 409
        
    except Exception as e:
        return jsonify({'error': 'Failed to create skill', 'details': str(e)}), 500

@admin_bp.route('/pending-requests', methods=['GET'])
@jwt_required()
def get_pending_requests():
    """Get emergency requests pending approval"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        cursor.execute('''
            SELECT er.*, u.full_name as organization_name, c.name as category_name
            FROM emergency_requests er
            JOIN users u ON er.organization_id = u.id
            JOIN categories c ON er.category_id = c.id
            WHERE er.is_approved = 0 AND er.status = 'pending'
            ORDER BY er.created_at DESC
        ''')
        
        pending_requests = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'requests': [dict(req) for req in pending_requests]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get pending requests', 'details': str(e)}), 500

@admin_bp.route('/approve-request/<int:request_id>', methods=['PUT'])
@jwt_required()
def approve_request(request_id):
    """Approve or reject emergency request"""
    try:
        admin_id = get_current_user_id()
        data = request.get_json()
        action = data.get('action')  # 'approve' or 'reject'
        
        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Action must be approve or reject'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        if action == 'approve':
            cursor.execute('''
                UPDATE emergency_requests 
                SET is_approved = 1, status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (admin_id, request_id))
        else:
            cursor.execute('''
                UPDATE emergency_requests 
                SET status = 'rejected', approved_by = ?, approved_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (admin_id, request_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Request not found'}), 404
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, f'request_{action}d', f'Request ID: {request_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'Request {action}d successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to {action} request', 'details': str(e)}), 500

@admin_bp.route('/activity', methods=['GET'])
@jwt_required()
def get_system_activity():
    """Get recent system activity for admin (important notifications only)"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Get only important activity logs (filter out routine actions)
        important_actions = [
            'user_approved', 'user_rejected', 'user_registered',
            'organization_created', 'category_created', 'skill_created',
            'category_approved', 'category_rejected', 'skill_approved', 'skill_rejected',
            'request_approved', 'request_rejected', 'emergency_request_created',
            'skill_verified', 'user_skill_verified'
        ]
        
        # Create placeholders for the IN clause
        placeholders = ','.join(['?' for _ in important_actions])
        
        cursor.execute(f'''
            SELECT al.*, u.full_name as user_name, u.user_type
            FROM activity_logs al
            JOIN users u ON al.user_id = u.id
            WHERE al.action IN ({placeholders})
            ORDER BY al.created_at DESC
            LIMIT 20
        ''', important_actions)
        
        activities = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'activities': [dict(activity) for activity in activities]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get activity', 'details': str(e)}), 500

@admin_bp.route('/overview', methods=['GET'])
@jwt_required()
def get_system_overview():
    """Get system overview data for admin"""
    try:
        user_id = get_current_user_id()
        time_range = request.args.get('range', '7d')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Calculate date filter based on time range
        if time_range == '24h':
            date_filter = "datetime('now', '-1 day')"
        elif time_range == '30d':
            date_filter = "datetime('now', '-30 days')"
        else:  # default 7d
            date_filter = "datetime('now', '-7 days')"
        
        # Get priority breakdown for the time range
        cursor.execute(f'''
            SELECT priority_level, COUNT(*) as count
            FROM emergency_requests
            WHERE is_approved = 1 AND created_at >= {date_filter}
            GROUP BY priority_level
        ''')
        priority_results = cursor.fetchall()
        priority_breakdown = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        for row in priority_results:
            if row['priority_level'] in priority_breakdown:
                priority_breakdown[row['priority_level']] = row['count']
        
        # Get verification stats (not time-filtered as these are current states)
        cursor.execute('SELECT COUNT(*) as total FROM users WHERE is_verified = 1')
        verified_users = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM users WHERE verification_status = "pending"')
        pending_users = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM user_skills WHERE is_verified = 1')
        verified_skills = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM user_skills WHERE is_verified = 0')
        pending_skills = cursor.fetchone()['total']
        
        # Get response metrics for the time range - check if volunteer_assignments table exists
        try:
            cursor.execute(f'''
                SELECT COUNT(*) as total FROM volunteer_assignments 
                WHERE status = "accepted" AND created_at >= {date_filter}
            ''')
            active_assignments = cursor.fetchone()['total']
        except:
            # Table might not exist, use default value
            active_assignments = 0
        
        # Calculate average response time (simplified) - check if table exists first
        try:
            cursor.execute(f'''
                SELECT AVG(
                    CASE 
                        WHEN accepted_at IS NOT NULL 
                        THEN (julianday(accepted_at) - julianday(created_at)) * 24 
                        ELSE NULL 
                    END
                ) as avg_hours
                FROM volunteer_assignments 
                WHERE accepted_at IS NOT NULL AND created_at >= {date_filter}
            ''')
            avg_result = cursor.fetchone()
            avg_response_hours = avg_result['avg_hours'] if avg_result and avg_result['avg_hours'] else 0
        except:
            avg_response_hours = 0
        
        avg_response_time = f"{avg_response_hours:.1f}h" if avg_response_hours > 0 else "N/A"
        
        # Calculate success rate
        try:
            cursor.execute(f'''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed
                FROM volunteer_assignments 
                WHERE created_at >= {date_filter}
            ''')
            success_result = cursor.fetchone()
            success_rate = "0%"
            if success_result and success_result['total'] > 0:
                rate = (success_result['completed'] / success_result['total']) * 100
                success_rate = f"{rate:.0f}%"
            else:
                success_rate = "N/A"
        except:
            success_rate = "N/A"
        
        conn.close()
        
        return jsonify({
            'overview': {
                'priorityBreakdown': priority_breakdown,
                'verificationStats': {
                    'verifiedUsers': verified_users,
                    'pendingUsers': pending_users,
                    'verifiedSkills': verified_skills,
                    'pendingSkills': pending_skills
                },
                'responseMetrics': {
                    'avgResponseTime': avg_response_time,
                    'successRate': success_rate,
                    'activeAssignments': active_assignments
                },
                'timeRange': time_range
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get overview', 'details': str(e)}), 500

@admin_bp.route('/categories/<int:category_id>', methods=['PUT'])
@jwt_required()
def update_category(category_id):
    """Update category (admin only)"""
    try:
        admin_id = get_current_user_id()
        data = request.get_json()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        
        if not name:
            return jsonify({'error': 'Name is required'}), 400
        
        # Check if category exists
        cursor.execute('SELECT id FROM categories WHERE id = ?', (category_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Category not found'}), 404
        
        try:
            cursor.execute('''
                UPDATE categories 
                SET name = ?, description = ?
                WHERE id = ?
            ''', (name, description, category_id))
            
            # Log activity
            cursor.execute('''
                INSERT INTO activity_logs (user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (admin_id, 'category_updated', f'Category ID: {category_id}, Name: {name}', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            return jsonify({'message': 'Category updated successfully'}), 200
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Category name already exists'}), 409
        
    except Exception as e:
        return jsonify({'error': 'Failed to update category', 'details': str(e)}), 500

@admin_bp.route('/categories/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    """Delete category (admin only)"""
    try:
        admin_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Check if category exists
        cursor.execute('SELECT name FROM categories WHERE id = ?', (category_id,))
        category = cursor.fetchone()
        if not category:
            conn.close()
            return jsonify({'error': 'Category not found'}), 404
        
        # Check if category has skills
        cursor.execute('SELECT COUNT(*) as count FROM skills WHERE category_id = ?', (category_id,))
        skill_count = cursor.fetchone()['count']
        
        if skill_count > 0:
            conn.close()
            return jsonify({'error': f'Cannot delete category. It has {skill_count} skills associated with it.'}), 400
        
        cursor.execute('DELETE FROM categories WHERE id = ?', (category_id,))
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, 'category_deleted', f'Category: {category["name"]}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Category deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to delete category', 'details': str(e)}), 500

@admin_bp.route('/skills/<int:skill_id>', methods=['PUT'])
@jwt_required()
def update_skill(skill_id):
    """Update skill (admin only)"""
    try:
        admin_id = get_current_user_id()
        data = request.get_json()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        name = data.get('name', '').strip()
        category_id = data.get('category_id')
        description = data.get('description', '').strip()
        
        if not name or not category_id:
            return jsonify({'error': 'Name and category_id are required'}), 400
        
        # Check if skill exists
        cursor.execute('SELECT id FROM skills WHERE id = ?', (skill_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Skill not found'}), 404
        
        # Check if category exists and is approved
        cursor.execute('SELECT id FROM categories WHERE id = ? AND is_approved = 1 AND type = "skill"', (category_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Invalid or unapproved skill category'}), 400
        
        try:
            cursor.execute('''
                UPDATE skills 
                SET name = ?, category_id = ?, description = ?
                WHERE id = ?
            ''', (name, category_id, description, skill_id))
            
            # Log activity
            cursor.execute('''
                INSERT INTO activity_logs (user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (admin_id, 'skill_updated', f'Skill ID: {skill_id}, Name: {name}', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            return jsonify({'message': 'Skill updated successfully'}), 200
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Skill name already exists'}), 409
        
    except Exception as e:
        return jsonify({'error': 'Failed to update skill', 'details': str(e)}), 500

@admin_bp.route('/skills/<int:skill_id>', methods=['DELETE'])
@jwt_required()
def delete_skill(skill_id):
    """Delete skill (admin only)"""
    try:
        admin_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Check if skill exists
        cursor.execute('SELECT name FROM skills WHERE id = ?', (skill_id,))
        skill = cursor.fetchone()
        if not skill:
            conn.close()
            return jsonify({'error': 'Skill not found'}), 404
        
        # Check if skill is being used by users
        cursor.execute('SELECT COUNT(*) as count FROM user_skills WHERE skill_id = ?', (skill_id,))
        user_count = cursor.fetchone()['count']
        
        if user_count > 0:
            conn.close()
            return jsonify({'error': f'Cannot delete skill. It is being used by {user_count} users.'}), 400
        
        cursor.execute('DELETE FROM skills WHERE id = ?', (skill_id,))
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (admin_id, 'skill_deleted', f'Skill: {skill["name"]}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Skill deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to delete skill', 'details': str(e)}), 500

@admin_bp.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    """Get all volunteer users for admin management (excludes admins and organizations)"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Get only volunteer users (exclude admins and organizations)
        cursor.execute('''
            SELECT id, email, full_name, user_type, state, district, 
                   is_verified, verification_status, created_at
            FROM users
            WHERE user_type = 'volunteer'
            ORDER BY created_at DESC
        ''')
        
        users = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'users': [dict(user) for user in users]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get users', 'details': str(e)}), 500

@admin_bp.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_details(user_id):
    """Get detailed user information"""
    try:
        admin_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (admin_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Get user basic info
        cursor.execute('''
            SELECT id, email, full_name, phone, address, state, district, 
                   user_type, is_verified, verification_status, created_at
            FROM users WHERE id = ?
        ''', (user_id,))
        
        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        user_data = dict(user)
        
        # Get user skills if volunteer
        if user['user_type'] == 'volunteer':
            cursor.execute('''
                SELECT us.id, s.name as skill_name, c.name as category_name,
                       us.proficiency_level, us.is_verified, us.verification_link,
                       us.verification_notes, us.created_at
                FROM user_skills us
                JOIN skills s ON us.skill_id = s.id
                JOIN categories c ON s.category_id = c.id
                WHERE us.user_id = ?
                ORDER BY us.created_at DESC
            ''', (user_id,))
            
            user_data['skills'] = [dict(skill) for skill in cursor.fetchall()]
            
            # Get volunteer assignments/past work - handle if table doesn't exist
            try:
                cursor.execute('''
                    SELECT va.id, er.title, er.description, va.status, 
                           va.created_at, va.accepted_at, va.completed_at,
                           u.full_name as organization_name
                    FROM volunteer_assignments va
                    JOIN emergency_requests er ON va.request_id = er.id
                    JOIN users u ON er.organization_id = u.id
                    WHERE va.volunteer_id = ?
                    ORDER BY va.created_at DESC
                ''', (user_id,))
                
                user_data['assignments'] = [dict(assignment) for assignment in cursor.fetchall()]
            except:
                # Table doesn't exist, set empty assignments
                user_data['assignments'] = []
        
        # Get emergency requests if organization
        elif user['user_type'] == 'organization':
            cursor.execute('''
                SELECT id, title, description, priority_level, status, 
                       volunteers_needed, is_approved, created_at
                FROM emergency_requests
                WHERE organization_id = ?
                ORDER BY created_at DESC
            ''', (user_id,))
            
            user_data['emergency_requests'] = [dict(req) for req in cursor.fetchall()]
        
        # Get activity logs
        cursor.execute('''
            SELECT action, details, created_at, ip_address
            FROM activity_logs
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 20
        ''', (user_id,))
        
        user_data['recent_activity'] = [dict(activity) for activity in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({'user': user_data}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get user details', 'details': str(e)}), 500

@admin_bp.route('/organizations', methods=['GET'])
@jwt_required()
def get_all_organizations():
    """Get all organizations for admin management"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Get all organizations with basic info
        cursor.execute('''
            SELECT id, email, full_name, state, district, 
                   is_verified, verification_status, created_at
            FROM users
            WHERE user_type = 'organization'
            ORDER BY created_at DESC
        ''')
        
        organizations = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'organizations': [dict(org) for org in organizations]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get organizations', 'details': str(e)}), 500

@admin_bp.route('/reports/registration-trends', methods=['GET'])
@jwt_required()
def get_registration_trends():
    """Get registration trends report"""
    try:
        user_id = get_current_user_id()
        time_range = request.args.get('range', '7d')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Convert time range to days
        days_map = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
        days = days_map.get(time_range, 7)
        
        cursor.execute('''
            SELECT DATE(created_at) as date, user_type, COUNT(*) as count
            FROM users
            WHERE created_at >= datetime('now', '-{} days')
            GROUP BY DATE(created_at), user_type
            ORDER BY date DESC
        '''.format(days))
        trends = cursor.fetchall()
        
        # Get total count
        cursor.execute('''
            SELECT COUNT(*) as total
            FROM users
            WHERE created_at >= datetime('now', '-{} days')
        '''.format(days))
        total = cursor.fetchone()['total']
        
        conn.close()
        
        return jsonify({
            'trends': [dict(trend) for trend in trends],
            'total': total
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get registration trends', 'details': str(e)}), 500

@admin_bp.route('/reports/skills-distribution', methods=['GET'])
@jwt_required()
def get_skills_distribution():
    """Get skills distribution report"""
    try:
        user_id = get_current_user_id()
        time_range = request.args.get('range', '7d')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Convert time range to days
        days_map = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
        days = days_map.get(time_range, 7)
        
        cursor.execute('''
            SELECT c.name as category, s.name as skill_name, COUNT(us.id) as count
            FROM categories c
            LEFT JOIN skills s ON c.id = s.category_id
            LEFT JOIN user_skills us ON s.id = us.skill_id AND us.created_at >= datetime('now', '-{} days')
            WHERE c.type = 'skill'
            GROUP BY c.id, c.name, s.id, s.name
            HAVING count > 0
            ORDER BY count DESC
        '''.format(days))
        distribution = cursor.fetchall()
        
        # Get total count
        cursor.execute('''
            SELECT COUNT(*) as total
            FROM user_skills
            WHERE created_at >= datetime('now', '-{} days')
        '''.format(days))
        total = cursor.fetchone()['total']
        
        conn.close()
        
        return jsonify({
            'distribution': [dict(item) for item in distribution],
            'total': total
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get skills distribution', 'details': str(e)}), 500

@admin_bp.route('/reports/requests-by-state', methods=['GET'])
@jwt_required()
def get_requests_by_state():
    """Get emergency requests by state report"""
    try:
        user_id = get_current_user_id()
        time_range = request.args.get('range', '7d')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Convert time range to days
        days_map = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
        days = days_map.get(time_range, 7)
        
        cursor.execute('''
            SELECT u.state, COUNT(er.id) as count, AVG(
                CASE er.priority_level 
                    WHEN 'critical' THEN 4
                    WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 1
                    ELSE 0
                END
            ) as avg_priority_num
            FROM emergency_requests er
            JOIN users u ON er.organization_id = u.id
            WHERE er.created_at >= datetime('now', '-{} days')
            GROUP BY u.state
            ORDER BY count DESC
        '''.format(days))
        requests = cursor.fetchall()
        
        # Convert avg priority back to text
        for req in requests:
            req = dict(req)
            avg_num = req.get('avg_priority_num', 0)
            if avg_num >= 3.5:
                req['avg_priority'] = 'critical'
            elif avg_num >= 2.5:
                req['avg_priority'] = 'high'
            elif avg_num >= 1.5:
                req['avg_priority'] = 'medium'
            else:
                req['avg_priority'] = 'low'
        
        # Get total count
        cursor.execute('''
            SELECT COUNT(*) as total
            FROM emergency_requests
            WHERE created_at >= datetime('now', '-{} days')
        '''.format(days))
        total = cursor.fetchone()['total']
        
        conn.close()
        
        return jsonify({
            'requests': [dict(req) for req in requests],
            'total': total
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get requests by state', 'details': str(e)}), 500

@admin_bp.route('/reports/verification-summary', methods=['GET'])
@jwt_required()
def get_verification_summary():
    """Get verification status summary report"""
    try:
        user_id = get_current_user_id()
        time_range = request.args.get('range', '7d')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Convert time range to days
        days_map = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
        days = days_map.get(time_range, 7)
        
        cursor.execute('''
            SELECT 
                user_type,
                verification_status,
                COUNT(*) as count
            FROM users
            WHERE created_at >= datetime('now', '-{} days')
            GROUP BY user_type, verification_status
            ORDER BY user_type, verification_status
        '''.format(days))
        summary = cursor.fetchall()
        
        # Get total count
        cursor.execute('''
            SELECT COUNT(*) as total
            FROM users
            WHERE created_at >= datetime('now', '-{} days')
        '''.format(days))
        total = cursor.fetchone()['total']
        
        conn.close()
        
        return jsonify({
            'summary': [dict(item) for item in summary],
            'total': total
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get verification summary', 'details': str(e)}), 500

@admin_bp.route('/reports/activity-summary', methods=['GET'])
@jwt_required()
def get_activity_summary():
    """Get activity summary report"""
    try:
        user_id = get_current_user_id()
        time_range = request.args.get('range', '7d')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Convert time range to days
        days_map = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
        days = days_map.get(time_range, 7)
        
        cursor.execute('''
            SELECT 
                al.action,
                u.user_type,
                COUNT(*) as count
            FROM activity_logs al
            JOIN users u ON al.user_id = u.id
            WHERE al.created_at >= datetime('now', '-{} days')
            GROUP BY al.action, u.user_type
            ORDER BY count DESC
        '''.format(days))
        activities = cursor.fetchall()
        
        # Get total count
        cursor.execute('''
            SELECT COUNT(*) as total
            FROM activity_logs
            WHERE created_at >= datetime('now', '-{} days')
        '''.format(days))
        total = cursor.fetchone()['total']
        
        conn.close()
        
        return jsonify({
            'activities': [dict(activity) for activity in activities],
            'total': total
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get activity summary', 'details': str(e)}), 500

@admin_bp.route('/reports/response-metrics', methods=['GET'])
@jwt_required()
def get_response_metrics():
    """Get response metrics report"""
    try:
        user_id = get_current_user_id()
        time_range = request.args.get('range', '7d')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Convert time range to days
        days_map = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
        days = days_map.get(time_range, 7)
        
        # Calculate basic metrics
        cursor.execute('''
            SELECT COUNT(*) as total_requests
            FROM emergency_requests
            WHERE created_at >= datetime('now', '-{} days')
        '''.format(days))
        total_requests = cursor.fetchone()['total_requests']
        
        cursor.execute('''
            SELECT COUNT(*) as approved_requests
            FROM emergency_requests
            WHERE created_at >= datetime('now', '-{} days') AND is_approved = 1
        '''.format(days))
        approved_requests = cursor.fetchone()['approved_requests']
        
        cursor.execute('''
            SELECT COUNT(*) as active_volunteers
            FROM users
            WHERE user_type = 'volunteer' AND verification_status = 'approved'
        ''')
        active_volunteers = cursor.fetchone()['active_volunteers']
        
        cursor.execute('''
            SELECT COUNT(*) as total_volunteers
            FROM users
            WHERE user_type = 'volunteer'
        ''')
        total_volunteers = cursor.fetchone()['total_volunteers']
        
        # Calculate metrics
        success_rate = round((approved_requests / total_requests * 100) if total_requests > 0 else 0, 1)
        volunteer_utilization = round((active_volunteers / total_volunteers * 100) if total_volunteers > 0 else 0, 1)
        
        # Mock some metrics that would require more complex calculations
        avg_response_time = "2.5h"  # This would need actual response tracking
        active_assignments = 0  # This would need assignment tracking
        
        conn.close()
        
        return jsonify({
            'metrics': {
                'avgResponseTime': avg_response_time,
                'successRate': f"{success_rate}%",
                'activeAssignments': active_assignments,
                'volunteerUtilization': f"{volunteer_utilization}%"
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get response metrics', 'details': str(e)}), 500

@admin_bp.route('/reports/system', methods=['GET'])
@jwt_required()
def get_system_reports():
    """Get system reports for admin"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # User registration trends (last 30 days)
        cursor.execute('''
            SELECT DATE(created_at) as date, user_type, COUNT(*) as count
            FROM users
            WHERE created_at >= datetime('now', '-30 days')
            GROUP BY DATE(created_at), user_type
            ORDER BY date DESC
        ''')
        registration_trends = cursor.fetchall()
        
        # Skills distribution
        cursor.execute('''
            SELECT c.name as category, COUNT(us.id) as count
            FROM categories c
            LEFT JOIN skills s ON c.id = s.category_id
            LEFT JOIN user_skills us ON s.id = us.skill_id
            WHERE c.type = 'skill'
            GROUP BY c.id, c.name
            ORDER BY count DESC
        ''')
        skills_distribution = cursor.fetchall()
        
        # Emergency requests by state
        cursor.execute('''
            SELECT u.state, COUNT(er.id) as count
            FROM emergency_requests er
            JOIN users u ON er.organization_id = u.id
            WHERE er.is_approved = 1
            GROUP BY u.state
            ORDER BY count DESC
        ''')
        requests_by_state = cursor.fetchall()
        
        # Verification status summary
        cursor.execute('''
            SELECT 
                user_type,
                verification_status,
                COUNT(*) as count
            FROM users
            GROUP BY user_type, verification_status
        ''')
        verification_summary = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'reports': {
                'registrationTrends': [dict(trend) for trend in registration_trends],
                'skillsDistribution': [dict(skill) for skill in skills_distribution],
                'requestsByState': [dict(req) for req in requests_by_state],
                'verificationSummary': [dict(summary) for summary in verification_summary]
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get system reports', 'details': str(e)}), 500

@admin_bp.route('/pending', methods=['GET'])
@jwt_required()
def get_pending_approvals():
    """Get pending approvals for admin"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        pending = []
        
        # Get pending user verifications
        cursor.execute('''
            SELECT id, full_name, email, user_type, created_at
            FROM users WHERE verification_status = 'pending'
        ''')
        pending_users = cursor.fetchall()
        
        for user in pending_users:
            pending.append({
                'type': 'user',
                'id': user['id'],
                'description': f"{user['full_name']} ({user['user_type']}) - {user['email']}",
                'created_at': user['created_at']
            })
        
        # Get pending skill verifications (user skills needing verification)
        cursor.execute('''
            SELECT us.id, u.full_name, s.name as skill_name, us.created_at
            FROM user_skills us
            JOIN users u ON us.user_id = u.id
            JOIN skills s ON us.skill_id = s.id
            WHERE us.is_verified = 0
        ''')
        pending_user_skills = cursor.fetchall()
        
        for skill in pending_user_skills:
            pending.append({
                'type': 'user_skill',
                'id': skill['id'],
                'description': f"{skill['full_name']} - {skill['skill_name']} (skill verification)",
                'created_at': skill['created_at']
            })
        
        # Get pending skill suggestions (new skills needing approval)
        cursor.execute('''
            SELECT s.id, s.name, u.full_name as created_by_name, s.created_at
            FROM skills s
            JOIN users u ON s.created_by = u.id
            WHERE s.is_approved = 0
        ''')
        pending_skill_suggestions = cursor.fetchall()
        
        for skill in pending_skill_suggestions:
            pending.append({
                'type': 'skill',
                'id': skill['id'],
                'description': f"New skill: {skill['name']} by {skill['created_by_name']}",
                'created_at': skill['created_at']
            })
        
        # Get pending categories
        cursor.execute('''
            SELECT c.id, c.name, c.type, u.full_name as created_by_name, c.created_at
            FROM categories c
            JOIN users u ON c.created_by = u.id
            WHERE c.is_approved = 0
        ''')
        pending_categories = cursor.fetchall()
        
        for category in pending_categories:
            pending.append({
                'type': 'category',
                'id': category['id'],
                'description': f"{category['name']} ({category['type']}) by {category['created_by_name']}",
                'created_at': category['created_at']
            })
        
        conn.close()
        
        return jsonify({
            'pending': pending
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get pending approvals', 'details': str(e)}), 500