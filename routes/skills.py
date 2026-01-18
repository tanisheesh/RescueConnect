from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models.database import db
import sqlite3
from utils.auth import get_current_user_id

skills_bp = Blueprint('skills', __name__)

@skills_bp.route('/categories', methods=['GET'])
def get_categories():
    """Get all approved categories"""
    try:
        category_type = request.args.get('type', 'skill')  # 'skill' or 'disaster'
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, name, description, type
            FROM categories
            WHERE type = ? AND is_approved = 1
            ORDER BY name
        ''', (category_type,))
        
        categories = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'categories': [dict(cat) for cat in categories]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get categories', 'details': str(e)}), 500

@skills_bp.route('/categories', methods=['POST'])
@jwt_required()
def create_category():
    """Create new category (needs admin approval unless created by admin)"""
    try:
        user_id = get_current_user_id()
        data = request.get_json()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Get user type
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        cat_type = data.get('type', '').strip()
        
        if not name or not cat_type:
            return jsonify({'error': 'Name and type are required'}), 400
        
        if cat_type not in ['skill', 'disaster']:
            return jsonify({'error': 'Type must be skill or disaster'}), 400
        
        # Auto-approve if admin, otherwise needs approval
        is_approved = user['user_type'] == 'admin'
        
        try:
            cursor.execute('''
                INSERT INTO categories (name, description, type, is_approved, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, description, cat_type, is_approved, user_id))
            
            category_id = cursor.lastrowid
            
            # Log activity
            cursor.execute('''
                INSERT INTO activity_logs (user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (user_id, 'category_created', f'Category: {name}, Type: {cat_type}, Auto-approved: {is_approved}', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            message = 'Category created successfully' if is_approved else 'Category created and pending admin approval'
            
            return jsonify({
                'message': message,
                'category_id': category_id,
                'is_approved': is_approved
            }), 201
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Category name already exists'}), 409
        
    except Exception as e:
        return jsonify({'error': 'Failed to create category', 'details': str(e)}), 500

@skills_bp.route('/skills', methods=['GET'])
def get_all_skills():
    """Get all approved skills"""
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT s.id, s.name, s.description, c.name as category_name, c.id as category_id
            FROM skills s
            JOIN categories c ON s.category_id = c.id
            WHERE s.is_approved = 1 AND c.is_approved = 1
            ORDER BY c.name, s.name
        ''')
        
        skills = cursor.fetchall()
        conn.close()
        
        # Group skills by category
        skills_by_category = {}
        for skill in skills:
            category = skill['category_name']
            if category not in skills_by_category:
                skills_by_category[category] = []
            skills_by_category[category].append({
                'id': skill['id'],
                'name': skill['name'],
                'description': skill['description'],
                'category_id': skill['category_id']
            })
        
        return jsonify({
            'skills': skills_by_category,
            'total_skills': len(skills)
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get skills', 'details': str(e)}), 500

@skills_bp.route('/skills', methods=['POST'])
@jwt_required()
def create_skill():
    """Create new skill (needs admin approval unless created by admin)"""
    try:
        user_id = get_current_user_id()
        data = request.get_json()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Get user type
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
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
        
        # Auto-approve if admin, otherwise needs approval
        is_approved = user['user_type'] == 'admin'
        
        try:
            cursor.execute('''
                INSERT INTO skills (name, category_id, description, is_approved, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, category_id, description, is_approved, user_id))
            
            skill_id = cursor.lastrowid
            
            # Log activity
            cursor.execute('''
                INSERT INTO activity_logs (user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (user_id, 'skill_created', f'Skill: {name}, Auto-approved: {is_approved}', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            message = 'Skill created successfully' if is_approved else 'Skill created and pending admin approval'
            
            return jsonify({
                'message': message,
                'skill_id': skill_id,
                'is_approved': is_approved
            }), 201
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Skill name already exists'}), 409
        
    except Exception as e:
        return jsonify({'error': 'Failed to create skill', 'details': str(e)}), 500

@skills_bp.route('/user/skills', methods=['GET'])
@jwt_required()
def get_user_skills():
    """Get current user's skills"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT us.id, s.name, c.name as category_name, s.description, 
                   us.proficiency_level, us.is_verified,
                   us.verification_notes, us.verified_at, us.created_at
            FROM user_skills us
            JOIN skills s ON us.skill_id = s.id
            JOIN categories c ON s.category_id = c.id
            WHERE us.user_id = ? AND s.is_approved = 1
            ORDER BY c.name, s.name
        ''', (user_id,))
        
        user_skills = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'skills': [dict(skill) for skill in user_skills]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get user skills', 'details': str(e)}), 500

@skills_bp.route('/user/skills', methods=['POST'])
@jwt_required()
def add_user_skill():
    """Add a skill to current user"""
    try:
        user_id = get_current_user_id()
        data = request.get_json()
        
        skill_id = data.get('skill_id')
        proficiency_level = data.get('proficiency_level', 'beginner')
        verification_notes = data.get('verification_notes', '')
        
        if not skill_id:
            return jsonify({'error': 'skill_id is required'}), 400
        
        if proficiency_level not in ['beginner', 'intermediate', 'expert']:
            return jsonify({'error': 'Invalid proficiency level. Must be beginner, intermediate, or expert'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if skill exists and is approved
        cursor.execute('SELECT id FROM skills WHERE id = ? AND is_approved = 1', (skill_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Skill not found or not approved'}), 404
        
        try:
            cursor.execute('''
                INSERT INTO user_skills (user_id, skill_id, proficiency_level, verification_notes)
                VALUES (?, ?, ?, ?)
            ''', (user_id, skill_id, proficiency_level, verification_notes))
            
            user_skill_id = cursor.lastrowid
            
            # Log activity
            cursor.execute('''
                INSERT INTO activity_logs (user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (user_id, 'skill_added', f'Skill ID: {skill_id}, Level: {proficiency_level}', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'message': 'Skill added successfully',
                'user_skill_id': user_skill_id
            }), 201
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Skill already added to user'}), 409
        
    except Exception as e:
        return jsonify({'error': 'Failed to add skill', 'details': str(e)}), 500

@skills_bp.route('/user/skills/<int:user_skill_id>', methods=['PUT'])
@jwt_required()
def update_user_skill(user_skill_id):
    """Update user's skill proficiency level and verification info"""
    try:
        user_id = get_current_user_id()
        data = request.get_json()
        
        proficiency_level = data.get('proficiency_level')
        verification_notes = data.get('verification_notes')
        
        if not proficiency_level:
            return jsonify({'error': 'proficiency_level is required'}), 400
        
        if proficiency_level not in ['beginner', 'intermediate', 'expert']:
            return jsonify({'error': 'Invalid proficiency level. Must be beginner, intermediate, or expert'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user skill exists and belongs to current user
        cursor.execute('''
            SELECT id FROM user_skills 
            WHERE id = ? AND user_id = ?
        ''', (user_skill_id, user_id))
        
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'User skill not found'}), 404
        
        # Build update query dynamically
        update_fields = ['proficiency_level = ?']
        update_values = [proficiency_level]
        
        if verification_link is not None:
            update_fields.append('verification_link = ?')
            update_values.append(verification_link)
        
        if verification_notes is not None:
            update_fields.append('verification_notes = ?')
            update_values.append(verification_notes)
        
        update_values.extend([user_skill_id, user_id])
        
        cursor.execute(f'''
            UPDATE user_skills 
            SET {', '.join(update_fields)}
            WHERE id = ? AND user_id = ?
        ''', update_values)
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (user_id, 'skill_updated', f'User skill ID: {user_skill_id}, New level: {proficiency_level}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Skill updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to update skill', 'details': str(e)}), 500

@skills_bp.route('/user/skills/<int:user_skill_id>', methods=['DELETE'])
@jwt_required()
def remove_user_skill(user_skill_id):
    """Remove a skill from current user"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user skill exists and belongs to current user
        cursor.execute('''
            SELECT id FROM user_skills 
            WHERE id = ? AND user_id = ?
        ''', (user_skill_id, user_id))
        
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'User skill not found'}), 404
        
        cursor.execute('''
            DELETE FROM user_skills 
            WHERE id = ? AND user_id = ?
        ''', (user_skill_id, user_id))
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (user_id, 'skill_removed', f'User skill ID: {user_skill_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Skill removed successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to remove skill', 'details': str(e)}), 500

@skills_bp.route('/volunteers/by-skill/<int:skill_id>', methods=['GET'])
@jwt_required()
def get_volunteers_by_skill(skill_id):
    """Get volunteers who have a specific skill (for organizations)"""
    try:
        user_id = get_current_user_id()
        state_filter = request.args.get('state')
        district_filter = request.args.get('district')
        
        # Check if current user is organization or admin
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] not in ['organization', 'admin']:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Build query with optional filters
        query = '''
            SELECT u.id, u.full_name, u.email, u.phone, u.address, u.state, u.district,
                   us.proficiency_level, us.is_verified as skill_verified
            FROM users u
            JOIN user_skills us ON u.id = us.user_id
            WHERE us.skill_id = ? 
            AND u.user_type = 'volunteer'
            AND u.is_verified = TRUE
            AND u.verification_status = 'approved'
        '''
        params = [skill_id]
        
        if state_filter:
            query += ' AND u.state = ?'
            params.append(state_filter)
        
        if district_filter:
            query += ' AND u.district = ?'
            params.append(district_filter)
        
        query += ' ORDER BY us.proficiency_level DESC, u.full_name'
        
        cursor.execute(query, params)
        volunteers = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'volunteers': [dict(volunteer) for volunteer in volunteers],
            'total_volunteers': len(volunteers)
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get volunteers', 'details': str(e)}), 500