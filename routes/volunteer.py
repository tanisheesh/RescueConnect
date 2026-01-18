from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models.database import db
from utils.auth import get_current_user_id

volunteer_bp = Blueprint('volunteer', __name__)

@volunteer_bp.route('/assignments', methods=['GET'])
@jwt_required()
def get_volunteer_assignments():
    """Get assignments for current volunteer"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is volunteer
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'volunteer':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Get volunteer assignments with request details
        cursor.execute('''
            SELECT va.*, er.title as request_title, er.description as request_description,
                   er.state, er.district, er.priority_level, u.full_name as organization_name,
                   c.name as category_name
            FROM volunteer_assignments va
            JOIN emergency_requests er ON va.request_id = er.id
            JOIN users u ON er.organization_id = u.id
            JOIN categories c ON er.category_id = c.id
            WHERE va.volunteer_id = ?
            ORDER BY va.assigned_at DESC
        ''', (user_id,))
        
        assignments = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'assignments': [dict(assignment) for assignment in assignments]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get assignments', 'details': str(e)}), 500

@volunteer_bp.route('/applications', methods=['GET'])
@jwt_required()
def get_volunteer_applications():
    """Get applications submitted by current volunteer"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is volunteer
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'volunteer':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Get volunteer applications with request details
        cursor.execute('''
            SELECT va.*, er.title as request_title, er.description as request_description,
                   er.state, er.district, er.priority_level, u.full_name as organization_name,
                   c.name as category_name
            FROM volunteer_applications va
            JOIN emergency_requests er ON va.request_id = er.id
            JOIN users u ON er.organization_id = u.id
            JOIN categories c ON er.category_id = c.id
            WHERE va.volunteer_id = ?
            ORDER BY va.applied_at DESC
        ''', (user_id,))
        
        applications = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'applications': [dict(app) for app in applications]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get applications', 'details': str(e)}), 500

@volunteer_bp.route('/nearby-requests', methods=['GET'])
@jwt_required()
def get_nearby_requests():
    """Get nearby emergency requests for volunteer based on state/district"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Get volunteer location
        cursor.execute('SELECT state, district FROM users WHERE id = ?', (user_id,))
        volunteer = cursor.fetchone()
        
        if not volunteer or not volunteer['state']:
            conn.close()
            return jsonify({'requests': []}), 200
        
        # Get approved emergency requests in the same state
        cursor.execute('''
            SELECT er.*, u.full_name as organization_name, c.name as category_name,
                   GROUP_CONCAT(s.name) as required_skills,
                   CASE WHEN er.district = ? THEN 1 ELSE 0 END as same_district
            FROM emergency_requests er
            JOIN users u ON er.organization_id = u.id
            JOIN categories c ON er.category_id = c.id
            LEFT JOIN request_skills rs ON er.id = rs.request_id
            LEFT JOIN skills s ON rs.skill_id = s.id
            WHERE er.status IN ('approved', 'active') 
            AND er.is_approved = 1
            AND er.state = ?
            GROUP BY er.id
            ORDER BY same_district DESC, 
                     CASE er.priority_level 
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                     END,
                     er.created_at DESC
            LIMIT 20
        ''', (volunteer['district'], volunteer['state']))
        
        requests = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'requests': [dict(req) for req in requests]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get nearby requests', 'details': str(e)}), 500

@volunteer_bp.route('/state-requests', methods=['GET'])
@jwt_required()
def get_state_requests():
    """Get emergency requests in volunteer's state with optional priority filter"""
    try:
        user_id = get_current_user_id()
        priority_filter = request.args.get('priority')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Get volunteer location
        cursor.execute('SELECT state, district FROM users WHERE id = ?', (user_id,))
        volunteer = cursor.fetchone()
        
        if not volunteer or not volunteer['state']:
            conn.close()
            return jsonify({'requests': []}), 200
        
        # Build query with optional priority filter
        query = '''
            SELECT er.*, u.full_name as organization_name, c.name as category_name,
                   GROUP_CONCAT(s.name) as required_skills,
                   CASE WHEN er.district = ? THEN 1 ELSE 0 END as same_district
            FROM emergency_requests er
            JOIN users u ON er.organization_id = u.id
            JOIN categories c ON er.category_id = c.id
            LEFT JOIN request_skills rs ON er.id = rs.request_id
            LEFT JOIN skills s ON rs.skill_id = s.id
            WHERE er.status IN ('approved', 'active') 
            AND er.is_approved = 1
            AND er.state = ?
        '''
        
        params = [volunteer['district'], volunteer['state']]
        
        if priority_filter:
            query += ' AND er.priority_level = ?'
            params.append(priority_filter)
        
        query += '''
            GROUP BY er.id
            ORDER BY same_district DESC, 
                     CASE er.priority_level 
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                     END,
                     er.created_at DESC
            LIMIT 20
        '''
        
        cursor.execute(query, params)
        requests = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'requests': [dict(req) for req in requests]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get state requests', 'details': str(e)}), 500

@volunteer_bp.route('/suggest-skill', methods=['POST'])
@jwt_required()
def suggest_skill():
    """Volunteer suggests a new skill for admin approval"""
    try:
        user_id = get_current_user_id()
        data = request.get_json()
        
        skill_name = data.get('skill_name', '').strip()
        skill_description = data.get('skill_description', '').strip()
        category_option = data.get('category_option')  # 'existing' or 'new'
        category_id = data.get('category_id')
        category_name = data.get('category_name', '').strip()
        proficiency_level = data.get('proficiency_level')
        verification_notes = data.get('verification_notes', '').strip()
        
        if not skill_name or not proficiency_level:
            return jsonify({'error': 'Skill name and proficiency level are required'}), 400
        
        if category_option not in ['existing', 'new']:
            return jsonify({'error': 'Invalid category option'}), 400
        
        if category_option == 'existing' and not category_id:
            return jsonify({'error': 'Category ID is required for existing category'}), 400
        
        if category_option == 'new' and not category_name:
            return jsonify({'error': 'Category name is required for new category'}), 400
        
        if proficiency_level not in ['beginner', 'intermediate', 'expert']:
            return jsonify({'error': 'Invalid proficiency level'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is volunteer
        cursor.execute('SELECT user_type, full_name FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'volunteer':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Check if skill already exists
        cursor.execute('SELECT id FROM skills WHERE LOWER(name) = LOWER(?)', (skill_name,))
        existing_skill = cursor.fetchone()
        
        if existing_skill:
            conn.close()
            return jsonify({'error': 'This skill already exists in the system'}), 409
        
        # Handle category
        final_category_id = None
        category_details = ""
        
        if category_option == 'existing':
            # Verify category exists
            cursor.execute('SELECT id, name FROM categories WHERE id = ? AND type = "skill"', (category_id,))
            category = cursor.fetchone()
            if not category:
                conn.close()
                return jsonify({'error': 'Selected category not found'}), 404
            final_category_id = category_id
            category_details = f"Category: {category['name']}"
        else:
            # Check if category name already exists
            cursor.execute('SELECT id FROM categories WHERE LOWER(name) = LOWER(?) AND type = "skill"', (category_name,))
            existing_category = cursor.fetchone()
            
            if existing_category:
                conn.close()
                return jsonify({'error': 'This category already exists in the system'}), 409
            
            # Create new category suggestion
            cursor.execute('''
                INSERT INTO categories (name, type, description, created_by, is_approved)
                VALUES (?, ?, ?, ?, ?)
            ''', (category_name, 'skill', f'Suggested by volunteer: {user["full_name"]}', user_id, 0))
            
            final_category_id = cursor.lastrowid
            category_details = f"New Category: {category_name} (pending approval)"
        
        # Create skill suggestion
        cursor.execute('''
            INSERT INTO skills (name, category_id, description, created_by, is_approved)
            VALUES (?, ?, ?, ?, ?)
        ''', (skill_name, final_category_id, skill_description, user_id, 0))
        
        skill_id = cursor.lastrowid
        
        # Add the skill to user's profile (pending verification)
        cursor.execute('''
            INSERT INTO user_skills (user_id, skill_id, proficiency_level, verification_link, verification_notes, is_verified)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, skill_id, proficiency_level, verification_link, verification_notes, 0))
        
        # Log activity
        details = f'Skill: {skill_name}, {category_details}, Proficiency: {proficiency_level}'
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (user_id, 'skill_suggested', details, request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Skill suggestion submitted successfully',
            'skill_id': skill_id
        }), 201
        
    except Exception as e:
        return jsonify({'error': 'Failed to submit skill suggestion', 'details': str(e)}), 500

@volunteer_bp.route('/assignments/<int:assignment_id>/respond', methods=['PUT'])
@jwt_required()
def respond_to_assignment(assignment_id):
    """Volunteer responds to assignment (accept/decline)"""
    try:
        user_id = get_current_user_id()
        data = request.get_json()
        
        response = data.get('response')  # 'accepted' or 'declined'
        notes = data.get('notes', '')
        
        if response not in ['accepted', 'declined']:
            return jsonify({'error': 'Response must be "accepted" or "declined"'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if assignment exists and belongs to current user
        cursor.execute('''
            SELECT va.*, er.title as request_title
            FROM volunteer_assignments va
            JOIN emergency_requests er ON va.request_id = er.id
            WHERE va.id = ? AND va.volunteer_id = ?
        ''', (assignment_id, user_id))
        
        assignment = cursor.fetchone()
        if not assignment:
            conn.close()
            return jsonify({'error': 'Assignment not found'}), 404
        
        if assignment['status'] != 'assigned':
            conn.close()
            return jsonify({'error': 'Assignment already responded to'}), 400
        
        # Update assignment
        cursor.execute('''
            UPDATE volunteer_assignments 
            SET status = ?, responded_at = CURRENT_TIMESTAMP, notes = ?
            WHERE id = ?
        ''', (response, notes, assignment_id))
        
        # If declined, update request volunteers_assigned count
        if response == 'declined':
            cursor.execute('''
                UPDATE emergency_requests 
                SET volunteers_assigned = volunteers_assigned - 1
                WHERE id = ?
            ''', (assignment['request_id'],))
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (user_id, f'assignment_{response}', f'Assignment ID: {assignment_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': f'Assignment {response} successfully'
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to respond to assignment', 'details': str(e)}), 500

# Add this route for organizations to search volunteers by skill
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models.database import db
from utils.auth import get_current_user_id

@volunteer_bp.route('/by-skill/<int:skill_id>', methods=['GET'])
@jwt_required()
def get_volunteers_by_skill(skill_id):
    """Get volunteers who have a specific skill (for organizations)"""
    try:
        user_id = get_current_user_id()
        state_filter = request.args.get('state')
        district_filter = request.args.get('district')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is organization or admin
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] not in ['organization', 'admin']:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Build query to find volunteers with the specified skill
        query = '''
            SELECT DISTINCT u.id, u.full_name, u.email, u.phone, u.state, u.district,
                   us.proficiency_level, us.is_verified, s.name as skill_name,
                   u.created_at as joined_date
            FROM users u
            JOIN user_skills us ON u.id = us.user_id
            JOIN skills s ON us.skill_id = s.id
            WHERE u.user_type = 'volunteer' 
            AND us.skill_id = ? 
            AND us.is_verified = 1
            AND s.is_approved = 1
        '''
        
        params = [skill_id]
        
        if state_filter:
            query += ' AND u.state = ?'
            params.append(state_filter)
        
        if district_filter:
            query += ' AND u.district = ?'
            params.append(district_filter)
        
        query += ' ORDER BY us.proficiency_level DESC, u.full_name ASC'
        
        cursor.execute(query, params)
        volunteers = cursor.fetchall()
        
        # Get skill name for reference
        cursor.execute('SELECT name FROM skills WHERE id = ?', (skill_id,))
        skill = cursor.fetchone()
        
        conn.close()
        
        return jsonify({
            'volunteers': [dict(vol) for vol in volunteers],
            'skill_name': skill['name'] if skill else 'Unknown Skill',
            'total_count': len(volunteers)
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get volunteers by skill', 'details': str(e)}), 500