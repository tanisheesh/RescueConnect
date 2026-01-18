from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models.database import db
from utils.location import get_indian_states
import sqlite3
from utils.auth import get_current_user_id

emergency_bp = Blueprint('emergency', __name__)

@emergency_bp.route('/states', methods=['GET'])
def get_states():
    """Get list of Indian states"""
    try:
        states = get_indian_states()
        return jsonify({
            'states': states
        }), 200
    except Exception as e:
        return jsonify({'error': 'Failed to get states', 'details': str(e)}), 500

@emergency_bp.route('/requests', methods=['POST'])
@jwt_required()
def create_emergency_request():
    """Create a new emergency request (organizations only)"""
    try:
        user_id = get_current_user_id()
        data = request.get_json()
        
        # Check if user is organization
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'organization':
            conn.close()
            return jsonify({'error': 'Only organizations can create emergency requests'}), 403
        
        # Validate required fields
        required_fields = ['title', 'description', 'category_id', 'state', 'district', 'priority_level']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        title = data['title'].strip()
        description = data['description'].strip()
        category_id = data['category_id']
        state = data['state'].strip()
        district = data['district'].strip()
        priority_level = data['priority_level']
        volunteers_needed = data.get('volunteers_needed', 1)
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        required_skills = data.get('required_skills', [])  # List of skill IDs
        
        # Validate priority level
        if priority_level not in ['low', 'medium', 'high', 'critical']:
            return jsonify({'error': 'Invalid priority level'}), 400
        
        # Check if category exists and is approved
        cursor.execute('SELECT id FROM categories WHERE id = ? AND is_approved = 1 AND type = "disaster"', (category_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Invalid or unapproved disaster category'}), 400
        
        # Create emergency request (pending approval)
        cursor.execute('''
            INSERT INTO emergency_requests 
            (title, description, organization_id, category_id, state, district, 
             priority_level, volunteers_needed, start_time, end_time, status, is_approved)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, description, user_id, category_id, state, district, 
              priority_level, volunteers_needed, start_time, end_time, 'pending', False))
        
        request_id = cursor.lastrowid
        
        # Add required skills
        for skill_id in required_skills:
            # Verify skill exists and is approved
            cursor.execute('SELECT id FROM skills WHERE id = ? AND is_approved = 1', (skill_id,))
            if cursor.fetchone():
                cursor.execute('''
                    INSERT INTO request_skills (request_id, skill_id, required_proficiency)
                    VALUES (?, ?, ?)
                ''', (request_id, skill_id, 'intermediate'))  # Default proficiency
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (user_id, 'emergency_request_created', f'Request ID: {request_id}, Priority: {priority_level}, Status: pending approval', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Emergency request created successfully and is pending admin approval',
            'request_id': request_id
        }), 201
        
    except Exception as e:
        return jsonify({'error': 'Failed to create emergency request', 'details': str(e)}), 500

@emergency_bp.route('/requests', methods=['GET'])
@jwt_required()
def get_emergency_requests():
    """Get emergency requests based on user type"""
    try:
        user_id = get_current_user_id()
        category_filter = request.args.get('category')
        state_filter = request.args.get('state')
        district_filter = request.args.get('district')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Get user type
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        # Base query for approved requests
        base_query = '''
            SELECT er.*, u.full_name as organization_name, c.name as category_name,
                   GROUP_CONCAT(s.name) as required_skills
            FROM emergency_requests er
            JOIN users u ON er.organization_id = u.id
            JOIN categories c ON er.category_id = c.id
            LEFT JOIN request_skills rs ON er.id = rs.request_id
            LEFT JOIN skills s ON rs.skill_id = s.id
            WHERE er.is_approved = 1
        '''
        params = []
        
        # Query based on user type
        if user['user_type'] == 'volunteer':
            # For volunteers, show approved active requests
            base_query += ' AND er.status IN ("approved", "active")'
        elif user['user_type'] == 'organization':
            # For organizations, show their own requests (all statuses)
            base_query += ' AND er.organization_id = ?'
            params.append(user_id)
        else:  # admin
            # For admin, show all requests
            pass
        
        # Add filters
        if category_filter:
            base_query += ' AND er.category_id = ?'
            params.append(category_filter)
        
        if state_filter:
            base_query += ' AND er.state = ?'
            params.append(state_filter)
        
        if district_filter:
            base_query += ' AND er.district = ?'
            params.append(district_filter)
        
        base_query += '''
            GROUP BY er.id
            ORDER BY 
                CASE er.priority_level 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END,
                er.created_at DESC
        '''
        
        cursor.execute(base_query, params)
        requests = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'requests': [dict(req) for req in requests],
            'total_requests': len(requests)
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get emergency requests', 'details': str(e)}), 500

@emergency_bp.route('/requests/<int:request_id>', methods=['GET'])
@jwt_required()
def get_emergency_request(request_id):
    """Get specific emergency request details"""
    try:
        user_id = get_current_user_id()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Get request details with required skills
        cursor.execute('''
            SELECT er.*, u.full_name as organization_name, u.email as organization_email,
                   c.name as category_name
            FROM emergency_requests er
            JOIN users u ON er.organization_id = u.id
            JOIN categories c ON er.category_id = c.id
            WHERE er.id = ?
        ''', (request_id,))
        
        request_data = cursor.fetchone()
        
        if not request_data:
            conn.close()
            return jsonify({'error': 'Emergency request not found'}), 404
        
        # Check if current user has already applied (for volunteers)
        user_application = None
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if user and user['user_type'] == 'volunteer':
            cursor.execute('''
                SELECT * FROM volunteer_applications 
                WHERE request_id = ? AND volunteer_id = ?
            ''', (request_id, user_id))
            user_application = cursor.fetchone()
        
        # Get required skills separately
        cursor.execute('''
            SELECT s.id, s.name, rs.required_proficiency
            FROM request_skills rs
            JOIN skills s ON rs.skill_id = s.id
            WHERE rs.request_id = ? AND s.is_approved = 1
        ''', (request_id,))
        
        required_skills = cursor.fetchall()
        
        # Get volunteer applications
        cursor.execute('''
            SELECT va.*, u.full_name, u.email, u.phone, u.state, u.district
            FROM volunteer_applications va
            JOIN users u ON va.volunteer_id = u.id
            WHERE va.request_id = ?
            ORDER BY va.applied_at DESC
        ''', (request_id,))
        
        applications = cursor.fetchall()
        
        # Get assigned volunteers
        cursor.execute('''
            SELECT vas.*, u.full_name, u.email, u.phone, u.state, u.district
            FROM volunteer_assignments vas
            JOIN users u ON vas.volunteer_id = u.id
            WHERE vas.request_id = ?
            ORDER BY vas.assigned_at DESC
        ''', (request_id,))
        
        assignments = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'request': dict(request_data),
            'required_skills': [dict(skill) for skill in required_skills],
            'applications': [dict(app) for app in applications],
            'assignments': [dict(assignment) for assignment in assignments],
            'user_application': dict(user_application) if user_application else None
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get emergency request', 'details': str(e)}), 500

@emergency_bp.route('/requests/<int:request_id>/interest', methods=['POST'])
@jwt_required()
def express_interest(request_id):
    """Volunteer expresses interest in emergency request"""
    try:
        user_id = get_current_user_id()
        data = request.get_json()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is volunteer and approved
        cursor.execute('SELECT user_type, verification_status FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'volunteer':
            conn.close()
            return jsonify({'error': 'Only volunteers can express interest'}), 403
        
        if user['verification_status'] != 'approved':
            conn.close()
            return jsonify({'error': 'Your account must be approved to express interest'}), 403
        
        # Check if request exists and is approved
        cursor.execute('''
            SELECT id, status, required_skills FROM emergency_requests er
            LEFT JOIN (
                SELECT request_id, GROUP_CONCAT(skill_id) as required_skills
                FROM request_skills 
                GROUP BY request_id
            ) rs ON er.id = rs.request_id
            WHERE er.id = ? AND er.is_approved = 1 AND er.status IN ('approved', 'active')
        ''', (request_id,))
        
        request_data = cursor.fetchone()
        if not request_data:
            conn.close()
            return jsonify({'error': 'Request not found or not available for applications'}), 404
        
        # Check if volunteer has required skills (if any)
        if request_data['required_skills']:
            required_skill_ids = [int(x) for x in request_data['required_skills'].split(',')]
            
            # Get volunteer's approved skills
            cursor.execute('''
                SELECT skill_id FROM user_skills us
                JOIN skills s ON us.skill_id = s.id
                WHERE us.user_id = ? AND us.is_verified = 1 AND s.is_approved = 1
            ''', (user_id,))
            
            volunteer_skills = [row['skill_id'] for row in cursor.fetchall()]
            
            # Check if volunteer has at least one required skill
            has_required_skill = any(skill_id in volunteer_skills for skill_id in required_skill_ids)
            
            if not has_required_skill:
                conn.close()
                return jsonify({
                    'error': 'You do not have the required skills for this emergency request. Please add and verify the required skills first.'
                }), 400
        
        message = data.get('message', 'I am interested in volunteering for this emergency request.')
        
        try:
            cursor.execute('''
                INSERT INTO volunteer_applications (request_id, volunteer_id, message, status)
                VALUES (?, ?, ?, 'pending')
            ''', (request_id, user_id, message))
            
            application_id = cursor.lastrowid
            
            # Log activity
            cursor.execute('''
                INSERT INTO activity_logs (user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (user_id, 'volunteer_interest_expressed', f'Request ID: {request_id}', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'message': 'Interest expressed successfully! The organization will review your application.',
                'application_id': application_id
            }), 201
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'You have already expressed interest in this request'}), 409
        
    except Exception as e:
        return jsonify({'error': 'Failed to express interest', 'details': str(e)}), 500

@emergency_bp.route('/applications/<int:application_id>/respond', methods=['PUT'])
@jwt_required()
def respond_to_application(application_id):
    """Organization responds to volunteer application"""
    try:
        user_id = get_current_user_id()
        data = request.get_json()
        
        response = data.get('response')  # 'approved' or 'rejected'
        response_message = data.get('response_message', '')
        
        if response not in ['approved', 'rejected']:
            return jsonify({'error': 'Response must be "approved" or "rejected"'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if application exists and user has permission
        cursor.execute('''
            SELECT va.*, er.organization_id, er.volunteers_needed, er.volunteers_assigned
            FROM volunteer_applications va
            JOIN emergency_requests er ON va.request_id = er.id
            WHERE va.id = ?
        ''', (application_id,))
        
        application = cursor.fetchone()
        if not application:
            conn.close()
            return jsonify({'error': 'Application not found'}), 404
        
        # Check if user is the organization that owns the request
        if application['organization_id'] != user_id:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        if application['status'] != 'pending':
            conn.close()
            return jsonify({'error': 'Application already responded to'}), 400
        
        # Update application
        cursor.execute('''
            UPDATE volunteer_applications 
            SET status = ?, responded_at = CURRENT_TIMESTAMP, response_message = ?
            WHERE id = ?
        ''', (response, response_message, application_id))
        
        # If approved, create assignment
        if response == 'approved':
            try:
                cursor.execute('''
                    INSERT INTO volunteer_assignments (request_id, volunteer_id, status)
                    VALUES (?, ?, 'assigned')
                ''', (application['request_id'], application['volunteer_id']))
                
                # Update volunteers_assigned count
                cursor.execute('''
                    UPDATE emergency_requests 
                    SET volunteers_assigned = volunteers_assigned + 1,
                        status = CASE 
                            WHEN volunteers_assigned + 1 >= volunteers_needed THEN 'active'
                            ELSE status
                        END
                    WHERE id = ?
                ''', (application['request_id'],))
                
            except sqlite3.IntegrityError:
                # Volunteer already assigned
                pass
        
        # Log activity
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (user_id, f'application_{response}', f'Application ID: {application_id}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': f'Application {response} successfully'
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to respond to application', 'details': str(e)}), 500