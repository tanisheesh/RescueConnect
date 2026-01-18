from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models.database import db
from utils.auth import get_current_user_id

organization_bp = Blueprint('organization', __name__)

@organization_bp.route('/applications', methods=['GET'])
@jwt_required()
def get_organization_applications():
    """Get applications for organization's requests"""
    try:
        user_id = get_current_user_id()
        status_filter = request.args.get('status')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is organization
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'organization':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Build query with optional status filter
        query = '''
            SELECT va.*, u.full_name as volunteer_name, u.email as volunteer_email,
                   u.phone as volunteer_phone, u.state as volunteer_state, u.district as volunteer_district,
                   er.title as request_title, er.priority_level
            FROM volunteer_applications va
            JOIN users u ON va.volunteer_id = u.id
            JOIN emergency_requests er ON va.request_id = er.id
            WHERE er.organization_id = ?
        '''
        params = [user_id]
        
        if status_filter:
            query += ' AND va.status = ?'
            params.append(status_filter)
        
        query += ' ORDER BY va.applied_at DESC'
        
        cursor.execute(query, params)
        applications = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'applications': [dict(app) for app in applications]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get applications', 'details': str(e)}), 500

@organization_bp.route('/assignments', methods=['GET'])
@jwt_required()
def get_organization_assignments():
    """Get assignments for organization's requests"""
    try:
        user_id = get_current_user_id()
        status_filter = request.args.get('status')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is organization
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'organization':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Build query with optional status filter
        query = '''
            SELECT va.*, u.full_name as volunteer_name, u.email as volunteer_email,
                   u.phone as volunteer_phone, u.state as volunteer_state, u.district as volunteer_district,
                   er.title as request_title, er.priority_level
            FROM volunteer_assignments va
            JOIN users u ON va.volunteer_id = u.id
            JOIN emergency_requests er ON va.request_id = er.id
            WHERE er.organization_id = ?
        '''
        params = [user_id]
        
        if status_filter:
            query += ' AND va.status = ?'
            params.append(status_filter)
        
        query += ' ORDER BY va.assigned_at DESC'
        
        cursor.execute(query, params)
        assignments = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'assignments': [dict(assignment) for assignment in assignments]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get assignments', 'details': str(e)}), 500

@organization_bp.route('/request-volunteers/<int:request_id>', methods=['GET'])
@jwt_required()
def get_request_volunteers(request_id):
    """Get volunteers for a specific request"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is organization and owns the request
        cursor.execute('''
            SELECT * FROM emergency_requests 
            WHERE id = ? AND organization_id = ?
        ''', (request_id, user_id))
        
        request_data = cursor.fetchone()
        if not request_data:
            conn.close()
            return jsonify({'error': 'Request not found or access denied'}), 404
        
        # Get volunteers who applied to this request
        cursor.execute('''
            SELECT va.*, u.full_name as volunteer_name, u.email as volunteer_email,
                   u.phone as volunteer_phone, u.state as volunteer_state, u.district as volunteer_district
            FROM volunteer_applications va
            JOIN users u ON va.volunteer_id = u.id
            WHERE va.request_id = ?
            ORDER BY va.applied_at DESC
        ''', (request_id,))
        
        volunteers = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'request': dict(request_data),
            'volunteers': [dict(vol) for vol in volunteers]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get request volunteers', 'details': str(e)}), 500

@organization_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_organization_stats():
    """Get statistics for organization"""
    try:
        user_id = get_current_user_id()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if user is organization
        cursor.execute('SELECT user_type FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user or user['user_type'] != 'organization':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        # Get total requests
        cursor.execute('''
            SELECT COUNT(*) as total FROM emergency_requests WHERE organization_id = ?
        ''', (user_id,))
        total_requests = cursor.fetchone()['total']
        
        # Get approved requests
        cursor.execute('''
            SELECT COUNT(*) as total FROM emergency_requests 
            WHERE organization_id = ? AND is_approved = 1
        ''', (user_id,))
        approved_requests = cursor.fetchone()['total']
        
        # Get pending requests
        cursor.execute('''
            SELECT COUNT(*) as total FROM emergency_requests 
            WHERE organization_id = ? AND is_approved = 0 AND status = 'pending'
        ''', (user_id,))
        pending_requests = cursor.fetchone()['total']
        
        # Get total applications
        cursor.execute('''
            SELECT COUNT(*) as total FROM volunteer_applications va
            JOIN emergency_requests er ON va.request_id = er.id
            WHERE er.organization_id = ?
        ''', (user_id,))
        total_applications = cursor.fetchone()['total']
        
        # Get pending applications
        cursor.execute('''
            SELECT COUNT(*) as total FROM volunteer_applications va
            JOIN emergency_requests er ON va.request_id = er.id
            WHERE er.organization_id = ? AND va.status = 'pending'
        ''', (user_id,))
        pending_applications = cursor.fetchone()['total']
        
        # Calculate average response time (simplified)
        cursor.execute('''
            SELECT AVG(
                CASE 
                    WHEN va.responded_at IS NOT NULL 
                    THEN (julianday(va.responded_at) - julianday(va.applied_at)) * 24
                    ELSE NULL 
                END
            ) as avg_response_hours
            FROM volunteer_applications va
            JOIN emergency_requests er ON va.request_id = er.id
            WHERE er.organization_id = ?
        ''', (user_id,))
        
        result = cursor.fetchone()
        avg_response_time = result['avg_response_hours'] if result['avg_response_hours'] else 0
        
        conn.close()
        
        return jsonify({
            'stats': {
                'totalRequests': total_requests,
                'approvedRequests': approved_requests,
                'pendingRequests': pending_requests,
                'totalApplications': total_applications,
                'pendingApplications': pending_applications,
                'avgResponseTime': f"{avg_response_time:.1f}h" if avg_response_time else "0h"
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get stats', 'details': str(e)}), 500