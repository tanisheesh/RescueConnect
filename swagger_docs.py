"""
Swagger Documentation using Flask-RESTX
Proxies requests to actual API endpoints
"""

from flask import Blueprint, request, jsonify
from flask_restx import Api, Resource, fields
import requests

# Create blueprint for Swagger docs
swagger_bp = Blueprint('swagger', __name__)

# Initialize Flask-RESTX API
api = Api(
    swagger_bp,
    version='1.0',
    title='Citizen Emergency Response Platform API',
    description='Complete API documentation for Emergency Response Platform with Indian state-based volunteer coordination system',
    doc='/docs/',
    authorizations={
        'Bearer': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'JWT Authorization header. Example: "Bearer {token}"'
        }
    },
    security='Bearer'
)

# Define namespaces
auth_ns = api.namespace('auth', description='Authentication operations')
admin_ns = api.namespace('admin', description='Admin operations')
skills_ns = api.namespace('skills', description='Skills management')
emergency_ns = api.namespace('emergency', description='Emergency requests')

# Define models
user_login_model = api.model('UserLogin', {
    'email': fields.String(required=True, description='User email', example='admin@emergency.gov'),
    'password': fields.String(required=True, description='Password', example='admin123!')
})

# Helper function to proxy requests to actual API
def proxy_request(method, endpoint, data=None, headers=None):
    """Proxy request to actual API endpoint"""
    base_url = request.host_url.rstrip('/')
    url = f"{base_url}/api{endpoint}"
    
    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=10)
        elif method.upper() == 'POST':
            response = requests.post(url, json=data, headers=headers, timeout=10)
        elif method.upper() == 'PUT':
            response = requests.put(url, json=data, headers=headers, timeout=10)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=headers, timeout=10)
        
        return response.json(), response.status_code
    except Exception as e:
        return {'error': f'Request failed: {str(e)}'}, 500

# Authentication endpoints
@auth_ns.route('/login')
class UserLogin(Resource):
    @api.expect(user_login_model)
    @api.doc('login_user', description='Login user and get real JWT token')
    def post(self):
        """Login user and receive actual JWT token"""
        data = request.get_json()
        result, status_code = proxy_request('POST', '/auth/login', data)
        return result, status_code

@auth_ns.route('/profile')
class UserProfile(Resource):
    @api.doc('get_profile', security='Bearer', description='Get current user profile')
    def get(self):
        """Get current user profile"""
        headers = {}
        if request.headers.get('Authorization'):
            headers['Authorization'] = request.headers.get('Authorization')
        result, status_code = proxy_request('GET', '/auth/profile', headers=headers)
        return result, status_code

# Emergency endpoints
@emergency_ns.route('/states')
class IndianStates(Resource):
    @api.doc('get_states', description='Get list of all Indian states and union territories')
    def get(self):
        """Get all Indian states and union territories"""
        result, status_code = proxy_request('GET', '/emergency/states')
        return result, status_code

# Skills endpoints
@skills_ns.route('/skills')
class Skills(Resource):
    @api.doc('get_skills', description='Get all approved skills grouped by categories')
    def get(self):
        """Get all approved skills"""
        result, status_code = proxy_request('GET', '/skills')
        return result, status_code

# Admin endpoints
@admin_ns.route('/stats')
class AdminStats(Resource):
    @api.doc('get_admin_stats', security='Bearer', description='Get system statistics (admin only)')
    def get(self):
        """Get system statistics"""
        headers = {}
        if request.headers.get('Authorization'):
            headers['Authorization'] = request.headers.get('Authorization')
        result, status_code = proxy_request('GET', '/admin/stats', headers=headers)
        return result, status_code

# Health check
@api.route('/health')
class HealthCheck(Resource):
    @api.doc('health_check', description='API health check')
    def get(self):
        """Check API health status"""
        result, status_code = proxy_request('GET', '/health')
        return result, status_code