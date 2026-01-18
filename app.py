from flask import Flask, jsonify, render_template
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from config import Config
from models.database import db
from routes.auth import auth_bp
from routes.skills import skills_bp
from routes.emergency import emergency_bp
from routes.volunteer import volunteer_bp
from routes.organization import organization_bp
from routes.admin import admin_bp
from swagger_docs import swagger_bp
import os

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config.from_object(Config)
    
    # Explicitly set JWT configuration
    app.config['JWT_SECRET_KEY'] = Config.JWT_SECRET_KEY
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = Config.JWT_ACCESS_TOKEN_EXPIRES
    
    # Initialize extensions
    jwt = JWTManager(app)
    CORS(app)
    
    # Create upload directory
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(skills_bp, url_prefix='/api')
    app.register_blueprint(emergency_bp, url_prefix='/api/emergency')
    app.register_blueprint(volunteer_bp, url_prefix='/api/volunteer')
    app.register_blueprint(organization_bp, url_prefix='/api/organization')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    
    # Register Swagger documentation
    app.register_blueprint(swagger_bp, url_prefix='/api-docs')
    
    # JWT error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({'error': 'Token has expired'}), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({'error': 'Invalid token'}), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({'error': 'Authorization token is required'}), 401
    
    # Routes
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/login')
    def login_page():
        return render_template('login.html')
    
    @app.route('/register')
    def register_page():
        return render_template('register.html')
    
    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html')
    
    @app.route('/volunteer-dashboard')
    def volunteer_dashboard():
        return render_template('volunteer_dashboard.html')
    
    @app.route('/organization-dashboard')
    def organization_dashboard():
        return render_template('organization_dashboard.html')
    
    @app.route('/admin-dashboard')
    def admin_dashboard():
        return render_template('admin_dashboard.html')
    
    @app.route('/emergency')
    def emergency_page():
        return render_template('emergency.html')
    
    @app.route('/skills')
    def skills_page():
        return render_template('skills.html')
    
    @app.route('/manage-users')
    def manage_users_page():
        return render_template('manage_users.html')
    
    @app.route('/manage-organizations')
    def manage_organizations_page():
        return render_template('manage_organizations.html')
    
    @app.route('/system-reports')
    def system_reports_page():
        return render_template('system_reports.html')
    
    @app.route('/my-applications')
    def my_applications_page():
        return render_template('my_applications.html')
    
    @app.route('/api/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'message': 'Citizen Skill Volunteering Platform API is running'
        }), 200
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Resource not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    # Get port from environment (Render sets this automatically)
    port = int(os.environ.get('PORT', Config.PORT))
    
    print("🚀 Starting Citizen Skill Volunteering & Emergency Response Platform")
    print(f"📍 Server running on {Config.HOST}:{port}")
    print("🔧 Debug mode:", Config.DEBUG)
    print("💡 To initialize database, run: python init_db.py")
    
    app.run(
        host=Config.HOST,
        port=port,
        debug=Config.DEBUG
    )