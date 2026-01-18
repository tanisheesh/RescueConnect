# 🚨 Rescue Connect

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-v2.3.3-green.svg)
![SQLite](https://img.shields.io/badge/sqlite-v3-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

A web application that connects volunteers with emergency response organizations during disasters. Match skills with needs, coordinate responses, and manage emergency requests efficiently.

## ✨ Features

- **Multi-role System**: Volunteers, Organizations, and Admins
- **Skill Matching**: Connect volunteers with required emergency skills  
- **Emergency Requests**: Organizations post and manage emergency needs
- **Location-based**: State and district-wise coordination
- **Real-time Applications**: Instant volunteer response system
- **Admin Dashboard**: Complete system management and analytics

## 🚀 Quick Setup

### Install & Run
```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database
python init_db.py

# Start application
python app.py
```

Visit: `http://localhost:5000`

### Demo Accounts
```
Admin:        admin@emergency.gov / admin123!
Organization: disaster@redcross.org / org123!
Volunteer:    john.doe@email.com / volunteer123!
```

## 🔧 Tech Stack

![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Bootstrap](https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white)

- **Backend**: Flask, SQLite, JWT Authentication
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Security**: bcrypt, Input validation, Role-based access

## 📱 Main Pages

- **Dashboard**: Role-specific home pages
- **Emergency Requests**: Browse and apply for emergencies
- **Skills Management**: Add and verify volunteer skills
- **Admin Panel**: User management and system reports
- **Profile**: Manage personal information and verification

## 🗂️ Project Structure

```
├── app.py              # Main application
├── config.py           # Configuration
├── init_db.py          # Database setup
├── routes/             # API endpoints
├── models/             # Database models
├── templates/          # HTML pages
├── static/             # CSS, JS, assets
└── utils/              # Helper functions
```

## 🔌 Key API Endpoints

```
POST /api/auth/login           # User login
POST /api/auth/register        # User registration
GET  /api/emergency/requests   # List emergencies
POST /api/emergency/requests   # Create emergency
GET  /api/skills               # List skills
POST /api/user/skills          # Add user skill
GET  /api/admin/stats          # System statistics
```

## 🎯 User Roles

**Volunteers**
- Register and verify skills
- Browse emergency requests
- Apply for relevant emergencies
- Track assignments and applications

**Organizations**
- Create emergency requests
- Review volunteer applications
- Manage assignments
- Track response metrics

**Admins**
- Approve user registrations
- Manage skills and categories
- System monitoring and reports
- Content moderation

## 🔒 Security

- JWT token authentication
- Password hashing with bcrypt
- Role-based access control
- Input validation and sanitization

## 📊 Database

Core tables: `users`, `emergency_requests`, `skills`, `categories`, `user_skills`, `volunteer_applications`, `volunteer_assignments`

## 🚀 Production Setup

1. Set environment variables in `.env`
2. Change default passwords
3. Use production database
4. Configure web server (Nginx/Apache)
5. Enable HTTPS

---

**Rescue Connect** - Connecting communities in times of need