// Authentication utilities
class AuthManager {
    constructor() {
        this.token = localStorage.getItem('token');
        this.user = this.getUser();
        this.updateNavigation();
    }
    
    getToken() {
        if (!this.token) {
            this.token = localStorage.getItem('token');
        }
        return this.token;
    }
    
    getUser() {
        const userStr = localStorage.getItem('user');
        return userStr ? JSON.parse(userStr) : null;
    }
    
    isAuthenticated() {
        const token = this.getToken();
        const user = this.getUser();
        return !!token && !!user;
    }
    
    login(token, user) {
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(user));
        this.token = token;
        this.user = user;
        this.updateNavigation();
    }
    
    logout() {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        this.token = null;
        this.user = null;
        this.updateNavigation();
        window.location.href = '/';
    }
    
    updateNavigation() {
        const loginLink = document.getElementById('loginLink');
        const registerLink = document.getElementById('registerLink');
        const logoutLink = document.getElementById('logoutLink');
        const dashboardLink = document.getElementById('dashboardLink');
        const emergencyLink = document.getElementById('emergencyLink');
        const skillsLink = document.getElementById('skillsLink');
        
        if (this.isAuthenticated()) {
            // Hide login/register, show authenticated links
            if (loginLink) loginLink.style.display = 'none';
            if (registerLink) registerLink.style.display = 'none';
            if (logoutLink) logoutLink.style.display = 'block';
            if (dashboardLink) dashboardLink.style.display = 'block';
            if (emergencyLink) emergencyLink.style.display = 'block';
            if (skillsLink) skillsLink.style.display = 'block';
        } else {
            // Show login/register, hide authenticated links
            if (loginLink) loginLink.style.display = 'block';
            if (registerLink) registerLink.style.display = 'block';
            if (logoutLink) logoutLink.style.display = 'none';
            if (dashboardLink) dashboardLink.style.display = 'none';
            if (emergencyLink) emergencyLink.style.display = 'none';
            if (skillsLink) skillsLink.style.display = 'none';
        }
    }
    
    async makeAuthenticatedRequest(url, options = {}) {
        const token = this.getToken();
        if (!token) {
            console.error('No authentication token available');
            this.logout();
            throw new Error('No authentication token available');
        }
        
        const headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            ...(options.headers || {})
        };
        
        const requestOptions = {
            ...options,
            headers
        };
        
        console.log('Making authenticated request to:', url, 'with token:', token.substring(0, 20) + '...');
        
        const response = await fetch(url, requestOptions);
        
        // Handle token expiration
        if (response.status === 401) {
            console.error('Authentication failed - token expired or invalid');
            this.logout();
            throw new Error('Authentication expired');
        }
        
        return response;
    }
    
    requireAuth() {
        if (!this.isAuthenticated()) {
            console.log('Authentication required - redirecting to login');
            window.location.href = '/login';
            return false;
        }
        return true;
    }
    
    requireUserType(allowedTypes) {
        if (!this.requireAuth()) return false;
        
        const user = this.getUser();
        if (!allowedTypes.includes(user.user_type)) {
            showNotification('Access denied: Insufficient permissions', 'error');
            return false;
        }
        return true;
    }
}

// Global auth manager instance
const auth = new AuthManager();

// Global logout function
function logout() {
    auth.logout();
}

// Check authentication on protected pages
function checkAuth() {
    console.log('Checking authentication...');
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    
    console.log('Token exists:', !!token);
    console.log('User exists:', !!user);
    
    if (!token || !user) {
        console.log('No token or user found, redirecting to login');
        window.location.href = '/login';
        return false;
    }
    
    // Update auth manager
    auth.token = token;
    auth.user = JSON.parse(user);
    
    console.log('Authentication successful');
    return true;
}

// Utility function for making authenticated API calls
async function apiCall(url, options = {}) {
    try {
        return await auth.makeAuthenticatedRequest(url, options);
    } catch (error) {
        console.error('API call failed:', error);
        throw error;
    }
}

// Initialize auth on page load
document.addEventListener('DOMContentLoaded', function() {
    // Update navigation based on auth state
    auth.updateNavigation();
    
    // Check if current page requires authentication
    const protectedPages = ['/dashboard', '/emergency', '/skills'];
    const currentPath = window.location.pathname;
    
    if (protectedPages.includes(currentPath)) {
        checkAuth();
    }
    
    // Redirect authenticated users away from login/register pages
    if ((currentPath === '/login' || currentPath === '/register') && auth.isAuthenticated()) {
        window.location.href = '/dashboard';
    }
});