// Main JavaScript utilities and functions

// Notification system
function showNotification(message, type = 'info', duration = 5000) {
    const notification = document.getElementById('notification');
    if (!notification) return;
    
    notification.textContent = message;
    notification.className = `notification ${type}`;
    
    // Show notification
    setTimeout(() => {
        notification.classList.add('show');
    }, 100);
    
    // Hide notification after duration
    setTimeout(() => {
        notification.classList.remove('show');
    }, duration);
}

// Mobile navigation toggle
document.addEventListener('DOMContentLoaded', function() {
    const navToggle = document.getElementById('navToggle');
    const navMenu = document.getElementById('navMenu');
    
    if (navToggle && navMenu) {
        navToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');
        });
    }
});

// Form validation utilities
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePassword(password) {
    const errors = [];
    
    if (password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }
    
    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/\d/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    
    return errors;
}

// Loading state management
function setLoading(element, isLoading, originalText = '') {
    if (isLoading) {
        element.disabled = true;
        element.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
    } else {
        element.disabled = false;
        element.innerHTML = originalText;
    }
}

// Date formatting utilities
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatRelativeTime(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);
    
    if (diffInSeconds < 60) {
        return 'Just now';
    } else if (diffInSeconds < 3600) {
        const minutes = Math.floor(diffInSeconds / 60);
        return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    } else if (diffInSeconds < 86400) {
        const hours = Math.floor(diffInSeconds / 3600);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    } else {
        const days = Math.floor(diffInSeconds / 86400);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }
}

// Distance calculation utilities
function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; // Radius of the Earth in kilometers
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = 
        Math.sin(dLat/2) * Math.sin(dLat/2) +
        Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
        Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    const distance = R * c;
    return distance;
}

function formatDistance(distanceKm) {
    if (distanceKm < 1) {
        return `${Math.round(distanceKm * 1000)}m`;
    } else {
        return `${distanceKm.toFixed(1)}km`;
    }
}

// Geolocation utilities
function getCurrentLocation() {
    return new Promise((resolve, reject) => {
        if (!navigator.geolocation) {
            reject(new Error('Geolocation is not supported by this browser'));
            return;
        }
        
        navigator.geolocation.getCurrentPosition(
            (position) => {
                resolve({
                    latitude: position.coords.latitude,
                    longitude: position.coords.longitude
                });
            },
            (error) => {
                let message = 'Unable to get location';
                switch(error.code) {
                    case error.PERMISSION_DENIED:
                        message = 'Location access denied by user';
                        break;
                    case error.POSITION_UNAVAILABLE:
                        message = 'Location information unavailable';
                        break;
                    case error.TIMEOUT:
                        message = 'Location request timed out';
                        break;
                }
                reject(new Error(message));
            },
            {
                enableHighAccuracy: true,
                timeout: 10000,
                maximumAge: 300000 // 5 minutes
            }
        );
    });
}

// Priority level utilities
function getPriorityColor(priority) {
    const colors = {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#28a745'
    };
    return colors[priority] || '#6c757d';
}

function getPriorityIcon(priority) {
    const icons = {
        'critical': 'fas fa-exclamation-triangle',
        'high': 'fas fa-exclamation-circle',
        'medium': 'fas fa-info-circle',
        'low': 'fas fa-check-circle'
    };
    return icons[priority] || 'fas fa-circle';
}

// Skill category utilities
function getSkillCategoryIcon(category) {
    const icons = {
        'Healthcare': 'fas fa-heartbeat',
        'Emergency Response': 'fas fa-ambulance',
        'Construction': 'fas fa-hard-hat',
        'Technical': 'fas fa-cogs',
        'Communication': 'fas fa-comments',
        'Management': 'fas fa-users-cog',
        'Support': 'fas fa-hands-helping',
        'Logistics': 'fas fa-truck'
    };
    return icons[category] || 'fas fa-certificate';
}

// Error handling utilities
function handleApiError(error, defaultMessage = 'An error occurred') {
    console.error('API Error:', error);
    
    if (error.message === 'Authentication expired') {
        showNotification('Session expired. Please log in again.', 'error');
        return;
    }
    
    if (error.message === 'Network error') {
        showNotification('Network error. Please check your connection.', 'error');
        return;
    }
    
    showNotification(defaultMessage, 'error');
}

// Debounce utility for search inputs
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Local storage utilities with error handling
function safeLocalStorageGet(key, defaultValue = null) {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : defaultValue;
    } catch (error) {
        console.error('Error reading from localStorage:', error);
        return defaultValue;
    }
}

function safeLocalStorageSet(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
        return true;
    } catch (error) {
        console.error('Error writing to localStorage:', error);
        return false;
    }
}

// Copy to clipboard utility
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showNotification('Copied to clipboard!', 'success', 2000);
    } catch (error) {
        console.error('Failed to copy to clipboard:', error);
        showNotification('Failed to copy to clipboard', 'error');
    }
}

// Initialize tooltips and other UI enhancements
document.addEventListener('DOMContentLoaded', function() {
    // Add click handlers for copy buttons
    document.querySelectorAll('[data-copy]').forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy');
            copyToClipboard(textToCopy);
        });
    });
    
    // Add smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Auto-hide notifications on click
    const notification = document.getElementById('notification');
    if (notification) {
        notification.addEventListener('click', function() {
            this.classList.remove('show');
        });
    }
});