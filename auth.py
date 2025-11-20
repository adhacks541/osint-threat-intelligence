"""
Basic authentication system for OSINT Dashboard
"""
from functools import wraps
from flask import request, session, redirect, url_for, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import os
from config import Config


def init_auth(app):
    """Initialize authentication for the Flask app"""
    app.secret_key = Config.SECRET_KEY


def login_required(f):
    """
    Decorator to require authentication for routes
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def check_auth(username, password):
    """
    Check if username and password are correct
    
    Args:
        username: Username to check
        password: Password to check
    
    Returns:
        True if credentials are valid, False otherwise
    """
    admin_username = Config.ADMIN_USERNAME
    admin_password = Config.ADMIN_PASSWORD
    
    # If no password is set, disable authentication
    if not admin_password or admin_password == 'change-this-password':
        return False
    
    return username == admin_username and password == admin_password


def login():
    """Handle login"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if check_auth(username, password):
            session['authenticated'] = True
            session['username'] = username
            if request.is_json:
                return jsonify({'status': 'success', 'message': 'Login successful'})
            return redirect(url_for('index'))
        else:
            if request.is_json:
                return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
            return redirect(url_for('login'))
    
    # GET request - show login page
    from flask import render_template
    return render_template('login.html')


def logout():
    """Handle logout"""
    session.pop('authenticated', None)
    session.pop('username', None)
    if request.is_json:
        return jsonify({'status': 'success', 'message': 'Logged out'})
    return redirect(url_for('login'))

