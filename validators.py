"""
Input validation and sanitization functions
Prevents SQL injection, XSS, and command injection attacks
"""
import re
from flask import abort, jsonify
import html


def sanitize_input(input_str, max_length=1000):
    """
    Sanitize user input to prevent injection attacks
    
    Args:
        input_str: Input string to sanitize
        max_length: Maximum allowed length
    
    Returns:
        Sanitized string
    """
    if not input_str:
        return ''
    
    if not isinstance(input_str, str):
        input_str = str(input_str)
    
    # Check length
    if len(input_str) > max_length:
        abort(400, f'Input too long. Maximum {max_length} characters allowed.')
    
    # Remove null bytes and control characters (except newline, tab, carriage return)
    sanitized = ''.join(
        char for char in input_str 
        if ord(char) >= 32 or char in '\n\r\t'
    )
    
    # Strip whitespace
    sanitized = sanitized.strip()
    
    # HTML escape to prevent XSS
    sanitized = html.escape(sanitized)
    
    return sanitized


def validate_ip(ip):
    """
    Validate IP address format
    
    Args:
        ip: IP address string to validate
    
    Returns:
        True if valid, raises 400 error if invalid
    """
    if not ip:
        abort(400, 'IP address is required')
    
    # Basic format check
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        abort(400, 'Invalid IP address format')
    
    # Validate each octet is 0-255
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            abort(400, 'Invalid IP address format')
        
        for part in parts:
            num = int(part)
            if not (0 <= num <= 255):
                abort(400, 'Invalid IP address range (0-255)')
    except ValueError:
        abort(400, 'Invalid IP address format')
    
    return True


def validate_domain(domain):
    """
    Validate domain name format
    
    Args:
        domain: Domain string to validate
    
    Returns:
        True if valid, raises 400 error if invalid
    """
    if not domain:
        abort(400, 'Domain is required')
    
    # Remove protocol if present
    domain = domain.replace('http://', '').replace('https://', '').replace('www.', '')
    domain = domain.split('/')[0].split('?')[0]  # Remove path and query
    
    # Basic domain validation
    # Allow letters, numbers, dots, and hyphens
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    if not re.match(pattern, domain):
        abort(400, 'Invalid domain format')
    
    # Check length
    if len(domain) > 253:  # Max domain length per RFC
        abort(400, 'Domain name too long')
    
    return True


def validate_username(username):
    """
    Validate username format
    
    Args:
        username: Username string to validate
    
    Returns:
        True if valid, raises 400 error if invalid
    """
    if not username:
        abort(400, 'Username is required')
    
    # Length check
    if len(username) < 3:
        abort(400, 'Username must be at least 3 characters')
    
    if len(username) > 30:
        abort(400, 'Username must be 30 characters or less')
    
    # Character check - alphanumeric, underscore, hyphen only
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        abort(400, 'Username can only contain letters, numbers, underscores, and hyphens')
    
    return True


def validate_query(query, tool):
    """
    Validate query based on tool type
    
    Args:
        query: Query string to validate
        tool: Tool name to determine validation type
    
    Returns:
        Sanitized and validated query
    """
    # First sanitize
    query = sanitize_input(query, max_length=500)
    
    if not query:
        abort(400, 'Query is required')
    
    # Validate based on tool
    if tool == 'shodan':
        validate_ip(query)
    elif tool in ['theharvester', 'google_dorks', 'whois', 'virustotal', 'censys']:
        validate_domain(query)
    elif tool == 'sherlock':
        validate_username(query)
    else:
        # Generic validation for unknown tools
        if len(query) < 1 or len(query) > 500:
            abort(400, 'Query must be between 1 and 500 characters')
    
    return query


def validate_tool(tool):
    """
    Validate tool name to prevent command injection
    
    Args:
        tool: Tool name to validate
    
    Returns:
        True if valid, raises 400 error if invalid
    """
    allowed_tools = ['shodan', 'theharvester', 'google_dorks', 'whois', 
                     'sherlock', 'virustotal', 'censys']
    
    if tool not in allowed_tools:
        abort(400, f'Invalid tool. Allowed tools: {", ".join(allowed_tools)}')
    
    return True

