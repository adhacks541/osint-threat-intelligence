# Quick Fixes Implementation Guide

This guide provides step-by-step instructions for implementing the most critical fixes.

## 🚨 CRITICAL: Fix Authentication (Do This First)

### 1. Protect Routes in `app.py`
Currently, sensitive routes are accessible without login. Apply the `@login_required` decorator.

```python
# In app.py
from auth import login_required

# Apply to these routes:
@app.route('/collect', methods=['POST'])
@login_required  # <--- ADD THIS
def collect():
    # ...

@app.route('/clean_db', methods=['POST'])
@login_required  # <--- ADD THIS
def clean_db():
    # ...

@app.route('/delete_findings', methods=['POST'])
@login_required  # <--- ADD THIS
def delete_findings():
    # ...

@app.route('/settings')
@login_required  # <--- ADD THIS
def settings():
    # ...

@app.route('/save_settings', methods=['POST'])
@login_required  # <--- ADD THIS
def save_settings():
    # ...
```

### 2. Secure Password Storage in `auth.py`
Don't store plain text passwords. Use hashing.

```python
# In auth.py
from werkzeug.security import check_password_hash, generate_password_hash

# 1. Generate a hash for your password (run this in python shell)
# >>> from werkzeug.security import generate_password_hash
# >>> generate_password_hash('your-secure-password')
# 'scrypt:32768:8:1$...'

# 2. Update .env
# ADMIN_PASSWORD_HASH=scrypt:32768:8:1$...

# 3. Update check_auth function
def check_auth(username, password):
    admin_username = Config.ADMIN_USERNAME
    admin_password_hash = os.getenv('ADMIN_PASSWORD_HASH')
    
    if not admin_password_hash:
        return False
        
    return username == admin_username and check_password_hash(admin_password_hash, password)
```

---

## 1. Environment Variables Setup (Already Partially Done)

### Step 1: Install python-dotenv
```bash
pip install python-dotenv
```

### Step 2: Create `.env` file
```bash
# .env file (DO NOT COMMIT THIS)
SHODAN_API_KEY=your_shodan_key_here
GOOGLE_API_KEY=your_google_key_here
GOOGLE_CSE_ID=your_cse_id_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
CENSYS_API_ID=your_censys_token_here
FLASK_ENV=development
FLASK_DEBUG=False
SECRET_KEY=your-secret-key
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=...
```

---

## 2. Add Logging System (Already in `app.py`)
*This is already implemented in your current `app.py`.*

---

## 3. Input Validation (Already in `validators.py`)
*This is already implemented in `validators.py` and used in `app.py`.*

---

## 4. Pin Dependency Versions

### Update `requirements.txt`
```txt
flask==3.0.0
folium==0.15.0
xhtml2pdf==0.2.11
shodan==1.31.0
google-api-python-client==2.100.0
selenium==4.15.2
ipwhois==1.2.0
pycountry-convert==0.7.2
python-whois==0.8.0
sherlock-project==0.14.0
requests==2.31.0
python-dotenv==1.0.0
werkzeug==3.0.1
```

---

## 5. Database Connection Pooling

### Update database connections
```python
import sqlite3
from contextlib import contextmanager

DATABASE = 'osint.db'

@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# Usage in routes
@app.route('/search', methods=['GET'])
def search():
    keyword = request.args.get('keyword', '')
    # ... validation ...
    
    with get_db() as conn:
        c = conn.cursor()
        # ... query ...
        results = c.fetchall()
    return jsonify(results)
```

---

## 6. Add Rate Limiting

### Install Flask-Limiter
```bash
pip install Flask-Limiter
```

### Update `app.py`
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/collect', methods=['POST'])
@limiter.limit("10 per minute")
def collect():
    # ... existing code ...
```
