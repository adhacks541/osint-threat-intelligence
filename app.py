from flask import Flask, render_template, request, jsonify, send_file
import sqlite3
import folium
from folium.plugins import HeatMap, MarkerCluster
from xhtml2pdf import pisa
import os
import sys
import json
import time
import datetime
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
import whois
import shodan
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import subprocess
import re
import requests
from base64 import urlsafe_b64encode
import logging
from logging.handlers import RotatingFileHandler
from contextlib import contextmanager

# Security imports
from config import get_config, Config
from validators import validate_query, validate_tool, sanitize_input
from auth import init_auth, login_required, login, logout
from ai_analyst import AIAnalyst

# Initialize Flask app
app = Flask(__name__)

# Load configuration
config_class = get_config()
app.config.from_object(config_class)

# Initialize authentication
init_auth(app)

# Initialize AI Analyst
ai_analyst = AIAnalyst()

# Setup logging
if not app.debug:
    if not os.path.exists(Config.LOG_DIR):
        os.mkdir(Config.LOG_DIR)
    file_handler = RotatingFileHandler(
        Config.LOG_FILE, 
        maxBytes=10240000,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(getattr(logging, Config.LOG_LEVEL))
    app.logger.addHandler(file_handler)
    app.logger.setLevel(getattr(logging, Config.LOG_LEVEL))
    app.logger.info('OSINT Dashboard startup')

# Config functions (backward compatibility - now uses environment variables)
def load_config():
    """Load configuration from environment variables"""
    return Config.get_config_dict()


# Database setup
DATABASE = Config.DATABASE_FILE

@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        app.logger.error(f'Database error: {str(e)}', exc_info=True)
        raise
    finally:
        conn.close()

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY,
                    type TEXT,
                    value TEXT,
                    source TEXT,
                    lat REAL,
                    lon REAL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    asn TEXT,
                    country TEXT,
                    ports TEXT
                )''')
    
    # Simple migration for existing databases
    try:
        c.execute("ALTER TABLE findings ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP")
    except sqlite3.OperationalError:
        pass # Column likely already exists
    try:
        c.execute("ALTER TABLE findings ADD COLUMN asn TEXT")
    except sqlite3.OperationalError:
        pass # Column likely already exists
    try:
        c.execute("ALTER TABLE findings ADD COLUMN country TEXT")
    except sqlite3.OperationalError:
        pass # Column likely already exists
    try:
        c.execute("ALTER TABLE findings ADD COLUMN ports TEXT")
    except sqlite3.OperationalError:
        pass # Column likely already exists
    try:
        c.execute("ALTER TABLE findings ADD COLUMN details TEXT")
    except sqlite3.OperationalError:
        pass # Column likely already exists

    conn.commit()
    conn.close()



init_db()

# Real OSINT Functions
def shodan_search(query):
    """Search Shodan for IP information"""
    app.logger.info(f'Shodan search initiated for: {query}')
    api_key = Config.SHODAN_API_KEY
    if not api_key:
        app.logger.warning('Shodan API key not configured')
        return [{'type': 'Error', 'value': 'Shodan API key not configured', 'source': 'System'}]
    
    try:
        api = shodan.Shodan(api_key)
        host = api.host(query)
        
        # Data Enrichment for table view
        asn_info = host.get('asn', 'N/A')
        country_name = host.get('country_name', 'N/A')
        ports = ', '.join(str(p) for p in host.get('ports', []))
        
        # Create a more descriptive value for the main table
        hostnames = ', '.join(host.get('hostnames', []))
        value_summary = f"{host.get('ip_str')} | Hostnames: {hostnames}"

        findings = [{
            'type': 'IP',
            'value': value_summary,
            'source': 'Shodan',
            'lat': host.get('latitude'),
            'lon': host.get('longitude'),
            'asn': asn_info,
            'country': country_name,
            'ports': ports,
            'details': host # Add the full host object for the details view
        }]
        app.logger.info(f'Shodan search completed successfully for: {query}')
        return findings
    except shodan.APIError as e:
        app.logger.error(f'Shodan API error: {str(e)}')
        return [{'type': 'Error', 'value': str(e), 'source': 'Shodan'}]
    except Exception as e:
        app.logger.error(f'Shodan search failed: {str(e)}', exc_info=True)
        return [{'type': 'Error', 'value': f'Unexpected error: {str(e)}', 'source': 'Shodan'}]

def theharvester_search(domain):
    """Search using theHarvester tool"""
    app.logger.info(f'theHarvester search initiated for: {domain}')
    try:
        # We will capture stdout, so no need for file output
        # Use absolute path to theHarvester in the same venv as python
        venv_bin = os.path.dirname(sys.executable)
        theharvester_cmd = os.path.join(venv_bin, 'theHarvester')
        
        command = [theharvester_cmd, '-d', domain, '-b', 'duckduckgo,bing,yahoo,certspotter']
        
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=120,
            cwd=os.path.expanduser('~') # Run from user's home directory
        )

        # A non-zero return code indicates an error
        if result.returncode != 0:
            error_message = result.stderr or result.stdout
            return [{'type': 'Error', 'value': f"theHarvester exited with an error: {error_message}", 'source': 'theHarvester'}]

        # Use the raw stdout as the details
        details = result.stdout
        
        # Create a simple summary value
        summary_value = f"theHarvester scan completed for {domain}"
        
        findings = [{
            'type': 'theHarvester Scan', 
            'value': summary_value, 
            'source': 'theHarvester',
            'details': details # Store the raw stdout
        }]

        app.logger.info(f'theHarvester search completed for: {domain}')
        return findings
    except FileNotFoundError:
        app.logger.error('theHarvester not found in PATH')
        return [{'type': 'Error', 'value': 'theHarvester not found. Make sure it is installed and in your PATH.', 'source': 'System'}]
    except subprocess.TimeoutExpired:
        app.logger.warning(f'theHarvester scan timed out for: {domain}')
        return [{'type': 'Error', 'value': 'theHarvester scan timed out after 2 minutes.', 'source': 'theHarvester'}]
    except Exception as e:
        app.logger.error(f'theHarvester search failed: {str(e)}', exc_info=True)
        return [{'type': 'Error', 'value': f"An unexpected error occurred: {e}", 'source': 'theHarvester'}]


def google_dorks_search(query):
    """Search using Google Dorks"""
    app.logger.info(f'Google Dorks search initiated for: {query}')
    api_key = Config.GOOGLE_API_KEY
    cse_id = Config.GOOGLE_CSE_ID

    if not api_key or not cse_id:
        app.logger.warning('Google API key or CSE ID not configured')
        return [{'type': 'Error', 'value': 'Google API key or CSE ID not configured', 'source': 'System'}]

    try:
        service = build("customsearch", "v1", developerKey=api_key)
        res = service.cse().list(q=query, cx=cse_id, num=10).execute()
        
        items = res.get('items', [])
        item_count = len(items)
        
        summary_value = f"Found {item_count} results for dork query"
        
        findings = [{
            'type': 'Google Dork',
            'value': summary_value,
            'source': 'Google Dorks',
            'details': res # The full API response
        }]
        app.logger.info(f'Google Dorks search completed for: {query}')
        return findings
    except HttpError as e:
        app.logger.error(f'Google API error: {e.reason}')
        return [{'type': 'Error', 'value': f"Google API Error: {e.reason}", 'source': 'Google Dorks'}]
    except Exception as e:
        app.logger.error(f'Google Dorks search failed: {str(e)}', exc_info=True)
        return [{'type': 'Error', 'value': str(e), 'source': 'Google Dorks'}]

def whois_search(domain):
    """Search WHOIS for domain information using WhoisXML API"""
    app.logger.info(f'WHOIS search initiated for: {domain}')
    
    api_key = Config.WHOISXML_API_KEY
    if not api_key:
        # Fallback to local library if no API key (though we know it's flaky)
        app.logger.warning('WhoisXML API key not found, falling back to local library')
        try:
            w = whois.whois(domain)
            if not w.get('domain_name'):
                 return [{'type': 'Error', 'value': 'WHOIS data not found.', 'source': 'WHOIS'}]
            info = f"Registrar: {w.registrar}, Created: {w.creation_date}"
            return [{'type': 'WHOIS', 'value': info, 'source': 'WHOIS', 'details': str(w)}]
        except Exception as e:
            return [{'type': 'Error', 'value': f"Local WHOIS failed: {str(e)}", 'source': 'WHOIS'}]

    try:
        # WhoisXML API Endpoint
        url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            'apiKey': api_key,
            'domainName': domain,
            'outputFormat': 'JSON'
        }
        
        response = requests.get(url, params=params)
        
        if response.status_code != 200:
             return [{'type': 'Error', 'value': f"API Error: {response.status_code}", 'source': 'WhoisXML'}]
             
        data = response.json()
        
        if 'WhoisRecord' not in data:
             return [{'type': 'Error', 'value': "No WHOIS record found.", 'source': 'WhoisXML'}]
             
        record = data['WhoisRecord']
        
        # Extract key info
        registrar = record.get('registrarName', 'N/A')
        created_date = record.get('createdDate', 'N/A')
        expires_date = record.get('expiresDate', 'N/A')
        registrant = record.get('registrant', {}).get('organization', 'N/A')
        
        info = f"Registrar: {registrar} | Created: {created_date} | Expires: {expires_date} | Org: {registrant}"
        
        findings = [{
            'type': 'WHOIS', 
            'value': info, 
            'source': 'WhoisXML API',
            'details': record # Store full JSON record
        }]
        
        app.logger.info(f'WHOIS search completed for: {domain}')
        return findings

    except Exception as e:
        app.logger.error(f'WHOIS search failed: {str(e)}', exc_info=True)
        return [{'type': 'Error', 'value': str(e), 'source': 'WhoisXML'}]

def sherlock_search(username):
    """Search using Sherlock tool - accepts usernames, names, or any searchable string"""
    app.logger.info(f'Sherlock search initiated for: {username}')
    try:
        # Add --no-color to prevent ANSI escape codes in the output
        # Add --local to prevent update checks from GitHub (prevents data.json errors)
        # Add a timeout and run from the user's home directory for consistency
        # Sanitize username to prevent command injection
        username = sanitize_input(username, max_length=100)
        command = ['sherlock', '--no-color', '--local', username]
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=120,
            cwd=os.path.expanduser('~')
        )

        if result.returncode != 0:
            error_message = result.stderr or result.stdout
            # Parse the error to provide a more user-friendly message
            if 'data.json' in error_message or 'update' in error_message.lower():
                error_message = "Sherlock update check failed. Running with local data only."
                app.logger.warning(f'Sherlock update check failed, but continuing with local data')
            else:
                return [{'type': 'Error', 'value': f"Sherlock exited with an error: {error_message}", 'source': 'Sherlock'}]

        # Count the number of found profiles for the summary
        found_lines = [line for line in result.stdout.splitlines() if line.startswith('[+]')]
        profile_count = len(found_lines)

        summary_value = f"Found {profile_count} profiles for '{username}'"
        
        findings = [{
            'type': 'Sherlock Scan', 
            'value': summary_value, 
            'source': 'Sherlock',
            'details': result.stdout # Store the raw, formatted stdout
        }]

        app.logger.info(f'Sherlock search completed for: {username}')
        return findings
    except FileNotFoundError:
        app.logger.error('Sherlock not found in PATH')
        return [{'type': 'Error', 'value': 'Sherlock not found. Make sure it is installed and in your PATH.', 'source': 'System'}]
    except subprocess.TimeoutExpired:
        app.logger.warning(f'Sherlock scan timed out for: {username}')
        return [{'type': 'Error', 'value': 'Sherlock scan timed out after 2 minutes.', 'source': 'Sherlock'}]
    except Exception as e:
        app.logger.error(f'Sherlock search failed: {str(e)}', exc_info=True)
        return [{'type': 'Error', 'value': f"An unexpected error occurred: {e}", 'source': 'Sherlock'}]

def virustotal_search(query):
    """Search VirusTotal for IP/domain reputation"""
    app.logger.info(f'VirusTotal search initiated for: {query}')
    api_key = Config.VIRUSTOTAL_API_KEY
    if not api_key:
        app.logger.warning('VirusTotal API key not configured')
        return [{'type': 'Error', 'value': 'VirusTotal API key not configured', 'source': 'System'}]

    headers = {
        "x-apikey": api_key
    }
    
    try:
        # Check if query is an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", query):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
            response = requests.get(url, headers=headers)
            response.raise_for_status() # Raise an exception for bad status codes
            resp = response.json()
            
            stats = resp.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            info = f"Malicious: {stats.get('malicious', 0)}, Harmless: {stats.get('harmless', 0)}, Suspicious: {stats.get('suspicious', 0)}"
            return [{'type': 'IP Reputation', 'value': info, 'source': 'VirusTotal', 'details': resp}]
        else: # Assume it's a domain/URL
            url_id = urlsafe_b64encode(query.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            resp = response.json()

            stats = resp.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            info = f"Malicious: {stats.get('malicious', 0)}, Harmless: {stats.get('harmless', 0)}, Suspicious: {stats.get('suspicious', 0)}"
            app.logger.info(f'VirusTotal search completed for: {query}')
            return [{'type': 'Domain Reputation', 'value': info, 'source': 'VirusTotal', 'details': resp}]
    except requests.exceptions.HTTPError as e:
        # Handle HTTP errors (like 404 Not Found) gracefully
        app.logger.error(f'VirusTotal API error: {e.response.status_code} {e.response.reason}')
        return [{'type': 'Error', 'value': f"VirusTotal API Error: {e.response.status_code} {e.response.reason}", 'source': 'VirusTotal'}]
    except Exception as e:
        app.logger.error(f'VirusTotal search failed: {str(e)}', exc_info=True)
        return [{'type': 'Error', 'value': str(e), 'source': 'VirusTotal'}]

def censys_search(query):
    """Search Censys for host information (accepts IP addresses or domains)"""
    app.logger.info(f'Censys search initiated for: {query}')
    token = Config.CENSYS_API_ID
    if not token:
        app.logger.warning('Censys API token not configured')
        return [{'type': 'Error', 'value': 'Censys Personal Access Token not configured', 'source': 'System'}]

    # Headers for the new Censys Platform API v3
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.censys.api.v3.host.v1+json"
    }
    
    # The new Censys Platform API v3 endpoint for hosts (accepts both IPs and domains)
    url = f"https://api.platform.censys.io/v3/global/asset/host/{query}"
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        resp = response.json()

        # Correctly parse the new v3 response structure
        services = []
        resource = resp.get('result', {}).get('resource', {})
        for service in resource.get('services', []):
            # Use 'transport_protocol' as confirmed by the JSON response
            services.append(f"{service.get('port')}/{service.get('transport_protocol')}")
        
        info = f"Services: {', '.join(services)}" if services else "No services found"
        
        app.logger.info(f'Censys search completed for: {query}')
        return [{'type': 'Censys Host', 'value': info, 'source': 'Censys', 'details': resp.get('result', {})}]
    except requests.exceptions.HTTPError as e:
        # The new API might return a more detailed error message in the response body
        try:
            error_details = e.response.json().get('error', str(e))
        except json.JSONDecodeError:
            error_details = str(e)
        app.logger.error(f'Censys API error: {e.response.status_code} - {error_details}')
        return [{'type': 'Error', 'value': f"Censys API Error: {e.response.status_code} - {error_details}", 'source': 'Censys'}]
    except Exception as e:
        app.logger.error(f'Censys search failed: {str(e)}', exc_info=True)
        return [{'type': 'Error', 'value': str(e), 'source': 'Censys'}]

# Authentication routes (optional - can be enabled via environment variable)
@app.route('/login', methods=['GET', 'POST'])
def login_route():
    """Login route"""
    return login()

@app.route('/logout')
def logout_route():
    """Logout route"""
    return logout()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/collect', methods=['POST'])
def collect():
    """Collect OSINT data from various sources"""
    try:
        # Validate and sanitize input
        query = request.form.get('query', '')
        tool = request.form.get('tool', '')
        
        # Validate tool
        validate_tool(tool)
        
        # Validate and sanitize query
        query = validate_query(query, tool)
        
        app.logger.info(f'Data collection requested: tool={tool}, query={query}')
        
        findings = []
        if tool == 'shodan':
            findings = shodan_search(query)
        elif tool == 'theharvester':
            findings = theharvester_search(query)
        elif tool == 'google_dorks':
            findings = google_dorks_search(query)
        elif tool == 'whois':
            findings = whois_search(query)
        elif tool == 'sherlock':
            findings = sherlock_search(query)
        elif tool == 'virustotal':
            findings = virustotal_search(query)
        elif tool == 'censys':
            findings = censys_search(query)
        
        # Store in DB
        try:
            with get_db() as conn:
                c = conn.cursor()
                for f in findings:
                    # Need to serialize the details dict to a JSON string for DB storage
                    details_json = json.dumps(f.get('details'), indent=4) if f.get('details') else None
                    c.execute("INSERT INTO findings (type, value, source, lat, lon, asn, country, ports, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                              (f['type'], f.get('value'), f.get('source'), f.get('lat'), f.get('lon'), f.get('asn'), f.get('country'), f.get('ports'), details_json))
            app.logger.info(f'Stored {len(findings)} findings in database')
        except Exception as e:
            app.logger.error(f'Failed to store findings in database: {str(e)}', exc_info=True)
            return jsonify({'status': 'error', 'message': 'Failed to store findings'}), 500
        
        return jsonify({'status': 'success', 'findings': findings})
    except Exception as e:
        app.logger.error(f'Collection error: {str(e)}', exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/search', methods=['GET'])
def search():
    """Search findings in database"""
    # Sanitize search inputs
    keyword = sanitize_input(request.args.get('keyword', ''), max_length=100)
    port = sanitize_input(request.args.get('port', ''), max_length=50)
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            query_parts = ["SELECT id, type, value, source, lat, lon, timestamp, asn, country, ports, details FROM findings WHERE value LIKE ?"]
            params = ['%' + keyword + '%']
    
            if port:
                query_parts.append("AND ports LIKE ?")
                params.append('%' + port + '%')
            
            if start_date:
                query_parts.append("AND timestamp >= ?")
                params.append(start_date)
                
            if end_date:
                query_parts.append("AND timestamp <= ?")
                params.append(end_date + ' 23:59:59') # Include the entire end day
                
            query_parts.append("ORDER BY timestamp DESC")
    
            query = ' '.join(query_parts)
            c.execute(query, params)
            
            results = c.fetchall()
            # Convert Row objects to lists for JSON serialization
            results = [list(row) for row in results]
        return jsonify(results)
    except Exception as e:
        app.logger.error(f'Search error: {str(e)}', exc_info=True)
        return jsonify({'error': 'Search failed'}), 500

@app.route('/heatmap')
def heatmap():
    """Generate heatmap visualization"""
    port = sanitize_input(request.args.get('port', ''), max_length=50)
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')

    try:
        with get_db() as conn:
            c = conn.cursor()

            query_parts = ["SELECT lat, lon, value, asn, country FROM findings WHERE lat IS NOT NULL AND lon IS NOT NULL"]
            params = []
        
            if port:
                query_parts.append("AND ports LIKE ?")
                params.append('%' + port + '%')
            
            if start_date:
                query_parts.append("AND timestamp >= ?")
                params.append(start_date)
                
            if end_date:
                query_parts.append("AND timestamp <= ?")
                params.append(end_date + ' 23:59:59')

            query = ' '.join(query_parts)
            c.execute(query, params)

            points = c.fetchall()
        
        heatmap_html_path = 'static/heatmap.html'

        if points:
            m = folium.Map(location=[20, 0], zoom_start=2)
            heat_data = [[point[0], point[1]] for point in points]
            HeatMap(heat_data).add_to(m)
            marker_cluster = MarkerCluster().add_to(m)
            for lat, lon, value, asn, country in points:
                popup_html = f"<b>IP:</b> {value}<br><b>Country:</b> {country}<br><b>ASN:</b> {asn}"
                folium.Marker(
                    location=[lat, lon],
                    popup=popup_html,
                ).add_to(marker_cluster)
            m.save(heatmap_html_path)
            return send_file(heatmap_html_path)
        else:
            no_data_html = """
            <!DOCTYPE html>
            <html>
            <head><title>No Data</title></head>
            <body><h3>No geolocation data available for the current filter.</h3></body>
            </html>
            """
            with open(heatmap_html_path, 'w') as f:
                f.write(no_data_html)
    
            return send_file(heatmap_html_path)
    except Exception as e:
        app.logger.error(f'Heatmap generation error: {str(e)}', exc_info=True)
        return "Error generating heatmap", 500

@app.route('/export_pdf')
def export_pdf():
    """Export findings to PDF report"""
    app.logger.info('PDF export requested')
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM findings ORDER BY timestamp DESC")
            db_findings = c.fetchall()
            
            c.execute("SELECT lat, lon, value FROM findings WHERE lat IS NOT NULL AND lon IS NOT NULL")
            points = c.fetchall()

        # Process findings for the template
        findings_for_template = []
        for finding in db_findings:
            finding_dict = dict(finding)
            if finding_dict['details']:
                try:
                    # Parse and re-stringify for pretty printing in the report
                    details_obj = json.loads(finding_dict['details'])
                    finding_dict['details'] = json.dumps(details_obj, indent=4)
                except (json.JSONDecodeError, TypeError):
                    # If it's not a valid JSON string (like for theHarvester), just pass it as is
                    pass
            findings_for_template.append(finding_dict)
    
        heatmap_path = None
        heatmap_filename = f"static/heatmap_{int(time.time())}.png"
        map_html_filename = f"static/map_{int(time.time())}.html"

        try:
            if points:
                # 1. Generate hybrid heatmap HTML
                m = folium.Map(location=[20, 0], zoom_start=2)
                heat_data = [[point['lat'], point['lon']] for point in points]
                HeatMap(heat_data).add_to(m)
                marker_cluster = MarkerCluster().add_to(m)
                for lat, lon, value in points:
                    folium.Marker(location=[lat, lon], popup=value).add_to(marker_cluster)
                m.save(map_html_filename)
    
                # 2. Take screenshot with Selenium
                options = webdriver.ChromeOptions()
                options.add_argument('--headless')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                
                service = ChromeService()
                driver = webdriver.Chrome(service=service, options=options)
                driver.set_window_size(1200, 800) # Set window size to prevent cut-off map
                
                driver.get(f"file://{os.path.abspath(map_html_filename)}")
                time.sleep(2) # Allow map to render
                driver.save_screenshot(heatmap_filename)
                driver.quit()
                heatmap_path = os.path.abspath(heatmap_filename)
    
            # 3. Render HTML for PDF
            rendered_html = render_template(
                'report_template.html',
                findings=findings_for_template,
                generation_date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                heatmap_path=heatmap_path
            )
            
            # 4. Create PDF
            output_filename = 'report.pdf'
            with open(output_filename, "w+b") as pdf_file:
                pisa_status = pisa.CreatePDF(rendered_html, dest=pdf_file)
    
            if pisa_status.err:
                app.logger.error('PDF generation failed')
                return "Error generating PDF", 500
            
            app.logger.info('PDF export completed successfully')
            return send_file(output_filename, as_attachment=True)
        finally:
            # 5. Cleanup
            if heatmap_path and os.path.exists(heatmap_filename):
                os.remove(heatmap_filename)
            if os.path.exists(map_html_filename):
                os.remove(map_html_filename)
    except Exception as e:
        app.logger.error(f'PDF export error: {str(e)}', exc_info=True)
        return "Error generating PDF", 500

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/get_settings', methods=['GET'])
def get_settings():
    return jsonify(load_config())

@app.route('/save_settings', methods=['POST'])
def save_settings():
    """Save settings - Note: Settings are now managed via environment variables"""
    # Settings are now managed via .env file for security
    # This endpoint is kept for backward compatibility but doesn't actually save
    app.logger.warning('Settings save attempted - settings now managed via environment variables')
    return jsonify({
        'message': 'Settings are now managed via environment variables (.env file). Please update your .env file and restart the application.'
    })

@app.route('/clean_db', methods=['POST'])
def clean_db():
    """Clean all findings from database"""
    app.logger.warning('Database clean requested')
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM findings")
        app.logger.info('Database cleaned successfully')
        return jsonify({'message': 'Database cleaned successfully!'})
    except Exception as e:
        app.logger.error(f'Database clean failed: {str(e)}', exc_info=True)
        return jsonify({'error': 'Failed to clean database'}), 500

@app.route('/delete_findings', methods=['POST'])
def delete_findings():
    """Delete selected findings from database"""
    data = request.get_json()
    ids_to_delete = data.get('ids', [])
    
    if not ids_to_delete:
        return jsonify({'status': 'error', 'message': 'No IDs provided'}), 400
    
    # Validate IDs are integers
    try:
        ids_to_delete = [int(id) for id in ids_to_delete]
    except (ValueError, TypeError):
        app.logger.warning('Invalid IDs provided for deletion')
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Using placeholders to prevent SQL injection
            placeholders = ','.join('?' for _ in ids_to_delete)
            query = f"DELETE FROM findings WHERE id IN ({placeholders})"
            
            c.execute(query, ids_to_delete)
        
        app.logger.info(f'Deleted {len(ids_to_delete)} findings')
        return jsonify({'status': 'success', 'message': f'Deleted {len(ids_to_delete)} findings.'})
    except Exception as e:
        app.logger.error(f'Delete findings failed: {str(e)}', exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to delete findings'}), 500

@app.route('/get_date_range', methods=['GET'])
def get_date_range():
    """Get date range of findings in database"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT MIN(timestamp), MAX(timestamp) FROM findings")
            result = c.fetchone()
        
        # Convert to YYYY-MM-DD format for date inputs
        min_date = result[0].split(' ')[0] if result[0] else ''
        max_date = result[1].split(' ')[0] if result[1] else ''
        
        return jsonify({'min_date': min_date, 'max_date': max_date})
    except Exception as e:
        app.logger.error(f'Get date range failed: {str(e)}', exc_info=True)
        return jsonify({'min_date': '', 'max_date': ''})


# --- AI Analyst Routes ---

@app.route('/ai/analyze', methods=['POST'])
def ai_analyze():
    try:
        # Get recent findings for context
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM findings ORDER BY timestamp DESC LIMIT 50")
            rows = c.fetchall()
            # Convert rows to list of dicts for JSON serialization
            findings = [dict(row) for row in rows]

        analysis = ai_analyst.analyze_findings(findings)
        
        # Also extract IOCs from the raw values of findings
        all_text = " ".join([f['value'] for f in findings])
        iocs = ai_analyst.extract_iocs(all_text)
        
        return jsonify({
            "status": "success",
            "analysis": analysis,
            "iocs": iocs
        })
    except Exception as e:
        app.logger.error(f"AI Analyze Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/ai/chat', methods=['POST'])
def ai_chat():
    try:
        data = request.get_json()
        query = data.get('query')
        
        if not query:
            return jsonify({"error": "No query provided"}), 400

        # Get context
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM findings ORDER BY timestamp DESC LIMIT 50")
            rows = c.fetchall()
            findings = [dict(row) for row in rows]

        response = ai_analyst.chat_with_data(query, findings)
        return jsonify({"status": "success", "response": response})
    except Exception as e:
        app.logger.error(f"AI Chat Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/ai/report', methods=['POST'])
def ai_report():
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM findings ORDER BY timestamp DESC LIMIT 100")
            rows = c.fetchall()
            findings = [dict(row) for row in rows]

        report_content = ai_analyst.generate_comprehensive_report(findings)
        return jsonify({"status": "success", "report": report_content})
    except Exception as e:
        app.logger.error(f"AI Report Error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Use configuration to determine debug mode
    app.run(debug=app.config['DEBUG'], host='127.0.0.1', port=5001)
