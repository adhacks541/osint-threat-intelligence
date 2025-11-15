from flask import Flask, render_template, request, jsonify, send_file
import sqlite3
import folium
from xhtml2pdf import pisa
import os

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY,
                    type TEXT,
                    value TEXT,
                    source TEXT,
                    lat REAL,
                    lon REAL
                )''')
    conn.commit()
    conn.close()



init_db()

# Mocked OSINT Functions (return sample data)
def shodan_search(query):
    # Simple mock: return a fixed location for any IP query, but include the query IP.
    return [
        {'type': 'IP', 'value': query, 'source': 'Shodan', 'lat': 40.7128, 'lon': -74.0060}, # New York
        {'type': 'IP', 'value': '8.8.8.8', 'source': 'Shodan', 'lat': 37.3860, 'lon': -122.0840}
    ]

def theharvester_search(domain):
    return [
        {'type': 'Email', 'value': 'admin@' + domain, 'source': 'theHarvester'},
        {'type': 'Domain', 'value': domain, 'source': 'theHarvester'}
    ]

def google_dorks_search(query):
    return [
        {'type': 'Domain', 'value': f'found.by.google.{query}', 'source': 'Google Dorks'},
        {'type': 'Domain', 'value': f'another.result.{query}', 'source': 'Google Dorks'}
    ]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/collect', methods=['POST'])
def collect():
    query = request.form['query']
    tool = request.form['tool']
    findings = []
    if tool == 'shodan':
        findings = shodan_search(query)
    elif tool == 'theharvester':
        findings = theharvester_search(query)
    elif tool == 'google_dorks':
        findings = google_dorks_search(query)
    
    # Store in DB
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    for f in findings:
        c.execute("INSERT INTO findings (type, value, source, lat, lon) VALUES (?, ?, ?, ?, ?)",
                  (f['type'], f['value'], f['source'], f.get('lat'), f.get('lon')))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'findings': findings})

@app.route('/search', methods=['GET'])
def search():
    keyword = request.args.get('keyword', '')
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    c.execute("SELECT * FROM findings WHERE value LIKE ?", ('%' + keyword + '%',))
    results = c.fetchall()
    conn.close()
    return jsonify(results)

@app.route('/heatmap')
def heatmap():
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    c.execute("SELECT lat, lon, value FROM findings WHERE lat IS NOT NULL AND lon IS NOT NULL")
    points = c.fetchall()
    conn.close()
    
    # Generate Folium map
    m = folium.Map(location=[20, 0], zoom_start=2)
    for lat, lon, value in points:
        folium.Marker([lat, lon], popup=value).add_to(m)
    m.save('static/heatmap.html')
    return send_file('static/heatmap.html')

@app.route('/export_pdf')
def export_pdf():
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    c.execute("SELECT * FROM findings")
    findings = c.fetchall()
    conn.close()
    
    html = '<html><body><h1>OSINT Findings Report</h1><ul>'
    for f in findings:
        html += f'<li>{f[1]}: {f[2]} (Source: {f[3]})</li>'
    html += '</ul></body></html>'
    
    output_filename = 'report.pdf'
    with open(output_filename, "w+b") as pdf_file:
        pisa_status = pisa.CreatePDF(html, dest=pdf_file)

    if pisa_status.err:
        return "Error generating PDF", 500
        
    return send_file(output_filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
