# 🛡️ OSINT Threat Intelligence Dashboard

<div align="center">

![OSINT Dashboard](https://img.shields.io/badge/OSINT-Threat%20Intelligence-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0.0-black?style=for-the-badge&logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A professional web-based dashboard for collecting, analyzing, and visualizing OSINT (Open-Source Intelligence) data with AI-powered threat analysis.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [API Keys](#-api-configuration) • [Screenshots](#-screenshots)

</div>

---

## ✨ Features

### 🔍 Intelligence Collection
- **Shodan** - IP intelligence and service enumeration
- **theHarvester** - Domain reconnaissance and email harvesting
- **Google Dorks** - Advanced Google search queries
- **WHOIS** - Domain registration information
- **Sherlock** - Username/name search across social platforms
- **VirusTotal** - IP/domain reputation analysis
- **Censys** - Host information (supports both IPs and domains)

### 🤖 AI-Powered Analysis
- **Gemini AI Integration** - Automated threat analysis
- **Risk Scoring** - AI-calculated threat levels
- **IOC Extraction** - Automatic extraction of IPs, domains, and hashes
- **Interactive Chat** - Query your collected data using natural language
- **AI Report Generation** - Comprehensive narrative reports

### 📊 Visualization & Reporting
- **Interactive GeoMap** - Heatmap visualization of IP locations with markers
- **Real-time Filtering** - Search by keyword, port, or date range
- **PDF Export** - Professional reports with findings and visualizations
- **DataTables Integration** - Sortable, paginated results

### 🎨 Modern UI/UX
- **Glassmorphism Design** - Beautiful dark mode interface
- **Responsive Layout** - Works on desktop, tablet, and mobile
- **Smooth Animations** - Polished user experience
- **Real-time Updates** - Live progress indicators

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Step 1: Clone the Repository
```bash
git clone https://github.com/yourusername/osint-dashboard.git
cd osint-dashboard
```

### Step 2: Create Virtual Environment
```bash
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env` and add your API keys (see [API Configuration](#-api-configuration)):

```env
# Flask Configuration
SECRET_KEY=your-secret-key-here
DEBUG=True

# API Keys
SHODAN_API_KEY=your_shodan_api_key
GOOGLE_API_KEY=your_google_api_key
GOOGLE_CSE_ID=your_google_cse_id
VIRUSTOTAL_API_KEY=your_virustotal_api_key
CENSYS_API_ID=your_censys_api_key
GEMINI_API_KEY=your_gemini_api_key
WHOISXML_API_KEY=your_whoisxml_api_key

# Database
DATABASE_URL=sqlite:///osint.db

# Logging
LOG_LEVEL=INFO
```

### Step 5: Run the Application
```bash
python app.py
```

The dashboard will be available at: **http://127.0.0.1:5001**

---

## 🔑 API Configuration

### Required APIs

| Service | Purpose | Get API Key |
|---------|---------|-------------|
| **Gemini AI** | AI analysis and chat | [Google AI Studio](https://makersuite.google.com/app/apikey) |
| **Shodan** | IP intelligence | [Shodan Account](https://account.shodan.io/) |
| **Censys** | Host information | [Censys Account](https://search.censys.io/account/api) |

### Optional APIs

| Service | Purpose | Get API Key |
|---------|---------|-------------|
| **Google Custom Search** | Google Dorks | [Google Cloud Console](https://console.cloud.google.com/) |
| **VirusTotal** | Reputation checks | [VirusTotal](https://www.virustotal.com/gui/my-apikey) |
| **WhoisXML** | WHOIS lookups | [WhoisXML API](https://whoisxmlapi.com/) |

### Tool Installation

Some features require additional tools to be installed:

```bash
# Install Sherlock (username search)
pip install sherlock-project

# Install theHarvester (domain recon)
pip install git+https://github.com/laramies/theHarvester.git
```

---

## 📖 Usage

### 1. Starting a Scan
1. Enter your target (IP, domain, username, or name)
2. Select the intelligence source
3. Click "Start Scan"
4. View results in the Findings tab

### 2. Viewing GeoMap
1. Click the "GeoMap" tab
2. See heatmap of IP locations
3. Click markers for detailed information
4. Use filters to refine the view

### 3. AI Analysis
1. Navigate to the "AI Analyst" tab
2. Click "Analyze Now" for automated threat analysis
3. View risk scores, threat levels, and recommendations
4. Use the chat to query your data
5. Generate comprehensive AI reports

### 4. Exporting Reports
1. Go to the "Reports" tab
2. Click "Download PDF Report"
3. Get a professional PDF with all findings and visualizations

### 5. Filtering Results
- **Search**: Use the search box to filter by keyword
- **Port**: Filter by specific port numbers
- **Date Range**: Select start and end dates
- **Delete**: Select findings and delete them

---

## 🎯 Input Format Guide

| Tool | Accepts | Examples |
|------|---------|----------|
| **Shodan** | IP addresses | `8.8.8.8`, `1.1.1.1` |
| **theHarvester** | Domains | `example.com`, `google.com` |
| **Google Dorks** | Search queries | `site:example.com`, `filetype:pdf` |
| **WHOIS** | Domains | `example.com`, `github.com` |
| **Sherlock** | Usernames/Names | `johndoe`, `John Doe`, `john.doe` |
| **VirusTotal** | IPs or Domains | `8.8.8.8`, `example.com` |
| **Censys** | IPs or Domains | `8.8.8.8`, `google.com` |

---

## 🏗️ Project Structure

```
osint-dashboard/
├── app.py                 # Main Flask application
├── ai_analyst.py          # AI analysis module
├── auth.py               # Authentication module
├── config.py             # Configuration management
├── validators.py         # Input validation
├── requirements.txt      # Python dependencies
├── .env                  # Environment variables (create this)
├── static/
│   ├── style.css        # Custom styles
│   └── script.js        # Frontend JavaScript
├── templates/
│   ├── index.html       # Main dashboard
│   └── settings.html    # Settings page
└── logs/                # Application logs
```

---

## 🔒 Security Features

- **Input Validation** - Prevents SQL injection and XSS attacks
- **Sanitization** - All user inputs are sanitized
- **Environment Variables** - Sensitive data stored securely
- **Session Management** - Secure cookie handling
- **Rate Limiting** - Protection against abuse

---

## 🐛 Troubleshooting

### GeoMap Not Loading
**Solution**: Restart the Flask server to apply the fix
```bash
# Stop server (Ctrl+C), then restart:
python app.py
```

### Sherlock GitHub Errors
**Solution**: The `--local` flag is now automatically used to prevent update checks

### Censys Input Errors
**Solution**: Censys now accepts both IP addresses and domain names

### Missing Dependencies
```bash
pip install -r requirements.txt --upgrade
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is for **educational and authorized security research purposes only**. Users are responsible for ensuring they have proper authorization before conducting any reconnaissance or intelligence gathering activities. Always follow ethical hacking guidelines and respect privacy laws.

---

## 🙏 Acknowledgments

- **Flask** - Web framework
- **Folium** - Map visualization
- **Google Gemini** - AI analysis
- **Shodan** - IP intelligence
- **theHarvester** - Domain reconnaissance
- **Sherlock** - Username search
- **Censys** - Host information

---

## 📧 Contact

For questions, issues, or suggestions, please open an issue on GitHub.

---

<div align="center">

**Made with ❤️ for the OSINT community**

⭐ Star this repo if you find it useful!

</div>
