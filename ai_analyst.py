import os
import json
import re
import google.generativeai as genai
from config import Config

class AIAnalyst:
    def __init__(self):
        self.api_key = Config.GEMINI_API_KEY
        self._configured = False
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self._configured = True

    def _ensure_configured(self):
        if not self._configured:
             # Try reloading in case it was set after init
            self.api_key = os.environ.get('GEMINI_API_KEY')
            if self.api_key:
                genai.configure(api_key=self.api_key)
                self._configured = True
        return self._configured

    def analyze_findings(self, findings):
        """
        Analyzes a list of findings to provide a summary, threat classification, and risk score.
        """
        if not self._ensure_configured():
            return {
                "summary": "AI Analysis unavailable (Gemini API Key missing).",
                "threat_level": "Unknown",
                "risk_score": 0,
                "recommendations": ["Configure Gemini API Key in Settings."]
            }

        # Prepare context from findings (limit length to avoid token limits)
        context = json.dumps(findings[:50], default=str) 
        
        prompt = f"""
        Analyze the following OSINT findings and provide a security assessment.
        
        Findings Data:
        {context}
        
        Return a JSON response with the following structure:
        {{
            "summary": "A concise executive summary of the findings (max 3 sentences).",
            "threat_level": "Low/Medium/High/Critical",
            "risk_score": <integer 0-100>,
            "recommendations": ["List of 3 actionable security recommendations"]
        }}
        """

        try:
            model = genai.GenerativeModel('gemini-2.0-flash-lite')
            response = model.generate_content(prompt)
            
            # Clean up response text to ensure valid JSON
            content = response.text
            content = content.replace('```json', '').replace('```', '').strip()
            
            return json.loads(content)
        except Exception as e:
            print(f"AI Analysis Error: {e}")
            return {
                "summary": "Error performing AI analysis.",
                "threat_level": "Unknown",
                "risk_score": 0,
                "recommendations": []
            }

    def extract_iocs(self, text_data):
        """
        Extracts IOCs (IPs, Domains, Hashes) from text using Regex (faster/cheaper than AI for this).
        """
        iocs = {
            "ips": [],
            "domains": [],
            "hashes": []
        }
        
        # IP Regex (IPv4)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs["ips"] = list(set(re.findall(ip_pattern, text_data)))

        # Domain Regex (Simplified)
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        # Filter out common false positives or IPs matched as domains
        domains = re.findall(domain_pattern, text_data)
        iocs["domains"] = list(set([d for d in domains if not re.match(ip_pattern, d)]))

        # Hash Regex (MD5, SHA1, SHA256)
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        iocs["hashes"] = list(set(re.findall(hash_pattern, text_data)))

        return iocs

    def chat_with_data(self, query, findings_context):
        """
        Allows the user to ask natural language questions about the collected data.
        """
        if not self._ensure_configured():
            return "AI Chat unavailable. Please configure your Gemini API Key."

        context = json.dumps(findings_context[:50], default=str)

        prompt = f"""
        You are a helpful OSINT assistant. Answer questions based strictly on the provided findings data. 
        If the answer isn't in the data, say so.
        
        Current Findings Data: {context}
        
        User Question: {query}
        """

        try:
            model = genai.GenerativeModel('gemini-2.0-flash-lite')
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error processing query: {str(e)}"

    def generate_comprehensive_report(self, findings):
        """
        Generates a detailed narrative report based on findings.
        """
        if not self._ensure_configured():
            return "AI Reporting unavailable."

        context = json.dumps(findings[:100], default=str) # More context for report

        prompt = f"""
        Generate a comprehensive Threat Intelligence Report based on the following findings.
        
        Findings:
        {context}
        
        The report should be in Markdown format and include:
        1. Executive Summary
        2. Key Findings (Bullet points)
        3. Technical Analysis (Patterns, Anomalies)
        4. Risk Assessment
        5. Mitigation Strategies
        
        Format the output as clean Markdown.
        """

        try:
            model = genai.GenerativeModel('gemini-2.0-flash-lite')
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error generating report: {str(e)}"
