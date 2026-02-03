#!/usr/bin/env python3
"""
Flask API for OSS DevAssist - Upgrade Recommendation Service
Provides vulnerability analysis and upgrade recommendations for GitHub repositories.
"""

from flask import Flask, request, jsonify
import mysql.connector
import os
from dotenv import load_dotenv
from typing import Dict, List, Any
from openai import OpenAI
import json

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Initialize OpenAI client
client = None
if os.environ.get('OPENAI_API_KEY'):
    client = OpenAI(api_key=os.environ['OPENAI_API_KEY'])
else:
    print("⚠️  Warning: OPENAI_API_KEY not found. AI recommendations will be disabled.")

# Database configuration
DB_CONFIG = {
    'host': os.environ.get('MYSQL_HOST'),
    'user': os.environ.get('MYSQL_USER'),
    'password': os.environ.get('MYSQL_PASS'),
    'database': os.environ.get('MYSQL_DB'),
    'port': int(os.environ.get('MYSQL_PORT', 3306))
}


def get_db_connection():
    """Create and return a database connection."""
    return mysql.connector.connect(**DB_CONFIG)


def parse_severity(severity_str: str) -> float:
    """
    Parse severity string to numeric value.
    Handles formats like 'HIGH', 'MODERATE', 'LOW', or numeric strings.
    """
    severity_map = {
        'CRITICAL': 10.0,
        'HIGH': 8.5,
        'MODERATE': 5.0,
        'MEDIUM': 5.0,
        'LOW': 2.0,
        'UNKNOWN': 0.0
    }
    
    # Try to parse as float first
    try:
        return float(severity_str)
    except (ValueError, TypeError):
        # Fall back to string mapping
        return severity_map.get(str(severity_str).upper(), 0.0)


def get_ai_upgrade_decision_for_package(package_name: str, package_data: Dict[str, Any]) -> Dict[str, str]:
    """
    Use OpenAI to determine upgrade urgency for a specific package.
    
    Returns:
        Dictionary with 'decision' and 'reasoning' keys.
        Decision is one of: 'Must fix', 'Can fix later'
    """
    system_prompt = """You are an OSS security advisor. Based on a single package's vulnerability data, determine upgrade urgency.

Respond with ONE of these decisions:
- "Must fix" - Requires immediate remediation
- "Can fix later" - Can be fixed in future release. Not urgent.

Provide brief reasoning (under 50 words).

Output ONLY valid JSON with this structure:
{
  "decision": "Must fix|Can fix later",
  "reasoning": "brief explanation"
}"""

    user_prompt = f"""Analyze this package and provide upgrade recommendation:

Package: {package_name}
Current Version: {package_data.get('version', 'unknown')}
Fixed In: {package_data.get('fixed_in', 'no fix available')}
Severity: {package_data.get('severity', 'UNKNOWN')} (score: {package_data.get('severity_score', 0)})
Vulnerability ID: {package_data.get('vulnerability_id', 'N/A')}
Vulnerability Summary: {package_data.get('vulnerability_summary', 'N/A')}
Risk Summary: {package_data.get('risk_summary', 'No risk summary available')}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.3,
        response_format={"type": "json_object"}
    )
    
    ai_response = json.loads(response.choices[0].message.content)
    return ai_response


@app.route('/upgrade-recommendation', methods=['POST'])
def upgrade_recommendation():
    """
    API endpoint to get upgrade recommendations for vulnerable packages in a GitHub repo.
    
    Request Body:
        {
            "repo_url": "https://github.com/user/repo"
        }
    
    Response:
        {
            "repo_url": "https://github.com/user/repo",
            "high_impact": [
                {
                    "package": "package_name",
                    "version": "1.0.0",
                    "fixed_in": "1.2.0",
                    "risk_summary": "...",
                    "severity": "HIGH",
                    "vulnerability_id": "GHSA-xxxx"
                }
            ],
            "low_impact": [...]
        }
    """
    try:
        # Get repo_url from request
        data = request.get_json()
        if not data or 'repo_url' not in data:
            return jsonify({
                'error': 'Missing required parameter: repo_url'
            }), 400
        
        repo_url = data['repo_url']
        
        # Connect to database
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get project ID for the repo
        cursor.execute(
            "SELECT p_id FROM projects WHERE repo = %s",
            (repo_url,)
        )
        project = cursor.fetchone()
        
        if not project:
            cursor.close()
            conn.close()
            return jsonify({
                'error': f'Repository not found in database: {repo_url}. Please run the extract_packages.py script to set the foundation for upgrade recommendation.',
                'repo_url': repo_url
            }), 404
        
        p_id = project['p_id']
        
        # Query to get all vulnerable packages with their details
        query = """
        SELECT 
            pv.package_name,
            pv.version,
            pv.fixed_in,
            pv.risk_summary,
            v.v_id as vulnerability_id,
            v.severity,
            v.summary as vulnerability_summary,
            v.published,
            v.modified
        FROM package_vulnerabilities pv
        JOIN vulnerabilities v ON pv.v_id = v.v_id
        WHERE pv.p_id = %s
        ORDER BY pv.package_name, v.severity DESC
        """
        
        cursor.execute(query, (p_id,))
        vulnerabilities = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        # Process and categorize vulnerabilities
        high_impact = []
        low_impact = []
        
        for vuln in vulnerabilities:
            # Parse severity score
            severity_score = parse_severity(vuln['severity'])
            
            # Build vulnerability entry with package name as key
            vuln_entry = {
                vuln['package_name']: {
                    'version': vuln['version'] or 'unknown',
                    'fixed_in': vuln['fixed_in'] or 'no fix available',
                    'risk_summary': vuln['risk_summary'] or 'No risk summary available',
                    'severity': vuln['severity'],
                    'severity_score': severity_score,
                    'vulnerability_id': vuln['vulnerability_id'],
                    'vulnerability_summary': vuln['vulnerability_summary'],
                    'published': str(vuln['published']) if vuln['published'] else None,
                    'modified': str(vuln['modified']) if vuln['modified'] else None
                }
            }
            
            # Categorize based on severity score
            if severity_score >= 7.0:
                high_impact.append(vuln_entry)
            else:
                low_impact.append(vuln_entry)
        
        # Add AI recommendations to each package
        if client:
            for vuln_entry in high_impact:
                for pkg_name, pkg_data in vuln_entry.items():
                    try:
                        ai_rec = get_ai_upgrade_decision_for_package(pkg_name, pkg_data)
                        pkg_data['ai_recommendation'] = ai_rec
                    except Exception as e:
                        pkg_data['ai_recommendation'] = {
                            'error': f'AI recommendation failed: {str(e)}',
                            'decision': 'manual_review_required'
                        }
            
            for vuln_entry in low_impact:
                for pkg_name, pkg_data in vuln_entry.items():
                    try:
                        ai_rec = get_ai_upgrade_decision_for_package(pkg_name, pkg_data)
                        pkg_data['ai_recommendation'] = ai_rec
                    except Exception as e:
                        pkg_data['ai_recommendation'] = {
                            'error': f'AI recommendation failed: {str(e)}',
                            'decision': 'manual_review_required'
                        }
        else:
            # Add unavailable message to each package
            for vuln_entry in high_impact + low_impact:
                for pkg_name, pkg_data in vuln_entry.items():
                    pkg_data['ai_recommendation'] = {
                        'decision': 'ai_unavailable',
                        'message': 'OpenAI API key not configured'
                    }
        
        # Build response
        response = {
            'repo_url': repo_url,
            'total_vulnerabilities': len(vulnerabilities),
            'high_impact_count': len(high_impact),
            'low_impact_count': len(low_impact),
            'high_impact': high_impact,
            'low_impact': low_impact
        }
        
        return jsonify(response), 200
    
    except mysql.connector.Error as db_err:
        return jsonify({
            'error': 'Database error',
            'details': str(db_err)
        }), 500
    
    except Exception as e:
        return jsonify({
            'error': 'Internal server error',
            'details': str(e)
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e)
        }), 503


@app.route('/', methods=['GET'])
def index():
    """API documentation endpoint."""
    return jsonify({
        'service': 'OSS DevAssist - Upgrade Recommendation API',
        'version': '1.0.0',
        'endpoints': {
            '/upgrade-recommendation': {
                'method': 'POST',
                'description': 'Get upgrade recommendations for vulnerable packages in a GitHub repo',
                'request_body': {
                    'repo_url': 'GitHub repository URL'
                },
                'example': {
                    'repo_url': 'https://github.com/user/repo'
                }
            },
            '/health': {
                'method': 'GET',
                'description': 'Health check endpoint'
            }
        }
    }), 200


if __name__ == '__main__':
    # Check if database configuration is available
    if not all([DB_CONFIG['host'], DB_CONFIG['user'], DB_CONFIG['password'], DB_CONFIG['database']]):
        print("⚠️  Warning: Database configuration incomplete!")
        print("   Please set environment variables: MYSQL_HOST, MYSQL_USER, MYSQL_PASS, MYSQL_DB")
        print("   The API will not work without proper database configuration.\n")
    
    # Run the Flask app
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    print(f"🚀 Starting OSS DevAssist API on port {port}...")
    print(f"   Database: {DB_CONFIG['host']}/{DB_CONFIG['database']}")
    print(f"   Debug mode: {debug}\n")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
