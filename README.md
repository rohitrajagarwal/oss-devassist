# OSS DevAssist - Open Source Security DevAssistant

A comprehensive security scanning and vulnerability management system for GitHub repositories. Combines static analysis, risk scoring, and AI-powered upgrade recommendations to help development teams identify and remediate vulnerable open source dependencies.

## Overview

**OSS DevAssist** consists of two main components:

1. **Flask API** (`app.py`) - Backend service that analyzes repositories and provides vulnerability recommendations
2. **Streamlit UI** (`ui_app.py`) - Interactive frontend for scanning GitHub repositories and viewing risk analysis

## Features

- **Repository Scanning**: Parses GitHub repos to identify open source dependencies
- **Vulnerability Detection**: Cross-references packages against vulnerability databases
- **Risk Scoring**: Weighs vulnerabilities by severity and impact (High: 7.0+, Low: <7.0)
- **AI Recommendations**: Uses OpenAI to provide "Must fix" vs "Can fix later" guidance
- **Visual Dashboard**: Clean, responsive UI showing risk scores, vulnerabilities, and recommendations
- **AWS EC2 Ready**: Automated deployment scripts with supervisor process management

## Quick Start

### Prerequisites

- Python 3.11+
- MySQL 8.0+ (RDS or local)
- OpenAI API key
- GitHub repository access

### Installation

1. **Clone/Download the project** and navigate to the directory:
```bash
cd "OSS DevAssist Server"
```

2. **Install dependencies**:
```bash
pip install -r requirements-fixed.txt
```

3. **Configure environment variables** - Create a `.env` file:
```bash
PORT=5003
OPENAI_API_KEY=your-openai-api-key
MYSQL_HOST=your-database-host
MYSQL_DB=oss_vuln
MYSQL_USER=your-database-user
MYSQL_PASS=your-database-password
MYSQL_PORT=3306
```

4. **Run locally** (two terminals):

Terminal 1 - Flask API:
```bash
python app.py
```

Terminal 2 - Streamlit UI:
```bash
streamlit run ui_app.py
```

The UI will open at `http://localhost:8501`

## Architecture

```
┌─────────────────────────────────────┐
│  Streamlit UI (port 8501)           │
│  - Repository input form            │
│  - Risk score display               │
│  - Vulnerability listings           │
│  - AI recommendations               │
└──────────────┬──────────────────────┘
               │
               │ HTTP POST
               ↓
┌──────────────────────────────────────┐
│  Flask API (port 5003)               │
│  - /upgrade-recommendation endpoint  │
│  - GitHub repo parsing               │
│  - Vulnerability lookup              │
│  - AI analysis via OpenAI            │
└──────────────┬──────────────────────┘
               │
               ↓
┌──────────────────────────────────────┐
│  MySQL Database (RDS)                │
│  - Project inventory                 │
│  - Vulnerability data                │
│  - Package information               │
└──────────────────────────────────────┘
```

## API Endpoints

### POST /upgrade-recommendation

Analyzes a GitHub repository for vulnerable packages and provides upgrade recommendations.

**Request:**
```json
{
  "repo_url": "https://github.com/org/repo"
}
```

**Response:**
```json
{
  "repo_url": "https://github.com/org/repo",
  "total_vulnerabilities": 5,
  "high_impact_count": 2,
  "low_impact_count": 3,
  "high_impact": [
    {
      "package_name": "requests",
      "version": "2.25.0",
      "fixed_in": "2.31.0",
      "severity": "HIGH",
      "vulnerability_id": "GHSA-xxxx-yyyy-zzzz",
      "vulnerability_summary": "Remote code execution",
      "risk_summary": "Critical vulnerability allowing code execution...",
      "ai_recommendation": {
        "decision": "Must fix",
        "reasoning": "Critical severity with active exploits in the wild."
      }
    }
  ],
  "low_impact": [...]
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "ok"
}
```

## AWS EC2 Deployment

Automated deployment script is provided for Amazon Linux 2:

```bash
./deploy.sh
```

This script:
- Detects OS (Amazon Linux/Ubuntu) and installs dependencies
- Sets up Python virtual environment
- Configures supervisor for process management
- Starts Flask API and Streamlit UI
- Retrieves public IP via IMDSv2

**Access deployed application:**
- UI: `http://<EC2-IP>:8501`
- API: `http://<EC2-IP>:5003/upgrade-recommendation`

**Manage processes:**
```bash
sudo supervisorctl status          # Check services
sudo supervisorctl restart flask-api
sudo supervisorctl restart streamlit-ui
```

**View logs:**
```bash
sudo tail -f /var/log/flask-api.err.log
sudo tail -f /var/log/streamlit-ui.err.log
```

## File Structure

```
├── app.py                      # Flask API backend
├── ui_app.py                   # Streamlit UI frontend
├── config.py                   # Configuration loader
├── deploy.sh                   # AWS EC2 deployment script
├── requirements-fixed.txt      # Python dependencies (pinned versions)
├── OSS_assistant_db_DDL.sql   # Database schema
├── .env                        # Environment variables (not in git)
├── README.md                   # This file
└── .gitignore                  # Git ignore patterns
```

## Key Dependencies

- **openai>=1.12.0** - OpenAI API client
- **flask** - Web framework for API
- **streamlit** - Web framework for UI
- **mysql-connector-python** - MySQL database driver
- **requests** - HTTP library
- **python-dotenv** - Environment variable management

## Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PORT` | Flask API port | `5003` |
| `OPENAI_API_KEY` | OpenAI API key | `sk-...` |
| `MYSQL_HOST` | Database host | `oss-vuln.xxx.rds.amazonaws.com` |
| `MYSQL_DB` | Database name | `oss_vuln` |
| `MYSQL_USER` | Database user | `admin` |
| `MYSQL_PASS` | Database password | `***` |
| `MYSQL_PORT` | Database port | `3306` |

### AI Recommendation Categories

The system provides two types of recommendations:

- **Must fix**: Requires immediate remediation (high severity, active exploits, etc.)
- **Can fix later**: Can be fixed in future release (moderate severity, no active exploits, etc.)

## Troubleshooting

### Connection Timeout
- Verify AWS security group allows ports 5003 (API) and 8501 (UI)
- Check Flask API is running: `curl http://localhost:5003/health`

### "Repository not found" Error
- Verify repo URL format: `https://github.com/org/repo`
- Check database connectivity and repo existence in database

### OpenAI API Errors
- Verify `OPENAI_API_KEY` is set correctly
- Check OpenAI account has available quota
- Ensure using gpt-4o-mini model (or update model reference)

### Streamlit UI Not Loading
- Check both Flask API and Streamlit processes are running
- Verify `.env` file is in correct location
- Check firewall allows port 8501

## Security Notes

- `.env` file contains sensitive credentials - never commit to git
- Private key files (`*.pem`) should not be committed
- Output reports (`vulnerability*.json`) are gitignored by default
- Use AWS IAM roles for RDS authentication in production

## Testing the API

### Using curl

```bash
# Test upgrade-recommendation endpoint
curl -X POST http://localhost:5003/upgrade-recommendation \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/user/repo"}'

# Test health endpoint
curl http://localhost:5003/health
```

### Using Python requests

```python
import requests

response = requests.post(
    'http://localhost:5003/upgrade-recommendation',
    json={'repo_url': 'https://github.com/user/repo'}
)
print(response.json())
```