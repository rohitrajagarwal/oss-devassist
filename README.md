# OSS DevAssist - Open Source Security DevAssistant

A comprehensive security scanning and vulnerability management system for GitHub repositories. Combines static analysis, risk scoring, and AI-powered upgrade recommendations to help development teams identify and remediate vulnerable open source dependencies.

## Overview

**OSS DevAssist** consists of three main components:

1. **Package Extraction Script** (`extract_packages.py`) - CLI tool to scan repositories, detect packages, and identify vulnerabilities
2. **Flask API** (`app.py`) - Backend service that analyzes repositories and provides vulnerability recommendations
3. **Streamlit UI** (`ui_app.py`) - Interactive frontend for scanning GitHub repositories and viewing risk analysis

## Features

- **Package Extraction**: Parses Python files and Jupyter notebooks to identify imports
- **Repository Scanning**: Analyzes GitHub repos to identify open source dependencies
- **Vulnerability Detection**: Cross-references packages against OSV.dev vulnerability database
- **Risk Scoring**: Weighs vulnerabilities by severity and impact (High: 7.0+, Low: <7.0)
- **AI Risk Summaries**: Uses OpenAI to generate contextual risk assessments per vulnerability
- **AI Recommendations**: Provides "Must fix" vs "Can fix later" guidance
- **Visual Dashboard**: Clean, responsive UI showing risk scores, vulnerabilities, and recommendations
- **Database Integration**: Imports vulnerability data to MySQL for tracking and analysis
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

## Using extract_packages.py

The `extract_packages.py` script is a powerful CLI tool for scanning Python projects, extracting dependencies, and detecting vulnerabilities.

### Basic Usage

**Analyze local files:**
```bash
# Analyze local Jupyter notebook
python extract_packages.py

# Analyze specific Python file or notebook
python extract_packages.py --file path/to/file.py
python extract_packages.py --file path/to/notebook.ipynb

# Analyze entire directory
python extract_packages.py --dir path/to/project
```

**Analyze GitHub repositories:**
```bash
# Clone and analyze GitHub repo (uses temp directory)
python extract_packages.py --github https://github.com/user/repo

# Clone and keep local copy in github_repos/ directory
python extract_packages.py --github https://github.com/user/repo --keep
```

**Scan from extracted packages:**
```bash
# Scan vulnerabilities from previously extracted packages
python extract_packages.py --from-extracted

# Scan from specific extracted packages file
python extract_packages.py --from-extracted path/to/extracted_packages.txt
```

### Command-Line Options

| Flag | Description |
|------|-------------|
| `--github <URL>` | Clone and analyze a GitHub repository |
| `--file <PATH>` | Analyze a specific Python file or Jupyter notebook |
| `--dir <PATH>` | Analyze all Python files in a directory |
| `--keep` | Keep cloned GitHub repo in local `github_repos/` directory |
| `--no-versions` | Skip checking installed package versions |
| `--no-scan` | Extract packages only, skip vulnerability scanning |
| `--no-db` | Skip database import (keep data local only) |
| `--from-extracted [FILE]` | Load packages from `extracted_packages.txt` and scan |

### Output Files

The script generates several output files:

- **extracted_packages.txt** - List of detected packages with versions
- **vulnerability_report.json** - Raw vulnerability data from OSV.dev
- **vulnerability_report_enriched.json** - Enhanced report with additional fields
- **risk_summaries.json** - AI-generated risk summaries per vulnerability
- **enrichment_summary.txt** - Summary of enrichment process

### Full Workflow Example

```bash
# 1. Clone a GitHub repo and run full analysis
python extract_packages.py --github https://github.com/user/repo --keep

# 2. Script will:
#    - Clone the repository
#    - Extract all Python packages from .py and .ipynb files
#    - Check installed versions
#    - Query OSV.dev for vulnerabilities
#    - Enrich vulnerability data
#    - Generate AI-powered risk summaries
#    - Import data to MySQL database

# 3. Re-scan using extracted packages (faster, no repo cloning)
python extract_packages.py --from-extracted
```

### Database Import

By default, the script imports vulnerability data to MySQL. Configure database connection in `.env`:

```bash
MYSQL_HOST=your-database-host
MYSQL_DB=oss_vuln
MYSQL_USER=your-database-user
MYSQL_PASS=your-database-password
MYSQL_PORT=3306
```

Skip database import with `--no-db` flag if you only want local JSON reports.

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

### Prerequisites

- AWS EC2 instance (t2.medium or larger recommended)
- Amazon Linux 2 or Ubuntu 20.04+
- MySQL RDS instance or accessible MySQL database
- Security group allowing inbound traffic on ports 5003 (API) and 8501 (UI)
- SSH access to EC2 instance

### Deployment Steps

1. **Connect to your EC2 instance:**
```bash
ssh -i your-key.pem ec2-user@your-ec2-ip
```

2. **Clone or upload the project:**
```bash
# Option 1: Clone from git
git clone https://github.com/your-org/oss-devassist.git
cd oss-devassist

# Option 2: Upload via SCP
# (from local machine)
scp -i your-key.pem -r "OSS DevAssist Server" ec2-user@your-ec2-ip:~/
```

3. **Create `.env` file with your configuration:**
```bash
cat > .env << EOF
PORT=5003
OPENAI_API_KEY=your-openai-api-key
MYSQL_HOST=your-rds-endpoint.rds.amazonaws.com
MYSQL_DB=oss_vuln
MYSQL_USER=admin
MYSQL_PASS=your-database-password
MYSQL_PORT=3306
EOF
```

4. **Run the deployment script:**
```bash
chmod +x deploy.sh
./deploy.sh
```

The script will automatically:
- Detect OS (Amazon Linux/Ubuntu) and install dependencies (Python 3.11, pip, supervisor, git)
- Set up Python virtual environment
- Install Python packages from requirements-fixed.txt
- Configure supervisor for process management
- Create systemd services for supervisor (Amazon Linux)
- Start Flask API (port 5003) and Streamlit UI (port 8501)
- Display public IP address via IMDSv2

5. **Verify deployment:**
```bash
# Check service status
sudo supervisorctl status

# Should show:
# flask-api                        RUNNING   pid 1234, uptime 0:00:05
# streamlit-ui                     RUNNING   pid 1235, uptime 0:00:05
```

**Access deployed application:**
- UI: `http://<EC2-PUBLIC-IP>:8501`
- API: `http://<EC2-PUBLIC-IP>:5003/health`
- API endpoint: `http://<EC2-PUBLIC-IP>:5003/upgrade-recommendation`

### Managing Services

**Control services:**
```bash
sudo supervisorctl status          # Check all services
sudo supervisorctl restart flask-api
sudo supervisorctl restart streamlit-ui
sudo supervisorctl stop flask-api
sudo supervisorctl start flask-api
sudo supervisorctl restart all     # Restart both services
```

**View logs:**
```bash
# Real-time log monitoring
sudo tail -f /var/log/flask-api.err.log
sudo tail -f /var/log/streamlit-ui.err.log

# View full logs
sudo cat /var/log/flask-api.out.log
sudo cat /var/log/supervisor/supervisord.log
```

**Restart after code changes:**
```bash
cd /var/www/oss-devassist
git pull  # or update files
sudo supervisorctl restart all
```

### Security Group Configuration

Ensure your EC2 security group allows:

| Type | Port | Source | Description |
|------|------|--------|-------------|
| SSH | 22 | Your IP | SSH access |
| Custom TCP | 5003 | 0.0.0.0/0 | Flask API |
| Custom TCP | 8501 | 0.0.0.0/0 | Streamlit UI |
| Custom TCP | 3306 | EC2 SG | MySQL (if using RDS) |

### Database Setup

If using AWS RDS:

1. **Create MySQL RDS instance** (db.t3.micro for testing)
2. **Configure security group** to allow EC2 instance access on port 3306
3. **Create database schema:**
```bash
# Download DDL file or use provided SQL
mysql -h your-rds-endpoint -u admin -p oss_vuln < OSS_assistant_db_DDL.sql
```
4. **Update `.env` file** with RDS endpoint and credentials

### Troubleshooting Deployment

**Supervisor not starting:**
```bash
# Amazon Linux - check systemd service
sudo systemctl status supervisord
sudo systemctl restart supervisord

# Ubuntu/Debian
sudo systemctl status supervisor
sudo systemctl restart supervisor
```

**Port already in use:**
```bash
# Check what's using port 5003 or 8501
sudo lsof -i :5003
sudo lsof -i :8501

# Kill process if needed
sudo kill -9 <PID>
```

**Python version issues:**
```bash
# Verify Python 3.11 is installed
python3.11 --version

# Reinstall if needed (Amazon Linux)
sudo yum install -y python3.11 python3.11-pip
```

**Dependencies not installing:**
```bash
# Manually create venv and install
cd /var/www/oss-devassist
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements-fixed.txt
```

## File Structure

```
├── extract_packages.py         # CLI tool for package extraction & vulnerability scanning
├── app.py                      # Flask API backend
├── ui_app.py                   # Streamlit UI frontend
├── config.py                   # Configuration loader
├── deploy.sh                   # AWS EC2 deployment script
├── requirements-fixed.txt      # Python dependencies (pinned versions)
├── requirements.txt            # Python dependencies
├── OSS_assistant_db_DDL.sql   # Database schema
├── extracted_packages.txt      # Generated: extracted package list
├── vulnerability_report.json   # Generated: vulnerability data
├── vulnerability_report_enriched.json  # Generated: enriched vulnerability data
├── risk_summaries.json         # Generated: AI risk summaries
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