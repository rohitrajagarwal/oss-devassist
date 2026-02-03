#!/bin/bash
# Quick deployment script for OSS DevAssist

echo "🚀 OSS DevAssist Deployment Script"
echo "=================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect OS and set package manager
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS=$(uname -s)
fi

# Update system
echo -e "${YELLOW}Step 1: Updating system packages...${NC}"
if [[ "$OS" == "amzn" ]] || [[ "$OS" == "amazon" ]]; then
    # Amazon Linux
    sudo yum update -y
elif [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
    # Ubuntu/Debian
    sudo apt update && sudo apt upgrade -y
else
    echo "⚠️  Unsupported OS. Continuing anyway..."
fi

# Install dependencies
echo -e "${YELLOW}Step 2: Installing system dependencies...${NC}"
if [[ "$OS" == "amzn" ]] || [[ "$OS" == "amazon" ]]; then
    # Amazon Linux
    sudo yum install -y python3.11 python3.11-pip git
    sudo pip3.11 install supervisor
    
    # Create supervisor directories
    sudo mkdir -p /etc/supervisor/conf.d
    sudo mkdir -p /var/log/supervisor
    
    # Create supervisor config
    sudo tee /etc/supervisord.conf > /dev/null <<EOF
[unix_http_server]
file=/var/run/supervisor.sock

[supervisord]
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid
childlogdir=/var/log/supervisor

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=unix:///var/run/supervisor.sock

[include]
files = /etc/supervisor/conf.d/*.conf
EOF
    
    # Create systemd service for supervisor
    sudo tee /etc/systemd/system/supervisord.service > /dev/null <<EOF
[Unit]
Description=Supervisor process control system
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/supervisord -c /etc/supervisord.conf
ExecReload=/usr/local/bin/supervisorctl reload
ExecStop=/usr/local/bin/supervisorctl shutdown
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    sudo systemctl enable supervisord
    sudo systemctl start supervisord
    
elif [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
    # Ubuntu/Debian
    sudo apt install -y python3.11 python3.11-venv python3-pip supervisor git
    sudo systemctl enable supervisor
    sudo systemctl start supervisor
fi

echo "✓ Dependencies installed for $OS"

# Create app directory
echo -e "${YELLOW}Step 3: Setting up application directory...${NC}"
sudo mkdir -p /var/www/oss-devassist
sudo chown $USER:$USER /var/www/oss-devassist

# Check if we're in the right directory
if [ ! -f "app.py" ]; then
    echo "⚠️  Error: app.py not found. Please run this script from your project directory."
    exit 1
fi

# Copy files (only essential application files)
echo -e "${YELLOW}Step 4: Copying application files...${NC}"
cp app.py /var/www/oss-devassist/
cp ui_app.py /var/www/oss-devassist/
cp .env /var/www/oss-devassist/
# Copy requirements file (needed for pip install)
if [ -f requirements-fixed.txt ]; then
    cp requirements-fixed.txt /var/www/oss-devassist/
elif [ -f requirements.txt ]; then
    cp requirements.txt /var/www/oss-devassist/
fi
# Copy config.py if it exists
[ -f config.py ] && cp config.py /var/www/oss-devassist/

echo "✓ Copied essential application files"
cd /var/www/oss-devassist

# Create virtual environment
echo -e "${YELLOW}Step 5: Creating Python virtual environment...${NC}"
python3.11 -m venv venv
source venv/bin/activate

# Install Python packages
echo -e "${YELLOW}Step 6: Installing Python packages...${NC}"
pip install --upgrade pip
if [ -f "requirements-fixed.txt" ]; then
    pip install -r requirements-fixed.txt
else
    pip install -r requirements.txt
fi
pip install gunicorn streamlit

# Create supervisor configs
echo -e "${YELLOW}Step 7: Configuring process management...${NC}"

# Flask API supervisor config
sudo tee /etc/supervisor/conf.d/flask-api.conf > /dev/null <<EOF
[program:flask-api]
command=/var/www/oss-devassist/venv/bin/gunicorn -w 4 -b 0.0.0.0:5003 app:app
directory=/var/www/oss-devassist
user=$USER
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true
stderr_logfile=/var/log/flask-api.err.log
stdout_logfile=/var/log/flask-api.out.log
environment=PATH="/var/www/oss-devassist/venv/bin"
EOF

# Streamlit supervisor config
sudo tee /etc/supervisor/conf.d/streamlit-ui.conf > /dev/null <<EOF
[program:streamlit-ui]
command=/var/www/oss-devassist/venv/bin/streamlit run ui_app.py --server.port 8501 --server.address 0.0.0.0 --server.headless true
directory=/var/www/oss-devassist
user=$USER
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true
stderr_logfile=/var/log/streamlit-ui.err.log
stdout_logfile=/var/log/streamlit-ui.out.log
environment=PATH="/var/www/oss-devassist/venv/bin"
EOF

# Get public IP for display using IMDSv2 (token-based)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s 2>/dev/null)
if [ -n "$TOKEN" ]; then
    PUBLIC_IP=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)
else
    # Fallback to IMDSv1 if token fails
    PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)
fi

# If still no IP, try hostname -I as last resort
if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(hostname -I | awk '{print $1}')
fi

# Start services
echo -e "${YELLOW}Step 8: Starting services...${NC}"
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start flask-api
sudo supervisorctl start streamlit-ui

# Configure firewall
echo -e "${YELLOW}Step 9: Configuring firewall...${NC}"
sudo ufw allow OpenSSH
sudo ufw allow 5003/tcp  # Flask API
sudo ufw allow 8501/tcp  # Streamlit UI
echo "y" | sudo ufw enable

echo -e "${GREEN}=================================="
echo "✅ Deployment Complete!"
echo "==================================${NC}"
echo ""
echo -e "${GREEN}Access your application:${NC}"
echo "  Streamlit UI: http://$PUBLIC_IP:8501"
echo "  Flask API: http://$PUBLIC_IP:5003/upgrade-recommendation"
echo ""
echo -e "${YELLOW}Important: Make sure EC2 Security Group allows:${NC}"
echo "  - Port 5003 (Flask API)"
echo "  - Port 8501 (Streamlit UI)"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo "  Check status: sudo supervisorctl status"
echo "  View logs: sudo tail -f /var/log/flask-api.out.log"
echo "  Restart: sudo supervisorctl restart flask-api streamlit-ui"
