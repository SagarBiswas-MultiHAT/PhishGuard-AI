#!/bin/bash

# Exit on any error
set -e

echo "=========================================="
echo "🛡️  PhishGuard Deployment Script (Ubuntu)"
echo "=========================================="

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo ./deploy.sh)"
  exit 1
fi

DOMAIN="phishguard.multihat.dev"
REPO_URL="https://github.com/SagarBiswas-MultiHAT/PhishGuard-AI.git"
APP_DIR="/var/www/phishguard"
USER="www-data"

echo "[1/6] Updating system packages..."
apt update && apt upgrade -y
apt install python3.11 python3.11-venv python3-pip git nginx certbot python3-certbot-nginx -y

echo "[2/6] Setting up Application Directory..."
if [ -d "$APP_DIR" ]; then
    echo "Directory $APP_DIR already exists. Updating repository..."
    cd $APP_DIR
    git pull
else
    echo "Cloning repository..."
    mkdir -p /var/www
    cd /var/www
    git clone $REPO_URL $APP_DIR
    cd $APP_DIR
fi

echo "[3/6] Setting up Python Virtual Environment..."
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-ai.txt
# Gunicorn is generally better for Linux production than Waitress, but we'll install waitress just in case it's what the app is hardcoded to.
pip install waitress gunicorn

echo "[4/6] Ensuring Environment Variables exist..."
if [ ! -f "$APP_DIR/.env" ]; then
    echo "WARNING: .env file not found. Copying .env.example..."
    if [ -f "$APP_DIR/.env.example" ]; then
        cp "$APP_DIR/.env.example" "$APP_DIR/.env"
        echo "Please edit $APP_DIR/.env and add your API keys!"
    else
        echo "OPENROUTER_API_KEY=\"\"" > "$APP_DIR/.env"
        echo "GROQ_API_KEY=\"\"" >> "$APP_DIR/.env"
        echo "Please edit $APP_DIR/.env and add your API keys!"
    fi
fi

# Fix ownership
chown -R $USER:$USER $APP_DIR

echo "[5/6] Configuring Systemd Service..."
cp $APP_DIR/deploy/phishguard.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable phishguard
systemctl restart phishguard

echo "[6/6] Configuring Nginx and SSL..."
cp $APP_DIR/deploy/phishguard.conf /etc/nginx/sites-available/phishguard
if [ ! -L /etc/nginx/sites-enabled/phishguard ]; then
    ln -s /etc/nginx/sites-available/phishguard /etc/nginx/sites-enabled/
fi

# Remove default nginx site if it exists
if [ -L /etc/nginx/sites-enabled/default ]; then
    rm /etc/nginx/sites-enabled/default
fi

# Test Nginx config
nginx -t

# Reload Nginx
systemctl reload nginx

echo "Attempting to generate SSL Certificate with Certbot..."
certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m admin@multihat.dev || echo "Note: SSL generation may have failed if DNS is not pointing to this IP yet. You can run 'certbot --nginx -d $DOMAIN' manually later."

echo "=========================================="
echo "✅ Deployment setup complete!"
echo "Make sure you update your API keys in $APP_DIR/.env"
echo "Restart the service after updating keys: sudo systemctl restart phishguard"
echo "=========================================="
