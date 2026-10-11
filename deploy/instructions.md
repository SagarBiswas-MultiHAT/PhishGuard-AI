# PhishGuard Deployment Guide (A to Z)

This document contains the complete, step-by-step instructions for deploying the PhishGuard application to a production Ubuntu server (like a DigitalOcean Droplet) using Cloudflare for DNS and SSL.

## Prerequisites
- A DigitalOcean Droplet running **Ubuntu 24.04 LTS**.
- A domain name (e.g., `multihat.dev`) managed via **Cloudflare**.
- The `OPENROUTER_API_KEY` and `GROQ_API_KEY` for the AI integration.

---

## Phase 1: Cloudflare DNS Setup
Before touching the server, we must ensure your domain points to your new Droplet.

1. Log into your **Cloudflare Dashboard**.
2. Go to your domain settings and click on **DNS -> Records**.
3. Click **Add record** and configure it as follows:
   - **Type**: `A`
   - **Name**: `phishguard` (This creates `phishguard.yourdomain.com`)
   - **IPv4 address**: Your DigitalOcean Droplet's IP Address
   - **Proxy status**: Proxied (Orange Cloud turned ON)
4. Ensure your **SSL/TLS encryption mode** in Cloudflare is set to **Full**.

---

## Phase 2: Server Initialization
Log into your server via SSH:
```bash
ssh root@your_droplet_ip_address
```

Update your server's package list and upgrade any outdated software:
```bash
apt update && apt upgrade -y
```

Install the essential foundation software (Python, Git, Nginx, and Certbot):
```bash
apt install python3-venv python3-pip git nginx certbot python3-certbot-nginx -y
```

---

## Phase 3: Application Setup
Create the standard web directory, clone your code from GitHub, and move into the project folder.

```bash
mkdir -p /var/www
cd /var/www
git clone https://github.com/SagarBiswas-MultiHAT/PhishGuard-AI.git phishguard
cd phishguard
```

Set up an isolated Python environment and install the application dependencies:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-ai.txt
pip install waitress gunicorn
```

---

## Phase 4: Environment Variables (Secrets)
The application requires your API keys to function. Create the `.env` file manually:

```bash
cp .env.example .env
nano .env
```

If `.env.example` is missing or empty, simply paste the following into the editor:
```bash
OPENROUTER_API_KEY="your_openrouter_key_here"
GROQ_API_KEY="your_groq_key_here"
```

*Press `Ctrl+O`, `Enter`, and `Ctrl+X` to save and exit.*

Give the service account ownership of the application files and feedback directory:
```bash
mkdir -p /var/www/phishguard/FeedBack
chown -R www-data:www-data /var/www/phishguard
chmod 600 /var/www/phishguard/.env
```

---

## Phase 5: Systemd Background Service
To keep the application running 24/7 (even after we close the terminal or restart the server), we create a systemd service.

Open a new service file:
```bash
nano /etc/systemd/system/phishguard.service
```

Paste the following configuration:
```ini
[Unit]
Description=Waitress instance to serve PhishGuard
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/phishguard
Environment="PATH=/var/www/phishguard/.venv/bin"
EnvironmentFile=/var/www/phishguard/.env
ExecStart=/var/www/phishguard/.venv/bin/waitress-serve --port=5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Reload systemd to recognize the file, enable it to run on boot, and start it immediately:
```bash
systemctl daemon-reload
systemctl enable phishguard
systemctl start phishguard
```

Verify it is running:
```bash
systemctl status phishguard
```
*(We should see `Active: active (running)` in green).*

---

## Phase 6: Nginx Reverse Proxy Setup
Nginx acts as the front door, taking incoming web traffic on port 80 and forwarding it to your Python app running on port 5000.

Create an Nginx configuration file:
```bash
nano /etc/nginx/sites-available/phishguard
```

Paste the following block (replace `phishguard.multihat.dev` with your actual domain):
```nginx
server {
    listen 80;
    server_name phishguard.multihat.dev;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the configuration and disable the default Nginx page:
```bash
ln -s /etc/nginx/sites-available/phishguard /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default
```

Test the configuration for syntax errors:
```bash
nginx -t
```
*(It should say `syntax is ok` and `test is successful`).*

Reload Nginx to apply the changes smoothly:
```bash
systemctl reload nginx
```

---

## Phase 7: SSL Certificate (Let's Encrypt)
Finally, secure your domain with an SSL certificate so Cloudflare can securely proxy the traffic. Let's Encrypt provides this via Certbot.

Run the automatic Certbot tool:
```bash
certbot --nginx -d phishguard.multihat.dev
```

*Follow the prompts (enter your email, accept the TOS). Certbot will automatically alter your Nginx configuration to support HTTPS (Port 443).*

### Maintenance & Commands

- **Restart the App** (e.g., after changing API keys or pulling new code): 
  `systemctl restart phishguard`
- **View App Logs** (useful for debugging errors): 
  `journalctl -u phishguard -f`
- **Update Code**: 
  `cd /var/www/phishguard && git pull && systemctl restart phishguard`
