# PhishGuard Deployment Scripts

This folder contains all the files needed to quickly deploy PhishGuard onto an Ubuntu server (like a DigitalOcean Droplet).

## How to Deploy

1. Ensure your domain (`phishguard.multihat.dev`) has an **A Record** pointing to your Droplet's IP address via Cloudflare. Set the Cloudflare proxy to "Proxied" (Orange Cloud) and ensure your SSL mode in Cloudflare is "Full" or "Full (Strict)".

2. SSH into your server:
   ```bash
   ssh root@your_server_ip
   ```

3. Clone this repository onto your server (if you haven't already):
   ```bash
   git clone https://github.com/SagarBiswas-MultiHAT/PhishGuard-AI.git
   cd PhishGuard-AI/deploy
   ```

4. Make the deployment script executable and run it:
   ```bash
   chmod +x deploy.sh
   sudo ./deploy.sh
   ```

5. Once it completes, you will need to add your API keys to the `.env` file in the main app directory:
   ```bash
   sudo nano /var/www/phishguard/.env
   ```
   Add your `OPENROUTER_API_KEY` and `GROQ_API_KEY` and save the file.

6. Finally, restart the application so it picks up the new keys:
   ```bash
   sudo systemctl restart phishguard
   ```

Your site should now be live at **https://phishguard.multihat.dev**!
