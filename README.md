# 🛡️ PhishGuard: Your Personal Phishing Radar Trainer

<div align="right">

<!-- CI/CD & Code Quality -->
<!-- Tech Stack -->
<!-- Deployment & Licensing -->
[![Build Status](https://img.shields.io/github/actions/workflow/status/SagarBiswas-MultiHAT/PhishGuard-AI/ci.yml?branch=main&label=CI%20Build&style=flat-square)](https://github.com/SagarBiswas-MultiHAT/PhishGuard-AI/actions)
&nbsp;
[![Python Version](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)](https://www.python.org/)
&nbsp;
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json&style=flat-square)](https://github.com/astral-sh/ruff)
&nbsp;
[![Powered by OpenRouter](https://img.shields.io/badge/AI-OpenRouter-white?style=flat-square&logo=openai&logoColor=black)](https://openrouter.ai)
&nbsp;
[![Powered by Groq](https://img.shields.io/badge/Verified_by-Groq-f55036?style=flat-square)](https://groq.com)
&nbsp;
[![Live Deployment](https://img.shields.io/website?url=https%3A%2F%2Fphishguard.multihat.dev&up_message=online&down_message=offline&style=flat-square&label=PhishGuard%20Live)](https://phishguard.multihat.dev)
&nbsp;
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](https://opensource.org/licenses/MIT)
&nbsp;

</div>

Welcome to **PhishGuard**! This is a fast-paced, interactive web game designed to help anyone train their instincts against email phishing attacks.

Instead of sitting through boring cybersecurity slideshows, PhishGuard throws you right into the deep end: you are shown realistic, AI-generated emails and you have **10 seconds** to decide if it's a safe message or a dangerous scam.

---

![](https://imgur.com/MttZMLQ.png)

---

## 🌟 What is it?

Phishing is a type of online scam where criminals send fake emails to trick you into clicking malicious links or giving away passwords. It is still the #1 way hackers break into systems today.

**PhishGuard** turns learning how to spot these scams into a quick, repeatable game. By practicing with our tool, you will build a stronger, natural instinct for what looks right and what looks suspicious in your inbox.

## ✨ Key Features

* **Real-time AI Generation:** Every email you see is uniquely generated on the spot by powerful AI. You'll never see the exact same scam twice!
* **High-Stakes Timer:** You only get 10 seconds to make a call. This trains you to spot red flags quickly. Need a break? Just hit the "Pause Timer" button.
* **Dual-AI Verification:** To make sure the game is always accurate, we use two separate AI models. One creates the email, and the second one independently verifies it. You'll see a "Dual-AI Verified" badge when they both agree!
* **Track Your Instincts:** Keep an eye on your live score and attempt tracker to see how your phishing radar improves over time.
* **Beautiful 2050 Cyberpunk Design:** A sleek, futuristic interface featuring dynamic particle networks, smooth animations, and automatic Light/Dark mode support.

## 🎮 How to Play

1. **Read the Message:** An email will appear on your screen.
2. **Beat the Clock:** You have 10 seconds to read it and look for clues (weird urgency, strange requests, or unusual formatting).
3. **Make Your Call:** Click **Phishing** if you think it's a scam, or **Legitimate** if you think it's safe.
4. **Get Instant Feedback:** The screen will glow green if you were right, and shake red if you were tricked!
5. **Keep Going:** A brand new, uniquely generated email will load automatically for the next round.

---

## ⚙️ How to Run PhishGuard on Your Computer

Getting PhishGuard running locally is simple. You need Python and a single, **completely free** API key from OpenRouter.

### 1. What You Need
* **Python 3.11+**: Download from [python.org](https://www.python.org/downloads/).
* **A Free OpenRouter Key**: Used to generate emails via a 120B parameter AI. Get yours at [openrouter.ai/keys](https://openrouter.ai/keys) — no credit card required.
* **A Free Groq Key**: Used to instantly verify emails. Get yours at [console.groq.com/keys](https://console.groq.com/keys) — no credit card required.

### 2. Simple Setup
Open PowerShell in the project folder and run:

```powershell
# 1. Create a virtual environment
python -m venv .venv

# 2. Activate it
& ".venv/Scripts/Activate.ps1"

# 3. Install dependencies
pip install -r requirements.txt
pip install -r requirements-ai.txt
```

### 3. Start the Game!

Create a `.env` file (or copy `.env.example`) in the root directory:

```env
OPENROUTER_API_KEY=sk-or-v1-your-key-here
GROQ_API_KEY=gsk_your-key-here
```

Then launch the server:

```powershell
.\start.ps1
```

*(Alternatively, you can set them inline in PowerShell without creating a `.env` file:)*

```powershell
$env:OPENROUTER_API_KEY = "sk-or-v1-your-key-here"
$env:GROQ_API_KEY = "gsk_your-key-here"
.\start.ps1
```

Then open your browser and go to: **http://127.0.0.1:5000**

---

## 🧠 Behind the Scenes: The Consensus Engine

For the curious minds, here is how PhishGuard ensures the emails are always high quality and correctly labeled:

Instead of relying on a single AI, PhishGuard uses a **hybrid Consensus Engine**:

1. **The Writer** — High-capacity free models (e.g. `nvidia/nemotron-3-super-120b`, `google/gemma-4-26b`) via OpenRouter are asked to write either a safe email or a phishing scam.
2. **The Reviewer** — `llama-3.3-70b-versatile` via Groq is then shown the same email — without knowing the intended label — and classifies it independently.
3. If both AI models agree on the label, the email is served to you with a **✅ Dual-AI Verified** badge.
4. If they disagree, the system silently discards it and generates a fresh one (up to 5 rounds).
5. If consensus still fails, a fast fallback model generates directly so the game is never interrupted.

The generator uses OpenRouter's massive free model library, while the verifier uses Groq's dedicated GPU hardware for instant, rate-limit-free classification.

---

### License
This project is open-source and available under the MIT License. Feel free to use it, learn from it, and modify it!