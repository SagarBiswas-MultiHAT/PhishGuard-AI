"""PhishGuard - AI-powered phishing awareness trainer.

This module implements the Flask application, consensus engine, and
background prefetch cache for the PhishGuard game.

NOTE (SCALE-01): This application uses in-process global state for the
prefetch cache and rate-limit dictionary.  It MUST run as a single worker
process.  Running multiple workers (e.g. ``gunicorn -w 4``) will create
independent caches and multiply API calls.  If horizontal scaling is
required, migrate state to Redis or a similar shared store.
"""

from __future__ import annotations

import html as html_module
import json
import os
import re
import secrets
import smtplib
import threading
import time
import uuid
from email.mime.text import MIMEText
from typing import Any
from urllib.parse import urlsplit

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix


def _load_dotenv() -> None:
    """Load environment variables from a local .env file if it exists."""
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.isfile(env_file):
        try:
            with open(env_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip('"').strip("'")
                        curr = os.environ.get(k, "")
                        if k and (not curr or "your_" in curr or curr.startswith("sk-or-v1-your")):
                            os.environ[k] = v
        except Exception:
            pass

_load_dotenv()

try:
    from openai import OpenAI as _OpenAI
except ImportError:  # REL-04: catch only ImportError, not all exceptions
    _OpenAI = None

try:
    from groq import Groq
except ImportError:  # REL-04
    Groq = None

# ─── Application Constants ──────────────────────────────────────────────────
# MQ-04: All magic numbers centralised here.

DEFAULT_MAX_FEEDBACK_LENGTH = 300   # MQ-05: aligned with frontend maxlength
DEFAULT_MAX_EMAIL_LENGTH = 800
DEFAULT_MIN_FEEDBACK_INTERVAL = 2.0
DEFAULT_GET_EMAIL_INTERVAL = 1.5    # SEC-06: rate-limit for /get-email
PREFETCH_WAIT_TIMEOUT = 15          # MQ-04: seconds to wait for busy prefetch
PREFETCH_RETRY_DELAY = 0.4          # MQ-04: seconds between sync retries
ANSWER_DELAY = 1800                 # MQ-04: ms before loading next email (frontend)
TIMER_SECONDS = 10                  # MQ-04: game timer length
USER_AGENT_MAX_LENGTH = 512         # SEC-10: truncation cap for stored UA
RATE_LIMIT_TTL = 120                # REL-02: seconds before stale rate-limit entries expire

# ─── Consensus Engine Constants ─────────────────────────────────────────────
# Maximum number of rounds the two models are allowed to disagree before we
# give up and fall back to the static dataset.  Each round = 1 OpenRouter call +
# 1 Groq/Llama call, so keep this reasonable to avoid runaway API spend.
MAX_CONSENSUS_ROUNDS = 5

# ─── OpenRouter Models ───────────────────────────────────────────────────────
# We use only free models to guarantee zero cost.
OR_GENERATOR_MODELS: list[str] = [
    "google/gemma-4-26b-a4b-it:free",          # Fast, accurate JSON formatting, 26B
    "nvidia/nemotron-3-super-120b-a12b:free",  # Massive 120B parameter model
    "google/gemma-4-31b-it:free",              # Capable 31B instruction-tuned model
    "nvidia/nemotron-3.5-lightning:free",      # Fast secondary generator
]


# Fast model for direct generation if consensus fails
OR_FALLBACK_MODEL = "google/gemma-4-26b-a4b-it:free"

# ─── Scenario Taxonomy ──────────────────────────────────────────────────────
# Curated, real-world-inspired scenario archetypes to drive creative generation.
# The engine picks one at random (excluding recent history) for each email.

PHISHING_SCENARIOS: list[str] = [
    # Social Engineering & Impersonation
    "CEO fraud - urgent wire transfer request from a spoofed executive",
    "IT helpdesk impersonation with a fake password reset portal",
    "HR benefits enrollment deadline with a credential-harvesting form",
    "Vendor invoice with subtly altered bank account details",
    "Board member requesting confidential financial documents",
    # Emerging / Novel Threats
    "AI-generated voice message transcript with a callback phishing number",
    "QR code in an email leading to a credential harvesting page",
    "Calendar invite with a malicious meeting link",
    "Fake shipping notification from a courier with a tracking portal",
    "Charity donation request exploiting a recent natural disaster",
    "Job offer from a recruiter at a real company with a fake onboarding portal",
    "Tax refund notification from a spoofed government agency",
    "Cloud storage sharing notification with a lookalike domain",
    "Multi-factor authentication verify-your-identity push prompt",
    "Fake security alert - new device logged into your account",
    # Platform-Specific
    "Microsoft Teams message notification with an external login link",
    "Slack workspace invitation from a spoofed colleague",
    "LinkedIn connection request leading to a phishing profile",
    "PayPal dispute resolution requiring immediate login",
    "GitHub repository access notification with a malicious OAuth app",
    # Emotional Manipulation
    "Prize notification - you have been selected lottery scam",
    "Threatening legal action email demanding immediate payment",
    "Fake customer complaint threatening a public review unless refunded",
    "Subscription cancellation confirmation you did not initiate",
    # Supply Chain / B2B
    "Compromised vendor email chain with an updated payment link",
    "DMARC/SPF failure notice from a spoofed email security vendor",
    "SaaS trial expiration with a malicious renewal link",
    "Fake NDA or contract from a new business partner",
    "Software license audit notification requiring credential verification",
    "Fake two-factor backup codes email from a spoofed cloud provider",
]

LEGITIMATE_SCENARIOS: list[str] = [
    "Internal team standup recap with action items",
    "Manager sharing quarterly OKR progress with the team",
    "IT announcing scheduled maintenance downtime this weekend",
    "HR sharing open enrollment dates with a link to the real benefits portal",
    "Finance sending a budget approval confirmation with no action required",
    "Colleague forwarding meeting notes from a client call",
    "Automated CI/CD pipeline success notification",
    "Customer success team sharing a positive client testimonial",
    "Facilities notifying about office temperature adjustments",
    "Security team sharing a monthly phishing awareness tip",
    "Project manager sharing sprint retrospective highlights",
    "CEO quarterly all-hands recap email with no links and no asks",
    "Travel booking confirmation from a known corporate travel portal",
    "Peer recognition email from the company kudos platform",
    "Automated calendar reminder for a recurring one-on-one meeting",
]

# ─── Scenario Rotation & Deduplication ───────────────────────────────────────
_SCENARIO_HISTORY_SIZE = 10          # Remember last N scenarios to prevent repeats
_RECENT_TEXT_BUFFER_SIZE = 10        # Remember last N email texts for similarity guard
_SIMILARITY_THRESHOLD = 0.55        # Keyword overlap ratio to reject as duplicate
_MIN_QUALITY_SCORE = 3              # Minimum verifier quality score to accept

# Protected by _prefetch_lock
_recent_scenarios: list[str] = []
_recent_texts: list[str] = []


def _pick_scenario(desired_label: str) -> str:
    """Pick a random scenario from the taxonomy, avoiding recent repeats."""
    import random
    pool = PHISHING_SCENARIOS if desired_label == "phishing" else LEGITIMATE_SCENARIOS
    with _prefetch_lock:
        available = [s for s in pool if s not in _recent_scenarios]
    if not available:
        # All scenarios used recently - reset and pick from full pool
        available = pool
    choice = random.choice(available)
    with _prefetch_lock:
        _recent_scenarios.append(choice)
        if len(_recent_scenarios) > _SCENARIO_HISTORY_SIZE:
            _recent_scenarios.pop(0)
    return choice


_STOP_WORDS = {
    "a", "about", "above", "after", "again", "all", "an", "and", "any", "are",
    "as", "at", "be", "because", "been", "before", "being", "below", "between",
    "both", "but", "by", "can", "could", "did", "do", "does", "doing", "down",
    "during", "each", "few", "for", "from", "further", "had", "has", "have",
    "having", "he", "her", "here", "hers", "herself", "him", "himself", "his",
    "how", "i", "if", "in", "into", "is", "it", "its", "itself", "just", "me",
    "more", "most", "my", "myself", "no", "nor", "not", "now", "of", "off",
    "on", "once", "only", "or", "other", "our", "ours", "ourselves", "out",
    "over", "own", "same", "she", "should", "so", "some", "such", "than",
    "that", "the", "their", "theirs", "them", "themselves", "then", "there",
    "these", "they", "this", "those", "through", "to", "too", "under", "until",
    "up", "very", "was", "we", "were", "what", "when", "where", "which", "while",
    "who", "whom", "why", "will", "with", "would", "you", "your", "yours",
    "yourself", "yourselves",
}


def _extract_keywords(text: str) -> set[str]:
    """Extract lowercase keywords of 3+ letters, excluding common stop words."""
    words = {w for w in re.findall(r"\b[a-z]{3,}\b", text.lower()) if w not in _STOP_WORDS}
    return words or set(text.lower().split())


def _is_too_similar(new_text: str, threshold: float = _SIMILARITY_THRESHOLD) -> bool:
    """Check if new_text shares too many keywords with any recently served text."""
    new_words = _extract_keywords(new_text)
    if not new_words:
        return False
    with _prefetch_lock:
        recent = list(_recent_texts)
    for prev in recent:
        prev_words = _extract_keywords(prev)
        if not prev_words:
            continue
        overlap = len(new_words & prev_words) / min(len(new_words), len(prev_words))
        if overlap > threshold:
            return True
    return False


def _record_served_text(text: str) -> None:
    """Add a served email text to the recent buffer for deduplication."""
    with _prefetch_lock:
        _recent_texts.append(text)
        if len(_recent_texts) > _RECENT_TEXT_BUFFER_SIZE:
            _recent_texts.pop(0)

# ─── Prefetch Cache ──────────────────────────────────────────────────────────
# One email is pre-generated in the background while the user is reading the
# current question.  When the next /get-email request arrives the cached email
# is returned instantly, then a new background generation begins immediately.
_prefetch_lock  = threading.Lock()
_prefetch_cache: dict[str, Any] | None = None   # pre-generated email dict, or None
_prefetch_busy: bool = False                    # True while a background thread is active


def _run_prefetch(max_length: int) -> None:
    """Background worker: silently generate the next email and fill the cache."""
    global _prefetch_cache, _prefetch_busy
    import random

    try:
        label = random.choice(["phishing", "legitimate"])
        print(f"[Prefetch] Background generation started (label={label!r})...")
        email, _ = generate_ai_email(max_length, label)
        with _prefetch_lock:
            _prefetch_cache = email
        if email:
            print(f"[Prefetch] Cache ready (label={email.get('label')!r}).")
        else:
            print("[Prefetch] Background generation failed - cache remains empty.")
    except Exception as exc:
        print(f"[Prefetch] Background error: {_sanitize_log(exc)}")
    finally:
        with _prefetch_lock:
            _prefetch_busy = False


def _trigger_prefetch(max_length: int) -> None:
    """Spawn a background prefetch thread if one is not already running."""
    global _prefetch_busy
    with _prefetch_lock:
        if _prefetch_busy:
            return  # already warming - don't double-fetch
        _prefetch_busy = True
    threading.Thread(
        target=_run_prefetch,
        args=(max_length,),
        daemon=True,
        name="phishguard-prefetch",
    ).start()


def _pop_prefetch_cache() -> dict[str, Any] | None:
    """Thread-safely consume and return the cached email (or None if empty)."""
    global _prefetch_cache
    with _prefetch_lock:
        email = _prefetch_cache
        _prefetch_cache = None
    return email


# ─── Logging Helpers ─────────────────────────────────────────────────────────

def _sanitize_log(exc: BaseException) -> str:
    """Return a sanitised string representation of an exception.

    SEC-05: Redact anything that looks like an API key to prevent leaking
    secrets through log aggregators.
    """
    msg = str(exc)
    # Redact common API key patterns
    msg = re.sub(r"sk-or-v1-[A-Za-z0-9\-]+", "sk-or-v1-[REDACTED]", msg)
    msg = re.sub(r"gsk_[A-Za-z0-9]+", "gsk_[REDACTED]", msg)
    msg = re.sub(r"sk-[A-Za-z0-9]{20,}", "sk-[REDACTED]", msg)
    smtp_pass = os.getenv("SMTP_PASS", "").strip()
    if smtp_pass and len(smtp_pass) >= 6:
        msg = msg.replace(smtp_pass, "[REDACTED]")
    return msg


def _strip_html(text: str) -> str:
    """Remove HTML tags from AI-generated text (SEC-08: defence-in-depth)."""
    clean = re.sub(r"<[^>]+>", "", text)
    return html_module.unescape(clean)


# ─── Prompt ──────────────────────────────────────────────────────────────────


def _build_generation_prompt(desired_label: str, scenario_hint: str) -> str:
    """Build a dynamic, creativity-driven prompt for email generation."""
    parts: list[str] = [
        "You are generating training data for a phishing awareness quiz.",
        "Generate one realistic email or message that a real person would receive",
        "in a workplace or personal inbox.",
        "",
        "CREATIVITY RULES (CRITICAL):",
        "- Generate a NOVEL, CREATIVE scenario that feels like it emerged from a real inbox today.",
        "- Use specific, believable details: real-sounding but fake names, plausible dates,",
        "  department names, realistic ticket or reference numbers, and internal system names.",
        "- DO NOT use generic phishing cliches like 'Dear User' or 'click here immediately'.",
        "- DO NOT use 'example.com'. Invent realistic-looking but clearly fictional domains.",
        "- Write as if you are a real person - include natural language quirks, partial sentences,",
        "  or casual tone variations that make the email feel human-authored.",
        "- Vary the emotional register: some emails should be casual, some formal,",
        "  some urgent but not panicked.",
        "",
        f"SCENARIO DIRECTIVE: {scenario_hint}",
        "",
        "FORMAT RULES:",
    ]

    if desired_label == "phishing":
        parts.extend([
            "- Include at least one subtle red flag (urgency, spoofed domain,",
            "  credential request, authority impersonation, emotional manipulation,",
            "  or too-good-to-be-true offer).",
        ])
    else:
        parts.extend([
            "- Write a genuinely safe internal or business email with no suspicious elements.",
            "  Reference plausible internal systems, named colleagues, or specific dates.",
            "  Do NOT ask for credentials or passwords.",
        ])

    parts.extend([
        "- Format: 3-6 sentences. Include a subject line for roughly half of messages.",
        "  If you include a subject line, separate it from the body with a double newline.",
        f"- The label must be exactly '{desired_label}'.",
        "- Return ONLY a JSON object with keys 'text' and 'label'.",
        "  No markdown, no extra keys, no explanation.",
    ])

    return "\n".join(parts)


# Kept for the fallback path which does not use scenario hints
_FALLBACK_PROMPT_PARTS: list[str] = [
    "You are generating training data for a phishing awareness quiz.",
    "Generate one realistic, creative, and novel email or message.",
    "Rules:",
    "- If label is 'phishing': Include at least one subtle red flag.",
    "Use realistic-looking but clearly fake domains. Do NOT use 'example.com'.",
    "- If label is 'legitimate': Write a genuinely safe email with no suspicious elements.",
    "- Format: 3-6 sentences. Vary tone, persona, and scenario.",
    "- Return ONLY a JSON object with keys 'text' and 'label'.",
    "No markdown, no extra keys, no explanation.",
]


def json_error(message: str, status: int = 400) -> tuple[Response, int]:
    """Return a consistent JSON error response."""
    return jsonify({"error": message}), status


# ─── OpenRouter Unified Engine ─────────────────────────────────────────────

class _OpenRouterAuthFailed(Exception):
    """Raised to immediately abort if the API key is invalid."""


def _make_or_client() -> Any | None:
    """Return an OpenAI-compatible client pointed at OpenRouter."""
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key or _OpenAI is None:
        return None
    return _OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        # Fail instantly on rate limits instead of exponential backoff
        max_retries=0,
    )


def _is_rate_limit(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return "429" in msg or "rate limit" in msg or "quota" in msg


def _is_auth_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return "401" in msg or "unauthorized" in msg


_openrouter_rate_limit_until: float = 0.0


def _mark_openrouter_rate_limited(cooldown_seconds: float = 60.0) -> None:
    global _openrouter_rate_limit_until
    _openrouter_rate_limit_until = time.time() + cooldown_seconds


def _is_openrouter_cooling_down() -> bool:
    return time.time() < _openrouter_rate_limit_until


def _openrouter_generate(
    client: Any, desired_label: str, max_length: int,
    scenario_hint: str = "",
) -> tuple[dict[str, Any] | None, str | None]:
    """Ask OpenRouter to generate an email using the waterfall of generator models.

    Returns (email_dict, None) on success, or (None, error_str).
    """
    if _is_openrouter_cooling_down():
        remaining = max(1, int(_openrouter_rate_limit_until - time.time()))
        return None, f"OpenRouter cooling down after rate limit ({remaining}s remaining)."

    if scenario_hint:
        prompt = _build_generation_prompt(desired_label, scenario_hint)
    else:
        prompt = " ".join(_FALLBACK_PROMPT_PARTS + [
            f"- The label must be exactly '{desired_label}'.",
        ])

    last_error = "No models available."

    for model_name in OR_GENERATOR_MODELS:
        print(f"[Generator] Trying model: {model_name}")
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.85,
                max_tokens=400,
            )
            raw_text = (response.choices[0].message.content or "") if response.choices else ""
            match = re.search(r"\{.*\}", raw_text, re.DOTALL)
            if not match:
                last_error = f"{model_name}: returned no JSON object."
                continue

            email = json.loads(match.group(0))
            text = _strip_html(email.get("text", "").strip())  # SEC-08
            label = email.get("label", "").strip().lower()

            if text and label == desired_label and len(text) <= max_length:
                print(f"[Generator] Success with {model_name}")
                return {"text": text, "label": label, "_model": model_name}, None

            last_error = f"{model_name}: output failed validation."
            continue

        except Exception as exc:
            if _is_auth_error(exc):
                print("[Generator] FATAL: Auth failed. Check OPENROUTER_API_KEY.")
                raise _OpenRouterAuthFailed(str(exc)) from exc
            if _is_rate_limit(exc):
                err_text = str(exc).lower()
                if "free-models-per-min" in err_text or "per-minute" in err_text:
                    print(
                        "[Generator] OpenRouter free-tier per-minute limit reached - cooling down."
                    )
                    _mark_openrouter_rate_limited(60.0)
                    return None, "OpenRouter per-minute rate limit reached."
                print(f"[Generator] {model_name} rate limited - trying next model.")
                last_error = f"{model_name} rate limited."
                continue

            print(f"[Generator] {model_name} error: {_sanitize_log(exc)}")  # SEC-05
            last_error = f"{model_name}: {_sanitize_log(exc)}"
            continue

    if "rate limited" in str(last_error).lower():
        _mark_openrouter_rate_limited(30.0)

    return None, last_error


GROQ_VERIFIER_MODELS = [
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "qwen/qwen3.8-27b",
]


def _groq_classify(
    client: Any, email_text: str, exclude_model: str = ""
) -> tuple[str | None, int]:
    """Ask Groq to classify and score an email using available models.

    Returns (label, quality_score) where label is 'phishing' | 'legitimate' | None
    and quality_score is 1-5 (0 if parsing fails).
    """
    if not client:
        return None, 0

    classify_prompt = (
        "You are a cybersecurity expert evaluating an email for a phishing awareness quiz.\n"
        "Evaluate the following email on TWO dimensions:\n"
        "1. CLASSIFICATION: Is this email 'phishing' or 'legitimate'?\n"
        "2. QUALITY SCORE (1-5): How creative, realistic, and unique is this email?\n"
        "   5 = Extremely realistic, novel scenario, would fool experts\n"
        "   4 = Very convincing, creative approach\n"
        "   3 = Decent but uses common patterns\n"
        "   2 = Generic and formulaic\n"
        "   1 = Obviously fake, unrealistic\n\n"
        "Reply with EXACTLY this format on a single line: <label> <score>\n"
        "Example: phishing 4\n"
        "Example: legitimate 5\n\n"
        f"Email:\n{email_text}"
    )

    models_to_try = [m for m in GROQ_VERIFIER_MODELS if m != exclude_model]
    if exclude_model and exclude_model in GROQ_VERIFIER_MODELS:
        models_to_try.append(exclude_model)

    for model_name in models_to_try:
        try:
            completion = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": classify_prompt}],
                temperature=0.1,
                max_tokens=600,
            )
            raw = (
                (completion.choices[0].message.content or "").strip().lower()
                if completion.choices
                else ""
            )
            # If content is empty because reasoning consumed tokens, inspect reasoning trace
            if not raw and completion.choices:
                reasoning = getattr(completion.choices[0].message, "reasoning", "") or ""
                raw = reasoning.strip().lower()

            # Parse quality score from response like "phishing 4" or "legitimate 5"
            score = 0
            score_match = re.search(r'(\d)', raw)
            if score_match:
                parsed = int(score_match.group(1))
                if 1 <= parsed <= 5:
                    score = parsed

            match = re.search(r"\b(phishing|legitimate)\b", raw)
            if match:
                label = match.group(1)
                print(f"[Verifier] Groq ({model_name}) classified as {label} (quality={score}).")
                return label, score

            print(f"[Verifier] Groq ({model_name}) returned ambiguous response: {raw!r}")
        except Exception as exc:
            err_msg = _sanitize_log(exc)
            print(f"[Verifier] Groq ({model_name}) error: {err_msg}")  # SEC-05

    return None, 0


def _groq_generate(
    client: Any, desired_label: str, max_length: int, scenario_hint: str = ""
) -> tuple[dict[str, Any] | None, str | None]:
    """Generate an email using Groq when OpenRouter models are busy or rate-limited."""
    if not client:
        return None, "Groq client not available."
    if scenario_hint:
        prompt = _build_generation_prompt(desired_label, scenario_hint)
    else:
        prompt = " ".join(
            _FALLBACK_PROMPT_PARTS + [f"- The label must be exactly '{desired_label}'."]
        )

    for model_name in GROQ_VERIFIER_MODELS:
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.8,
                max_tokens=800,
            )
            raw_text = response.choices[0].message.content if response.choices else ""
            match = re.search(r"\{.*\}", raw_text, re.DOTALL)
            if not match:
                continue
            email = json.loads(match.group(0))
            text = _strip_html(email.get("text", "").strip())
            label = email.get("label", "").strip().lower()
            if text and label == desired_label and len(text) <= max_length:
                print(f"[Generator] Success with Groq ({model_name})")
                return {"text": text, "label": label, "_model": f"groq:{model_name}"}, None
        except Exception as exc:
            err_msg = _sanitize_log(exc)
            print(f"[Generator] Groq ({model_name}) error: {err_msg}")
            continue

    return None, "All Groq generation attempts failed."


# ─── Consensus Engine ────────────────────────────────────────────────────────
def generate_ai_email(
    max_length: int, desired_label: str, max_attempts: int = 3
) -> tuple[dict[str, Any] | None, str | None]:
    """Dual-model consensus loop with creativity scoring and deduplication.

    Algorithm
    ---------
    Step 0 - Pick a creative scenario from the taxonomy (with rotation).
    Step 1 - Generator chain attempts to write an email using the scenario hint.
    Step 1b- Reject if too similar to recently served content.
    Step 2 - Verifier chain independently classifies AND scores the email.
    Step 3 - If labels match AND quality >= threshold -> return (consensus locked).
             If quality too low or labels disagree -> repeat from Step 1.
    After MAX_CONSENSUS_ROUNDS rounds without consensus ->
        fall back to a fast direct generation.
    """
    client = _make_or_client()
    groq_api_key = os.getenv("GROQ_API_KEY")

    if not client or not groq_api_key:
        return None, "Missing OPENROUTER_API_KEY or GROQ_API_KEY environment variables."

    groq_client = Groq(api_key=groq_api_key) if Groq else None
    if not groq_client:
        return None, "Groq package not installed."

    last_error = "No consensus reached after all rounds."

    for round_num in range(1, MAX_CONSENSUS_ROUNDS + 1):
        # ── Step 0: Pick a creative scenario ─────────────────────────────────
        scenario_hint = _pick_scenario(desired_label)
        print(
            f"\n[Consensus] Round {round_num}/{MAX_CONSENSUS_ROUNDS}"
            f" - desired label: {desired_label!r}"
            f" - scenario: {scenario_hint!r}"
        )

        # ── Step 1: Generator chain ──────────────────────────────────────────
        try:
            email, gen_error = _openrouter_generate(
                client, desired_label, max_length, scenario_hint=scenario_hint,
            )
        except _OpenRouterAuthFailed:
            return None, "OpenRouter API key is invalid (401). Please check OPENROUTER_API_KEY."

        if email is None:
            # Fall back to Groq if OpenRouter models are rate-limited or congested
            print(
                f"[Consensus] Round {round_num}: OpenRouter busy - trying Groq ({gen_error})."
            )
            email, _ = _groq_generate(
                groq_client, desired_label, max_length, scenario_hint=scenario_hint
            )

        if email is None:
            print(f"[Consensus] Round {round_num}: All generators failed - {gen_error}")
            last_error = gen_error
            if "rate limited" in str(gen_error).lower() or "quota" in str(gen_error).lower():
                break
            continue

        email_text = email["text"]
        gen_label  = email["label"]
        gen_model  = email["_model"]
        print(f"[Consensus] Round {round_num}: {gen_model} generated label={gen_label!r}")

        # ── Step 1b: Similarity deduplication ────────────────────────────────
        if _is_too_similar(email_text):
            print(f"[Consensus] Round {round_num}: Content too similar to recent - regenerating.")
            last_error = f"Round {round_num}: Duplicate content rejected."
            continue

        # ── Step 2: Verifier chain (classify + quality score) ────────────────
        time.sleep(0.3)
        gen_groq_model = gen_model.split("groq:", 1)[1] if gen_model.startswith("groq:") else ""
        verifier_label, quality_score = _groq_classify(
            groq_client, email_text, exclude_model=gen_groq_model
        )

        if verifier_label is None:
            print(f"[Consensus] Round {round_num}: All verifiers failed - serving unverified.")
            email["_validated"]       = False
            email["_consensus_round"] = 0
            email["_quality_score"]   = 0
            email["_scenario_type"]   = scenario_hint
            _record_served_text(email_text)
            return email, None

        # ── Step 3: Check consensus + quality ────────────────────────────────
        if verifier_label == gen_label:
            if quality_score < _MIN_QUALITY_SCORE:
                print(
                    f"[Consensus] Round {round_num}: Consensus on label but quality"
                    f" too low ({quality_score}<{_MIN_QUALITY_SCORE}) - regenerating."
                )
                last_error = f"Round {round_num}: Quality score {quality_score} below threshold."
                continue

            print(
                f"[Consensus] Consensus reached on round {round_num}"
                f" - label={gen_label!r}, quality={quality_score}"
            )
            email["_validated"]       = True
            email["_consensus_round"] = round_num
            email["_quality_score"]   = quality_score
            email["_scenario_type"]   = scenario_hint
            _record_served_text(email_text)
            return email, None
        else:
            print(
                f"[Consensus] Disagreement: Gen={gen_label!r}"
                f" vs Verifier={verifier_label!r}. Re-running."
            )
            last_error = (
                f"Round {round_num}: Disagreement"
                f" ({gen_label!r} vs {verifier_label!r})."
            )

    # ── All rounds done: Direct Fallback ─────────────────────────────────────
    print(
        f"[Consensus] No consensus after {MAX_CONSENSUS_ROUNDS}"
        " rounds. Using fallback model directly."
    )
    # Attempt Groq direct generation first to bypass OpenRouter free-tier congestion
    if groq_client:
        fb_email, _ = _groq_generate(groq_client, desired_label, max_length)
        if fb_email:
            print("[Fallback] Success with Groq fallback generator.")
            _record_served_text(fb_email["text"])
            return {
                "text": fb_email["text"],
                "label": fb_email["label"],
                "_validated": False,
                "_consensus_round": 0,
                "_quality_score": 0,
                "_scenario_type": "",
                "_model": fb_email.get("_model", "groq-fallback"),
            }, None

    prompt_parts = _FALLBACK_PROMPT_PARTS + [f"- The label must be exactly '{desired_label}'."]
    prompt = " ".join(prompt_parts)

    for _ in range(max_attempts):
        try:
            response = client.chat.completions.create(
                model=OR_FALLBACK_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.85,
                max_tokens=400,
            )
            raw_text = response.choices[0].message.content if response.choices else ""
            match = re.search(r"\{.*\}", raw_text, re.DOTALL)
            if match:
                fb_email = json.loads(match.group(0))
                text = _strip_html(fb_email.get("text", "").strip())  # SEC-08
                label = fb_email.get("label", "").strip().lower()
                if text and label == desired_label and len(text) <= max_length:
                    print(f"[Fallback] Success with {OR_FALLBACK_MODEL}")
                    _record_served_text(text)
                    return {
                        "text": text,
                        "label": label,
                        "_validated": False,
                        "_consensus_round": 0,
                        "_quality_score": 0,
                        "_scenario_type": "",
                        "_model": OR_FALLBACK_MODEL,
                    }, None
        except Exception as exc:
            print(f"[Fallback] Error: {_sanitize_log(exc)}")  # SEC-05

    return None, last_error


# ─── Rate Limiter with TTL Eviction ──────────────────────────────────────────

class _RateLimiter:
    """Thread-safe rate limiter with automatic TTL eviction (REL-02)."""

    def __init__(self) -> None:
        self._store: dict[str, float] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def is_limited(self, key: str, interval_seconds: float) -> bool:
        """Return True if the key has been seen within the last `interval_seconds`."""
        now = time.time()
        with self._lock:
            # Periodic cleanup of stale entries
            if now - self._last_cleanup > RATE_LIMIT_TTL:
                cutoff = now - RATE_LIMIT_TTL
                self._store = {k: v for k, v in self._store.items() if v > cutoff}
                self._last_cleanup = now

            last = self._store.get(key, 0)
            if now - last < interval_seconds:
                return True
            self._store[key] = now
            return False


# ─── CSRF Validation ─────────────────────────────────────────────────────────

def _check_csrf(req: Any) -> str | None:
    """Validate request origin for CSRF protection (SEC-01).

    Returns an error message if the request fails validation, or None if OK.
    Uses a combination of Origin/Referer checking and custom header requirement.
    """
    # Require custom header (cannot be set by cross-origin form submissions)
    if not req.headers.get("X-Requested-With"):
        return "Missing required X-Requested-With header."

    origin = req.headers.get("Origin") or ""
    referer = req.headers.get("Referer") or ""
    host_parts = urlsplit(req.host_url)

    target_url = origin or referer
    if target_url:
        target_parts = urlsplit(target_url)
        # Verify exact host:port match
        if target_parts.netloc.lower() != host_parts.netloc.lower():
            return "Origin mismatch." if origin else "Referer mismatch."

        # Verify scheme matches (allowing https when terminated by reverse proxy)
        fwd_proto = req.headers.get("X-Forwarded-Proto", "").lower()
        allowed_schemes = {host_parts.scheme.lower()}
        if fwd_proto:
            allowed_schemes.add(fwd_proto)
        if target_parts.scheme and target_parts.scheme.lower() not in allowed_schemes:
            return "Origin mismatch." if origin else "Referer mismatch."

    return None


# ─── Feedback Email Notification ─────────────────────────────────────────────

def _send_feedback_email(
    feedback_text: str, client_ip: str, user_agent: str, created_at: int
) -> bool:
    """Send an email notification with submitted feedback via SMTP.

    Returns True if sent, False if skipped or failed.
    """
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_pass = os.getenv("SMTP_PASS", "").strip()
    recipient = os.getenv("FEEDBACK_RECIPIENT_EMAIL", "").strip() or smtp_user

    # If SMTP is not configured, silently skip email delivery
    if not smtp_host or not smtp_user or not smtp_pass or not recipient:
        return False

    try:
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError:
        smtp_port = 587

    time_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(created_at))
    body = (
        "You received new user feedback on PhishGuard!\n\n"
        f"Date & Time: {time_str}\n"
        f"Client IP:   {client_ip}\n"
        f"User-Agent:  {user_agent}\n\n"
        "--------------------------------------------------\n"
        "Feedback Content:\n"
        f"{feedback_text}\n"
        "--------------------------------------------------\n"
    )

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "[PhishGuard] New User Feedback Received"
    msg["From"] = smtp_user
    msg["To"] = recipient

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        print(f"[Feedback] Email notification sent to {recipient}")
        return True
    except Exception as exc:
        print(f"[Feedback] Failed to send email notification: {_sanitize_log(exc)}")
        return False


def _dispatch_feedback_email(
    feedback_text: str, client_ip: str, user_agent: str, created_at: int
) -> None:
    """Dispatch email notification asynchronously in a background worker thread."""
    threading.Thread(
        target=_send_feedback_email,
        args=(feedback_text, client_ip, user_agent, created_at),
        daemon=True,
        name="phishguard-feedback-email",
    ).start()


# ─── Flask Application Factory ──────────────────────────────────────────────

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # SEC-11: Trust reverse-proxy headers for accurate client IP and HTTPS detection
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # SEC-02: Set a proper secret key for session security
    app.secret_key = os.getenv(
        "FLASK_SECRET_KEY",
        secrets.token_hex(32),  # Generate a random key if not configured
    )

    # PERF-03: Cache static assets for 1 year (use cache-busting via query params)
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 31536000

    feedback_dir: str = os.getenv(
        "PHISHGUARD_FEEDBACK_DIR",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "FeedBack"),
    )
    max_feedback_length: int = int(
        os.getenv("PHISHGUARD_MAX_FEEDBACK", str(DEFAULT_MAX_FEEDBACK_LENGTH))
    )
    max_email_length: int = int(
        os.getenv("PHISHGUARD_MAX_EMAIL", str(DEFAULT_MAX_EMAIL_LENGTH))
    )
    min_feedback_interval: float = float(
        os.getenv("PHISHGUARD_MIN_FEEDBACK_INTERVAL", str(DEFAULT_MIN_FEEDBACK_INTERVAL))
    )
    get_email_interval: float = float(
        os.getenv("PHISHGUARD_GET_EMAIL_INTERVAL", str(DEFAULT_GET_EMAIL_INTERVAL))
    )

    rate_limiter = _RateLimiter()

    @app.after_request
    def set_security_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # SEC-04: Content Security Policy
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'",
        )
        return response

    # MQ-03: Global error handler - never leak tracebacks to the client
    @app.errorhandler(500)
    def internal_error(e: Exception) -> tuple[Response, int]:
        import traceback
        traceback.print_exc()
        return jsonify({"error": "An internal error occurred."}), 500

    @app.get("/")
    def index() -> str:
        return render_template("index.html")

    @app.get("/health")
    def health_check() -> tuple[Response, int]:
        return jsonify({"status": "ok"}), 200

    @app.get("/get-email")
    def get_email() -> tuple[Response, int]:
        import random

        # SEC-06: Rate-limit email generation requests
        requester = request.remote_addr or "unknown"
        if rate_limiter.is_limited(f"email:{requester}", get_email_interval):
            return json_error("Too many requests. Please wait a moment.", 429)

        try:
            # ── Step 1: Try to serve from the prefetch cache (instant) ────────
            email = _pop_prefetch_cache()

            if email:
                print("[Prefetch] Served from cache (instant response).")
            else:
                # ── Step 2: Cache miss - generate synchronously ───────────────
                print("[Prefetch] Cache miss - waiting for prefetch or generating synchronously.")

                # If a background prefetch is already running, wait for it instead of
                # launching a concurrent request (which instantly triggers free-tier rate limits)
                wait_time = 0
                while _prefetch_busy and wait_time < PREFETCH_WAIT_TIMEOUT:
                    time.sleep(0.5)
                    wait_time += 0.5

                # Try popping the cache again just in case the background thread finished
                email = _pop_prefetch_cache()

                if not email:
                    desired_label = random.choice(["phishing", "legitimate"])
                    email = None
                    last_error = None
                    for _attempt in range(2):
                        email, last_error = generate_ai_email(max_email_length, desired_label)
                        if email:
                            break
                        time.sleep(PREFETCH_RETRY_DELAY)

                if not email:
                    _trigger_prefetch(max_email_length)  # still warm cache for next time
                    # REL-03: fixed stale GEMINI reference
                    fallback_msg = (
                        "AI service unavailable."
                        " Please set OPENROUTER_API_KEY and GROQ_API_KEY."
                    )
                    return json_error(
                        last_error or fallback_msg,
                        503,
                    )

            # ── Step 3: Immediately kick off the NEXT generation in background ─
            _trigger_prefetch(max_email_length)

            # SEC-07: Strip internal metadata before sending to client
            email.pop("_model", None)
            email.pop("_scenario_type", None)  # Would reveal the answer

            return jsonify(email), 200
        except Exception:
            import traceback
            traceback.print_exc()
            # MQ-03: don't leak exception text
            return json_error("An internal error occurred.", 500)

    @app.post("/submit-feedback")
    def submit_feedback() -> tuple[Response, int]:
        # SEC-01: CSRF validation
        csrf_error = _check_csrf(request)
        if csrf_error:
            return json_error(f"Request blocked: {csrf_error}", 403)

        requester = request.remote_addr or "unknown"
        if rate_limiter.is_limited(f"feedback:{requester}", min_feedback_interval):
            return json_error("Please wait before submitting more feedback.", 429)
        payload = request.get_json(silent=True) or {}
        feedback_text = str(payload.get("feedback", "")).strip()
        if not feedback_text:
            return json_error("Feedback text is required.", 400)
        if len(feedback_text) > max_feedback_length:
            return json_error("Feedback is too long.", 400)

        os.makedirs(feedback_dir, exist_ok=True)
        created_at = int(time.time())
        user_agent = request.headers.get("User-Agent", "")[:USER_AGENT_MAX_LENGTH]

        # SEC-03: Use UUID to prevent filename collisions and predictability
        feedback_file_path = os.path.join(feedback_dir, f"feedback_{uuid.uuid4().hex}.json")
        with open(feedback_file_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "feedback": feedback_text,
                    "created_at": created_at,
                    # SEC-10: Truncate User-Agent to prevent disk-fill attacks
                    "user_agent": user_agent,
                },
                handle,
                indent=2,
                ensure_ascii=False,
            )

        # Dispatch email notification in background if SMTP is configured
        _dispatch_feedback_email(feedback_text, requester, user_agent, created_at)

        return jsonify({"message": "Feedback submitted successfully!"}), 200

    return app


app = create_app()

# REL-01: Only warm the prefetch cache if API keys are actually configured
if os.getenv("OPENROUTER_API_KEY") and os.getenv("GROQ_API_KEY"):
    _trigger_prefetch(DEFAULT_MAX_EMAIL_LENGTH)
else:
    print("[Startup] Skipping prefetch - API keys not set.")


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    port = int(os.getenv("PORT", os.getenv("PHISHGUARD_PORT", "5000")))
    default_host = "0.0.0.0" if os.getenv("PORT") else "127.0.0.1"
    host = os.getenv("PHISHGUARD_HOST", default_host)

    # SEC-09 / PERF-01: Use waitress production server when available
    if not debug:
        try:
            from waitress import serve

            print(f"[Server] Starting Waitress on {host}:{port}")
            serve(app, host=host, port=port)
        except ImportError:
            print("[Server] Waitress not installed - falling back to Flask dev server.")
            print("[Server] WARNING: The Flask dev server is NOT suitable for production.")
            app.run(host=host, port=port, debug=debug, threaded=True)
    else:
        print("[Server] Starting Flask dev server (debug mode).")
        try:
            app.run(host=host, port=port, debug=debug, threaded=True)
        except Exception as exc:
            print(f"Failed to start the server: {exc}")
