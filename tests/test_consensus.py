"""Unit tests for the consensus engine and supporting functions.

TEST-02: Covers the generator waterfall, verifier classification,
consensus loop, fallback path, and edge cases - all with mocked API
responses so no live keys are needed.
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _reload_app(monkeypatch):
    """Force-reimport app module with API keys stubbed out."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-test-key")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test_key")
    if "app" in sys.modules:
        del sys.modules["app"]

    # Patch threading.Thread so the module-level startup prefetch (app.py line 644)
    # never actually spawns.  This prevents the background thread from consuming
    # mock side_effects before the test's own `with patch.object(...)` block runs.
    with patch("threading.Thread"):
        import app as app_module

    # Reset global prefetch and cooldown state for a clean slate.
    app_module._openrouter_rate_limit_until = 0.0
    with app_module._prefetch_lock:
        app_module._prefetch_cache = None
        app_module._prefetch_busy = False

    return app_module


def _fake_choice(content):
    """Return a minimal OpenAI-style response with a single choice."""
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
    )


def _fake_email_json(text="Test email body", label="phishing"):
    return json.dumps({"text": text, "label": label})


# ─── _strip_html ──────────────────────────────────────────────────────────────


def test_strip_html_removes_tags(monkeypatch):
    app_mod = _reload_app(monkeypatch)
    assert app_mod._strip_html("<b>Bold</b> text") == "Bold text"
    assert app_mod._strip_html("<script>alert('x')</script>OK") == "alert('x')OK"
    assert app_mod._strip_html("No tags here") == "No tags here"


def test_strip_html_unescapes_entities(monkeypatch):
    app_mod = _reload_app(monkeypatch)
    assert app_mod._strip_html("&amp; &lt;div&gt;") == "& <div>"


# ─── _sanitize_log ───────────────────────────────────────────────────────────


def test_sanitize_log_redacts_api_keys(monkeypatch):
    app_mod = _reload_app(monkeypatch)
    msg = app_mod._sanitize_log(Exception("Error with sk-or-v1-abc123 key"))
    assert "abc123" not in msg
    assert "[REDACTED]" in msg


def test_sanitize_log_redacts_groq_keys(monkeypatch):
    app_mod = _reload_app(monkeypatch)
    msg = app_mod._sanitize_log(Exception("Auth failed: gsk_abc123456789"))
    assert "abc123456789" not in msg
    assert "[REDACTED]" in msg


# ─── _openrouter_generate ────────────────────────────────────────────────────


def test_openrouter_generate_success(monkeypatch):
    """A well-formed JSON response from the first model should succeed."""
    app_mod = _reload_app(monkeypatch)

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = _fake_choice(
        _fake_email_json("Suspicious email", "phishing")
    )

    email, error = app_mod._openrouter_generate(mock_client, "phishing", 800)

    assert email is not None
    assert error is None
    assert email["text"] == "Suspicious email"
    assert email["label"] == "phishing"
    assert "_model" in email


def test_openrouter_generate_waterfall_on_invalid_json(monkeypatch):
    """If the first model returns garbage, the second should be tried."""
    app_mod = _reload_app(monkeypatch)

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = [
        _fake_choice("Not valid JSON at all"),         # Model 1 fails
        _fake_choice(_fake_email_json("OK email", "phishing")),  # Model 2 succeeds
    ]

    email, error = app_mod._openrouter_generate(mock_client, "phishing", 800)

    assert email is not None
    assert email["text"] == "OK email"
    assert mock_client.chat.completions.create.call_count == 2


def test_openrouter_generate_wrong_label_skips(monkeypatch):
    """If the model returns the wrong label, it should try the next model."""
    app_mod = _reload_app(monkeypatch)

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = [
        _fake_choice(_fake_email_json("Email", "legitimate")),  # Wrong label
        _fake_choice(_fake_email_json("Email", "phishing")),     # Correct
    ]

    email, error = app_mod._openrouter_generate(mock_client, "phishing", 800)
    assert email is not None
    assert email["label"] == "phishing"


def test_openrouter_generate_all_fail(monkeypatch):
    """If all models fail, should return (None, error_string)."""
    app_mod = _reload_app(monkeypatch)

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = _fake_choice("no json here")

    email, error = app_mod._openrouter_generate(mock_client, "phishing", 800)

    assert email is None
    assert error is not None
    assert mock_client.chat.completions.create.call_count == len(app_mod.OR_GENERATOR_MODELS)


def test_openrouter_generate_rate_limit_continues(monkeypatch):
    """Rate-limited models should be skipped, next model tried."""
    app_mod = _reload_app(monkeypatch)

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = [
        Exception("429 rate limit exceeded"),
        _fake_choice(_fake_email_json("Email", "phishing")),
    ]

    email, error = app_mod._openrouter_generate(mock_client, "phishing", 800)
    assert email is not None


def test_openrouter_generate_auth_failure_raises(monkeypatch):
    """Auth errors should raise _OpenRouterAuthFailed immediately."""
    app_mod = _reload_app(monkeypatch)
    import pytest

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception("401 Unauthorized")

    with pytest.raises(app_mod._OpenRouterAuthFailed):
        app_mod._openrouter_generate(mock_client, "phishing", 800)


# ─── _groq_classify ──────────────────────────────────────────────────────────


def test_groq_classify_phishing(monkeypatch):
    app_mod = _reload_app(monkeypatch)

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = _fake_choice("phishing 4")

    label, score = app_mod._groq_classify(mock_client, "Some email text")
    assert label == "phishing"
    assert score == 4


def test_groq_classify_legitimate(monkeypatch):
    app_mod = _reload_app(monkeypatch)

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = _fake_choice("legitimate 5")

    label, score = app_mod._groq_classify(mock_client, "Some email text")
    assert label == "legitimate"
    assert score == 5


def test_groq_classify_ambiguous_returns_none(monkeypatch):
    app_mod = _reload_app(monkeypatch)

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = _fake_choice("I'm not sure, maybe spam?")

    label, score = app_mod._groq_classify(mock_client, "Some email text")
    assert label is None
    assert score == 0


def test_groq_classify_exception_returns_none(monkeypatch):
    app_mod = _reload_app(monkeypatch)

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception("Network error")

    label, score = app_mod._groq_classify(mock_client, "Some email text")
    assert label is None
    assert score == 0


def test_groq_classify_none_client(monkeypatch):
    app_mod = _reload_app(monkeypatch)
    label, score = app_mod._groq_classify(None, "Some email text")
    assert label is None
    assert score == 0


# ─── generate_ai_email (consensus loop) ──────────────────────────────────────


def test_consensus_reached_round_1(monkeypatch):
    """When generator and verifier agree with high quality, consensus should be reached."""
    app_mod = _reload_app(monkeypatch)

    mock_or_client = MagicMock()
    mock_or_client.chat.completions.create.return_value = _fake_choice(
        _fake_email_json("Phishing email", "phishing")
    )

    mock_groq_client = MagicMock()
    mock_groq_client.chat.completions.create.return_value = _fake_choice("phishing 4")

    with patch.object(app_mod, "_make_or_client", return_value=mock_or_client), \
         patch.object(app_mod, "Groq", return_value=mock_groq_client), \
         patch.object(app_mod, "_trigger_prefetch"), \
         patch("time.sleep"):
        email, error = app_mod.generate_ai_email(800, "phishing")

    assert email is not None
    assert error is None
    assert email["_validated"] is True
    assert email["_consensus_round"] == 1
    assert email["_quality_score"] == 4


def test_consensus_disagreement_retries(monkeypatch):
    """Disagreement should trigger retries; consensus on round 2 should succeed."""
    app_mod = _reload_app(monkeypatch)

    mock_or_client = MagicMock()
    mock_or_client.chat.completions.create.return_value = _fake_choice(
        _fake_email_json("Test email", "phishing")
    )

    mock_groq_client = MagicMock()
    # Round 1: disagree; Round 2: agree with quality
    mock_groq_client.chat.completions.create.side_effect = [
        _fake_choice("legitimate 3"),   # Disagree
        _fake_choice("phishing 4"),     # Agree
    ]

    # Patch _trigger_prefetch to no-op - the background thread would race with
    # the test and consume mock responses from the side_effect list.
    with patch.object(app_mod, "_make_or_client", return_value=mock_or_client), \
         patch.object(app_mod, "Groq", return_value=mock_groq_client), \
         patch.object(app_mod, "_trigger_prefetch"), \
         patch("time.sleep"):  # Skip delays
        email, error = app_mod.generate_ai_email(800, "phishing")

    assert email is not None
    assert email["_validated"] is True
    assert email["_consensus_round"] == 2
    assert email["_quality_score"] == 4


def test_verifier_failure_serves_unverified(monkeypatch):
    """If the verifier returns None, the email should be served unverified."""
    app_mod = _reload_app(monkeypatch)

    mock_or_client = MagicMock()
    mock_or_client.chat.completions.create.return_value = _fake_choice(
        _fake_email_json("Email", "phishing")
    )

    mock_groq_client = MagicMock()
    mock_groq_client.chat.completions.create.side_effect = Exception("Groq down")

    with patch.object(app_mod, "_make_or_client", return_value=mock_or_client), \
         patch.object(app_mod, "Groq", return_value=mock_groq_client), \
         patch("time.sleep"):
        email, error = app_mod.generate_ai_email(800, "phishing")

    assert email is not None
    assert email["_validated"] is False
    assert email["_consensus_round"] == 0
    assert email["_quality_score"] == 0


def test_missing_api_keys_returns_error(monkeypatch):
    """Missing API keys should return a clear error message."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    if "app" in sys.modules:
        del sys.modules["app"]
    with patch("threading.Thread"), patch("os.path.isfile", return_value=False):
        import app as app_mod

        email, error = app_mod.generate_ai_email(800, "phishing")
        assert email is None
        assert "Missing" in error


# ─── _RateLimiter ─────────────────────────────────────────────────────────────


def test_rate_limiter_allows_first_request(monkeypatch):
    app_mod = _reload_app(monkeypatch)
    limiter = app_mod._RateLimiter()
    assert limiter.is_limited("test_key", 2.0) is False


def test_rate_limiter_blocks_rapid_requests(monkeypatch):
    app_mod = _reload_app(monkeypatch)
    limiter = app_mod._RateLimiter()
    limiter.is_limited("test_key", 2.0)  # First request
    assert limiter.is_limited("test_key", 2.0) is True  # Too fast


def test_rate_limiter_allows_after_interval(monkeypatch):
    app_mod = _reload_app(monkeypatch)
    limiter = app_mod._RateLimiter()
    limiter.is_limited("test_key", 0.0)  # Interval of 0 = always allow
    assert limiter.is_limited("test_key", 0.0) is False


# ─── _check_csrf ──────────────────────────────────────────────────────────────


def test_csrf_rejects_missing_header(monkeypatch):
    app_mod = _reload_app(monkeypatch)

    mock_req = MagicMock()
    mock_req.headers = {}
    mock_req.host_url = "http://localhost:5000/"

    result = app_mod._check_csrf(mock_req)
    assert result is not None
    assert "X-Requested-With" in result


def test_csrf_accepts_valid_request(monkeypatch):
    app_mod = _reload_app(monkeypatch)

    mock_req = MagicMock()
    mock_req.headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "http://localhost:5000",
    }
    mock_req.host_url = "http://localhost:5000/"

    result = app_mod._check_csrf(mock_req)
    assert result is None


def test_csrf_rejects_cross_origin(monkeypatch):
    app_mod = _reload_app(monkeypatch)

    mock_req = MagicMock()
    mock_req.headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "http://evil.com",
    }
    mock_req.host_url = "http://localhost:5000/"

    result = app_mod._check_csrf(mock_req)
    assert result is not None
    assert "Origin" in result


def test_csrf_rejects_subdomain_prefix_hijack(monkeypatch):
    """Origin sharing prefix with host must be rejected."""
    app_mod = _reload_app(monkeypatch)

    mock_req = MagicMock()
    mock_req.headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "http://localhost:5000.evil.com",
    }
    mock_req.host_url = "http://localhost:5000/"

    result = app_mod._check_csrf(mock_req)
    assert result is not None
    assert "Origin" in result


def test_csrf_accepts_reverse_proxy_https(monkeypatch):
    """Reverse-proxied HTTPS requests with X-Forwarded-Proto should pass."""
    app_mod = _reload_app(monkeypatch)

    mock_req = MagicMock()
    mock_req.headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "https://phishguard.multihat.dev",
        "X-Forwarded-Proto": "https",
    }
    mock_req.host_url = "http://phishguard.multihat.dev/"

    result = app_mod._check_csrf(mock_req)
    assert result is None


def test_openrouter_circuit_breaker_activates_on_free_tier_limit(monkeypatch):
    """Account-level free tier limit should activate circuit breaker cooldown."""
    app_mod = _reload_app(monkeypatch)

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception(
        "Rate limit exceeded: free-models-per-min."
    )

    email, error = app_mod._openrouter_generate(mock_client, "phishing", 800)
    assert email is None
    assert error is not None
    assert app_mod._is_openrouter_cooling_down()

    # While cooling down, subsequent call should immediately return without API calls
    mock_client.chat.completions.create.reset_mock()
    email2, error2 = app_mod._openrouter_generate(mock_client, "phishing", 800)
    assert email2 is None
    assert "cooling down" in str(error2).lower()
    assert mock_client.chat.completions.create.call_count == 0


def test_groq_classify_prioritizes_non_generator_model(monkeypatch):
    """When a generator model is excluded, Groq verifier tries other models first."""
    app_mod = _reload_app(monkeypatch)

    mock_client = MagicMock()
    # First model (non-excluded) succeeds
    mock_client.chat.completions.create.return_value = _fake_choice("phishing 5")

    label, score = app_mod._groq_classify(
        mock_client, "Test text", exclude_model="qwen/qwen3.8-27b"
    )
    assert label == "phishing"
    assert score == 5

    # Check that model passed in create was not the excluded generator
    first_call_model = mock_client.chat.completions.create.call_args[1]["model"]
    assert first_call_model != "qwen/qwen3.8-27b"


