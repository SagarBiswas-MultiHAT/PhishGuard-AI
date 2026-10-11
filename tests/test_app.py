import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]


def build_client(tmp_path, monkeypatch):
    feedback_dir = tmp_path / "feedback"
    monkeypatch.setenv("PHISHGUARD_FEEDBACK_DIR", str(feedback_dir))
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-test-key")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test_key")

    if "app" in sys.modules:
        del sys.modules["app"]

    import app as app_module

    return app_module.app.test_client(), feedback_dir


# ─── API Endpoint Tests ────────────────────────────


def test_homepage_loads(tmp_path, monkeypatch):
    client, _ = build_client(tmp_path, monkeypatch)
    response = client.get("/")
    assert response.status_code == 200
    assert "PhishGuard" in response.get_data(as_text=True)


def test_get_email_returns_payload(tmp_path, monkeypatch):
    """Verify /get-email returns a valid payload.

    We mock generate_ai_email so this test works without live API keys.
    The mock simulates a successful consensus result.
    """
    client, _ = build_client(tmp_path, monkeypatch)
    mock_email = {
        "text": "Your account has been suspended. Click here to restore access immediately.",
        "label": "phishing",
        "_validated": True,
        "_consensus_round": 1,
        "_model": "test-model",  # SEC-07: this should be stripped by the endpoint
    }
    with patch("app.generate_ai_email", return_value=(mock_email, None)):
        response = client.get("/get-email", headers={
            "X-Requested-With": "XMLHttpRequest",
        })

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["text"]
    assert payload["label"] in {"phishing", "legitimate"}
    # Consensus metadata must be present
    assert "_validated" in payload
    assert "_consensus_round" in payload
    # SEC-07: _model must NOT be exposed to the client
    assert "_model" not in payload


def test_get_email_returns_503_when_ai_fails(tmp_path, monkeypatch):
    """If all AI attempts fail, /get-email must return 503 - no silent dataset fallback."""
    client, _ = build_client(tmp_path, monkeypatch)
    with patch("app.generate_ai_email", return_value=(None, "AI unavailable")):
        response = client.get("/get-email", headers={
            "X-Requested-With": "XMLHttpRequest",
        })

    assert response.status_code == 503
    payload = response.get_json()
    assert "error" in payload


def test_submit_feedback_persists_file(tmp_path, monkeypatch):
    client, feedback_dir = build_client(tmp_path, monkeypatch)
    response = client.post(
        "/submit-feedback",
        json={"feedback": "Great flow"},
        headers={
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    assert response.status_code == 200
    assert feedback_dir.exists()
    assert any(feedback_dir.iterdir())

    # SEC-03: Verify feedback file uses UUID naming, not timestamps
    for f in feedback_dir.iterdir():
        assert f.name.startswith("feedback_")
        assert len(f.name) > len("feedback_.json") + 10  # UUID is 32 hex chars


def test_health_endpoint(tmp_path, monkeypatch):
    client, _ = build_client(tmp_path, monkeypatch)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_submit_feedback_rejects_empty(tmp_path, monkeypatch):
    """Empty feedback must be rejected with 400."""
    client, _ = build_client(tmp_path, monkeypatch)
    response = client.post(
        "/submit-feedback",
        json={"feedback": ""},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert response.status_code == 400


def test_submit_feedback_rejects_too_long(tmp_path, monkeypatch):
    """Feedback exceeding the max length must be rejected with 400."""
    client, _ = build_client(tmp_path, monkeypatch)
    long_text = "x" * 301  # MQ-05: limit is now 300
    response = client.post(
        "/submit-feedback",
        json={"feedback": long_text},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert response.status_code == 400


def test_submit_feedback_rejects_missing_csrf_header(tmp_path, monkeypatch):
    """SEC-01: POST without X-Requested-With header must be rejected."""
    client, _ = build_client(tmp_path, monkeypatch)
    response = client.post(
        "/submit-feedback",
        json={"feedback": "Test"},
        # No X-Requested-With header
    )
    assert response.status_code == 403
    payload = response.get_json()
    assert "error" in payload


def test_security_headers_present(tmp_path, monkeypatch):
    """SEC-04: All security headers must be set on every response."""
    client, _ = build_client(tmp_path, monkeypatch)
    response = client.get("/")

    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert "Content-Security-Policy" in response.headers


def test_get_email_rate_limited(tmp_path, monkeypatch):
    """SEC-06: Rapid /get-email requests must be rate-limited."""
    client, _ = build_client(tmp_path, monkeypatch)
    mock_email = {
        "text": "Test email",
        "label": "phishing",
        "_validated": True,
        "_consensus_round": 1,
    }
    # Patch prefetch cache so both requests hit the rate limiter,
    # rather than the second being served from the global cache.
    with patch("app.generate_ai_email", return_value=(mock_email, None)), \
         patch("app._pop_prefetch_cache", return_value=None), \
         patch("app._trigger_prefetch"):
        # First request should succeed
        r1 = client.get(
            "/get-email",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert r1.status_code == 200

        # Immediate second request should be rate-limited
        r2 = client.get(
            "/get-email",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert r2.status_code == 429


def test_send_feedback_email_skipped_when_unconfigured(monkeypatch):
    """Email delivery should gracefully skip when SMTP env vars are absent."""
    import app
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASS", raising=False)
    assert app._send_feedback_email("Great app", "127.0.0.1", "TestAgent", 1000) is False


def test_send_feedback_email_success_starttls(monkeypatch):
    """Email delivery over STARTTLS port 587 should connect, authenticate, and send."""
    import app
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USER", "bot@example.com")
    monkeypatch.setenv("SMTP_PASS", "secret-app-password")
    monkeypatch.setenv("FEEDBACK_RECIPIENT_EMAIL", "admin@example.com")

    mock_server = MagicMock()
    with patch("smtplib.SMTP", return_value=mock_server) as mock_smtp:
        mock_server.__enter__.return_value = mock_server
        result = app._send_feedback_email("Need more scenarios", "127.0.0.1", "TestAgent", 1000)

        assert result is True
        mock_smtp.assert_called_once_with("smtp.example.com", 587, timeout=10)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("bot@example.com", "secret-app-password")
        assert mock_server.send_message.call_count == 1
        msg = mock_server.send_message.call_args[0][0]
        assert msg["Subject"] == "[PhishGuard] New User Feedback Received"
        assert msg["To"] == "admin@example.com"
        assert "Need more scenarios" in msg.get_payload(decode=True).decode("utf-8")


def test_send_feedback_email_success_ssl(monkeypatch):
    """Email delivery over SSL port 465 should connect via SMTP_SSL."""
    import app
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "465")
    monkeypatch.setenv("SMTP_USER", "bot@example.com")
    monkeypatch.setenv("SMTP_PASS", "secret-app-password")
    monkeypatch.setenv("FEEDBACK_RECIPIENT_EMAIL", "admin@example.com")

    mock_server = MagicMock()
    with patch("smtplib.SMTP_SSL", return_value=mock_server) as mock_smtp_ssl:
        mock_server.__enter__.return_value = mock_server
        result = app._send_feedback_email("SSL test feedback", "127.0.0.1", "TestAgent", 1000)

        assert result is True
        mock_smtp_ssl.assert_called_once_with("smtp.example.com", 465, timeout=10)
        mock_server.login.assert_called_once_with("bot@example.com", "secret-app-password")
        assert mock_server.send_message.call_count == 1


def test_send_feedback_email_catches_and_sanitizes_error(monkeypatch):
    """SMTP exceptions should be caught and logged safely without crashing."""
    import app
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USER", "bot@example.com")
    monkeypatch.setenv("SMTP_PASS", "secret-app-password")

    with patch("smtplib.SMTP", side_effect=Exception("Connection refused")):
        result = app._send_feedback_email("Fails safely", "127.0.0.1", "TestAgent", 1000)
        assert result is False

