"""Unit tests for the creativity engine subsystems.

Covers: scenario taxonomy & rotation, similarity deduplication guard,
quality score parsing, dynamic prompt builder, and low-quality rejection.
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

    with patch("threading.Thread"):
        import app as app_module

    # Reset global state for a clean slate
    with app_module._prefetch_lock:
        app_module._prefetch_cache = None
        app_module._prefetch_busy = False
        app_module._recent_scenarios.clear()
        app_module._recent_texts.clear()

    return app_module


def _fake_choice(content):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
    )


def _fake_email_json(text="Test email body", label="phishing"):
    return json.dumps({"text": text, "label": label})


# ─── _pick_scenario ──────────────────────────────────────────────────────────


def test_pick_scenario_returns_string(monkeypatch):
    """_pick_scenario should return a non-empty string from the taxonomy."""
    app_mod = _reload_app(monkeypatch)
    result = app_mod._pick_scenario("phishing")
    assert isinstance(result, str)
    assert len(result) > 0
    assert result in app_mod.PHISHING_SCENARIOS


def test_pick_scenario_legitimate(monkeypatch):
    """_pick_scenario with 'legitimate' should pick from LEGITIMATE_SCENARIOS."""
    app_mod = _reload_app(monkeypatch)
    result = app_mod._pick_scenario("legitimate")
    assert result in app_mod.LEGITIMATE_SCENARIOS


def test_pick_scenario_avoids_recent(monkeypatch):
    """Should not return the same scenario if it's still in the recent window."""
    app_mod = _reload_app(monkeypatch)

    # Fill the recent history with all but one scenario
    pool = app_mod.PHISHING_SCENARIOS
    all_but_last = pool[:-1]
    with app_mod._prefetch_lock:
        app_mod._recent_scenarios.extend(all_but_last)

    # The only available scenario should be the last one
    result = app_mod._pick_scenario("phishing")
    assert result == pool[-1]


def test_pick_scenario_resets_when_all_used(monkeypatch):
    """When all scenarios are in recent history, it should still return one."""
    app_mod = _reload_app(monkeypatch)

    # Fill with ALL scenarios
    with app_mod._prefetch_lock:
        app_mod._recent_scenarios.extend(app_mod.PHISHING_SCENARIOS)

    # Should not crash - picks from full pool when all are recent
    result = app_mod._pick_scenario("phishing")
    assert result in app_mod.PHISHING_SCENARIOS


# ─── _is_too_similar ──────────────────────────────────────────────────────────


def test_similarity_guard_rejects_duplicate(monkeypatch):
    """Near-duplicate text should be flagged as too similar."""
    app_mod = _reload_app(monkeypatch)

    # Record a text
    app_mod._record_served_text(
        "Your account has been suspended please verify your identity immediately"
    )

    # Very similar text (just slight word changes)
    similar = "Your account has been suspended please verify your identity now"
    assert app_mod._is_too_similar(similar) is True


def test_similarity_guard_allows_novel(monkeypatch):
    """Completely different text should pass the similarity check."""
    app_mod = _reload_app(monkeypatch)

    app_mod._record_served_text(
        "Your account has been suspended please verify your identity immediately"
    )

    novel = (
        "Hi team, the quarterly OKR review meeting has been moved to Friday at 3pm. "
        "Please update your slides in the shared drive before Thursday EOD."
    )
    assert app_mod._is_too_similar(novel) is False


def test_similarity_guard_empty_buffer(monkeypatch):
    """With no recent texts, nothing should be flagged as similar."""
    app_mod = _reload_app(monkeypatch)
    assert app_mod._is_too_similar("Any random email content") is False


def test_record_served_text_bounded(monkeypatch):
    """The recent text buffer should not exceed _RECENT_TEXT_BUFFER_SIZE."""
    app_mod = _reload_app(monkeypatch)

    for i in range(20):
        app_mod._record_served_text(f"Email number {i} with unique content")

    with app_mod._prefetch_lock:
        assert len(app_mod._recent_texts) <= app_mod._RECENT_TEXT_BUFFER_SIZE


# ─── _build_generation_prompt ─────────────────────────────────────────────────


def test_dynamic_prompt_includes_scenario(monkeypatch):
    """The generated prompt should contain the scenario hint."""
    app_mod = _reload_app(monkeypatch)
    prompt = app_mod._build_generation_prompt("phishing", "CEO fraud - urgent wire transfer")
    assert "CEO fraud" in prompt
    assert "SCENARIO DIRECTIVE" in prompt


def test_dynamic_prompt_includes_label(monkeypatch):
    """The prompt should contain the desired label."""
    app_mod = _reload_app(monkeypatch)
    prompt = app_mod._build_generation_prompt("legitimate", "Internal standup recap")
    assert "'legitimate'" in prompt


def test_dynamic_prompt_phishing_has_red_flags(monkeypatch):
    """Phishing prompts should mention red flags."""
    app_mod = _reload_app(monkeypatch)
    prompt = app_mod._build_generation_prompt("phishing", "Some scenario")
    assert "red flag" in prompt.lower()


def test_dynamic_prompt_legitimate_no_credentials(monkeypatch):
    """Legitimate prompts should instruct not to ask for credentials."""
    app_mod = _reload_app(monkeypatch)
    prompt = app_mod._build_generation_prompt("legitimate", "Some scenario")
    assert "credentials" in prompt.lower() or "passwords" in prompt.lower()


def test_dynamic_prompt_creativity_rules(monkeypatch):
    """Prompt should contain creativity-driving instructions."""
    app_mod = _reload_app(monkeypatch)
    prompt = app_mod._build_generation_prompt("phishing", "Some scenario")
    assert "NOVEL" in prompt or "CREATIVE" in prompt
    assert "example.com" in prompt  # anti-pattern guard


# ─── Quality Score Parsing ────────────────────────────────────────────────────


def test_quality_score_parsing_phishing_4(monkeypatch):
    """'phishing 4' should parse to label='phishing', score=4."""
    app_mod = _reload_app(monkeypatch)
    mock = MagicMock()
    mock.chat.completions.create.return_value = _fake_choice("phishing 4")
    label, score = app_mod._groq_classify(mock, "test")
    assert label == "phishing"
    assert score == 4


def test_quality_score_parsing_legitimate_5(monkeypatch):
    """'legitimate 5' should parse to label='legitimate', score=5."""
    app_mod = _reload_app(monkeypatch)
    mock = MagicMock()
    mock.chat.completions.create.return_value = _fake_choice("legitimate 5")
    label, score = app_mod._groq_classify(mock, "test")
    assert label == "legitimate"
    assert score == 5


def test_quality_score_missing(monkeypatch):
    """If the model returns just 'phishing' with no score, score should be 0."""
    app_mod = _reload_app(monkeypatch)
    mock = MagicMock()
    mock.chat.completions.create.return_value = _fake_choice("phishing")
    label, score = app_mod._groq_classify(mock, "test")
    assert label == "phishing"
    assert score == 0


# ─── Low Quality Rejection ───────────────────────────────────────────────────


def test_low_quality_triggers_regeneration(monkeypatch):
    """If verifier returns quality below threshold, the email should be rejected."""
    app_mod = _reload_app(monkeypatch)

    mock_or_client = MagicMock()
    # Generator always succeeds with valid JSON
    mock_or_client.chat.completions.create.return_value = _fake_choice(
        _fake_email_json("A generic phishing email", "phishing")
    )

    mock_groq_client = MagicMock()
    # Rounds 1-4: agree on label but quality too low (score=2 < threshold=3)
    # Round 5: agree with acceptable quality (score=4)
    mock_groq_client.chat.completions.create.side_effect = [
        _fake_choice("phishing 2"),  # Low quality
        _fake_choice("phishing 2"),  # Low quality
        _fake_choice("phishing 2"),  # Low quality
        _fake_choice("phishing 2"),  # Low quality
        _fake_choice("phishing 4"),  # Acceptable
    ]

    with patch.object(app_mod, "_make_or_client", return_value=mock_or_client), \
         patch.object(app_mod, "Groq", return_value=mock_groq_client), \
         patch.object(app_mod, "_trigger_prefetch"), \
         patch("time.sleep"):
        email, error = app_mod.generate_ai_email(800, "phishing")

    assert email is not None
    assert email["_quality_score"] == 4
    assert email["_consensus_round"] == 5


# ─── Scenario Type in Response ────────────────────────────────────────────────


def test_scenario_type_in_email_dict(monkeypatch):
    """The email dict should include _scenario_type from the taxonomy."""
    app_mod = _reload_app(monkeypatch)

    mock_or_client = MagicMock()
    mock_or_client.chat.completions.create.return_value = _fake_choice(
        _fake_email_json("Email text", "phishing")
    )

    mock_groq_client = MagicMock()
    mock_groq_client.chat.completions.create.return_value = _fake_choice("phishing 4")

    with patch.object(app_mod, "_make_or_client", return_value=mock_or_client), \
         patch.object(app_mod, "Groq", return_value=mock_groq_client), \
         patch.object(app_mod, "_trigger_prefetch"), \
         patch("time.sleep"):
        email, _ = app_mod.generate_ai_email(800, "phishing")

    assert email is not None
    assert "_scenario_type" in email
    assert email["_scenario_type"] in app_mod.PHISHING_SCENARIOS
