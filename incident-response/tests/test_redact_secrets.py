"""Tests for the evidence redactor / secret-scan backstop (K-011)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import redact_secrets as rs  # noqa: E402


@pytest.mark.parametrize("line,expected", [
    ("POSTGRES_PASSWORD: realvalue", "POSTGRES_PASSWORD: [REDACTED]"),
    ("  - POSTGRES_PASSWORD=realvalue", "  - POSTGRES_PASSWORD=[REDACTED]"),
    ("-e POSTGRES_PASSWORD=realvalue -e POSTGRES_DB=x", "-e POSTGRES_PASSWORD=[REDACTED] -e POSTGRES_DB=x"),
    ('GF_SECURITY_ADMIN_PASSWORD: "realvalue"', 'GF_SECURITY_ADMIN_PASSWORD: "[REDACTED]"'),
    ("my_api_key=abc123", "my_api_key=[REDACTED]"),
    ("Private-Key: abc123", "Private-Key: [REDACTED]"),
    ('"claim_token": "clm_realvalue"', '"claim_token": "[REDACTED]"'),
    # placeholders, comments and metadata are left alone
    ("RELAY_ENROLLMENT_SECRET: ${RELAY_ENROLLMENT_SECRET:?set it in .env}", None),
    ("GRAFANA_ADMIN_PASSWORD=<placeholder>", None),
    ("RELAY_ENROLLMENT_SECRET=change-me", None),
    ("# the enrollment secret: take it from .env", None),
    ("secret_scan: passed", None),
    ("POSTGRES_PASSWORD: [REDACTED]", None),
    ('"cache_creation_input_tokens": 13256, "output_tokens": 2', None),  # counts, not secrets
    ('"output_tokens_details": {"thinking_tokens": 0}', None),  # JSON structure
    ("WHERE agents.token_hash = %(token_hash_1)s::VARCHAR", None),  # SQL bind placeholder in a span
    ("WHERE token_hash = $1 AND secret = ?", None),
])
def test_config_style(line, expected):
    assert rs.redact_text(line, "compose.yaml") == (expected if expected is not None else line)


@pytest.mark.parametrize("line,expected", [
    ('ENROLLMENT_SECRET = "enroll-real"', 'ENROLLMENT_SECRET = "[REDACTED]"'),
    ('API_KEY: str = "sk-live-xyz"', 'API_KEY: str = "[REDACTED]"'),
    ('headers = {"X-Enrollment-Secret": "real"}', 'headers = {"X-Enrollment-Secret": "[REDACTED]"}'),
    # code must stay readable: expressions and annotations are not values
    ("claim_token: str = Field(min_length=1)", None),
    ("token_hash=secret_hash(token)", None),
    ('    token = new_secret("agt")', None),
    ("x_enrollment_secret: str | None = Header(default=None),", None),
])
def test_python_literals_only(line, expected):
    assert rs.redact_text(line, "main.py") == (expected if expected is not None else line)


def test_js_in_html_is_literal_only():
    line = "const token = document.querySelector('#token');"
    assert rs.redact_text(line, "dashboard.html") == line


def test_diff_uses_per_file_rules():
    diff = ("diff --git a/compose.yaml b/compose.yaml\n+      POSTGRES_PASSWORD: realvalue\n"
            "diff --git a/main.py b/main.py\n+    token_hash=secret_hash(token)\n")
    out = rs.redact_diff(diff)
    assert "POSTGRES_PASSWORD: [REDACTED]" in out and "realvalue" not in out
    assert "token_hash=secret_hash(token)" in out


def test_scan_backstop_finds_unredacted_and_passes_redacted(tmp_path):
    (tmp_path / "clean.yaml").write_text("POSTGRES_PASSWORD: [REDACTED]\nX: ${Y_SECRET:?set}\n")
    (tmp_path / "code.py").write_text("token_hash=secret_hash(token)\n")
    assert rs.find_hits(tmp_path) == []
    (tmp_path / "alert.json").write_text('{"annotations": {"leak": "POSTGRES_PASSWORD: realvalue"}}\n')
    assert rs.find_hits(tmp_path) == ["alert.json:1"]
