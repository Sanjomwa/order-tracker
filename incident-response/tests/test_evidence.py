from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pytest

import evidence

NOW = datetime(2026, 9, 30, 10, 0, tzinfo=timezone.utc)
TRACE_ID = "8ae225f57cf8fe440ee7f71bec6adf45"


class Backends:
    """Canned Prometheus / Loki / Tempo responses; records every request."""

    def __init__(self, log_line="order lookup order_id=standard-1001 status=200"):
        self.requests = []
        self.log_line = log_line

    def __call__(self, url, params=None, timeout=0):
        self.requests.append((url, params or {}))
        path = urlparse(url).path
        if path.startswith("/api/v1/query"):
            doc = {"status": "success", "data": {"resultType": "matrix", "result": []}}
        elif path == "/loki/api/v1/query_range":
            doc = {"status": "success", "data": {"result": [{
                "stream": {"service_name": "order-tracker", "detected_level": "ERROR", "trace_id": TRACE_ID,
                           "unrelated_attr": "dropped"},
                "values": [["1790760000000000000", self.log_line]]}]}}
        elif path == "/api/search":
            doc = {"traces": [{"traceID": TRACE_ID}, {"traceID": "not-a-trace-id"}]}
        elif path.startswith("/api/v2/traces/"):
            doc = {"trace": {"resourceSpans": []}}
        else:
            return 404, b"not found"
        return 200, json.dumps(doc).encode()


@pytest.fixture
def backends(monkeypatch, tmp_path):
    b = Backends()
    monkeypatch.setattr(evidence, "http_get", b)
    monkeypatch.setattr(evidence, "compose_ps", lambda: [{"Service": "app", "State": "running"}])
    monkeypatch.setattr(evidence, "git_state", lambda: {"head": "1" * 40, "status_short": []})
    monkeypatch.setattr(evidence, "ROOT", tmp_path)
    monkeypatch.setattr(evidence, "QUARANTINE", tmp_path / "quarantine")
    return b


def alert(**overrides):
    a = {"status": "firing", "labels": {"alertname": "OrderTracker5xx", "route": "/api/orders/{order_id}"},
         "annotations": {}, "startsAt": "2026-09-30T09:50:00Z"}
    a.update(overrides)
    return a


def queries(backends):
    return [params.get("query") or params.get("q") for _, params in backends.requests]


def test_manifest_lists_every_file_with_its_hash(backends, tmp_path):
    inc = tmp_path / "INC-x"
    manifest = evidence.collect("INC-x", inc, alert(), now=NOW)
    files = {p.name for p in (inc / "evidence").iterdir()}
    listed = {e["file"] for e in manifest["entries"]}
    assert files == listed | {"manifest.json"}
    for entry in manifest["entries"]:
        data = (inc / "evidence" / entry["file"]).read_bytes()
        assert entry["sha256"] == hashlib.sha256(data).hexdigest() and entry["bytes"] == len(data)
    assert {"alert.json", "window.json", "metrics-5xx-by-route.json", "metrics-requests-by-route-status.json",
            "metrics-request-totals.json", "logs-warn-error.json", "logs-recent.json",
            "tempo-error-traces-search.json", "tempo-trace-1.json", "docker-compose-ps.json",
            "git-state.json"} <= files
    assert "tempo-trace-2.json" not in files  # the invalid trace id was not fetched


def test_window_is_anchored_on_starts_at_or_now(backends, tmp_path):
    evidence.collect("INC-a", tmp_path / "a", alert(), now=NOW)
    window = json.loads((tmp_path / "a" / "evidence" / "window.json").read_text())
    assert window["anchor"] == "2026-09-30T09:50:00Z" and window["anchor_source"] == "startsAt"
    assert window["logs_and_traces"]["start"] == "2026-09-30T09:35:00Z"

    evidence.collect("INC-b", tmp_path / "b", alert(startsAt=None), now=NOW)
    window = json.loads((tmp_path / "b" / "evidence" / "window.json").read_text())
    assert window["anchor"] == "2026-09-30T10:00:00Z" and window["anchor_source"].startswith("now")


def test_route_is_used_only_when_valid(backends, tmp_path):
    evidence.collect("INC-a", tmp_path / "a", alert(), now=NOW)
    assert any('http_route="/api/orders/{order_id}"' in (q or "") for q in queries(backends))

    backends.requests.clear()
    injected = alert(labels={"alertname": "x", "route": '/x"} or vector(1) or {a="'})
    evidence.collect("INC-b", tmp_path / "b", injected, now=NOW)
    assert not any("http_route=" in (q or "") for q in queries(backends))
    assert not any("vector(1)" in (q or "") for q in queries(backends))


def test_queries_are_fixed_templates(backends, tmp_path):
    evidence.collect("INC-a", tmp_path / "a", alert(labels={"alertname": "anything"}), now=NOW)
    hosts = {urlparse(url).netloc for url, _ in backends.requests}
    assert hosts == {"localhost:9090", "localhost:3100", "localhost:3200"}
    loki = [p["query"] for url, p in backends.requests if "loki" in url]
    assert loki == list(evidence.LOKI_QUERIES.values())


def test_log_lines_are_compacted_and_redacted(monkeypatch, backends, tmp_path):
    backends.log_line = 'connect failed: DB_PASSWORD="hunter2hunter2" url=postgres://app:s3cretpw@db/orders'
    evidence.collect("INC-a", tmp_path / "a", alert(), now=NOW)
    text = (tmp_path / "a" / "evidence" / "logs-warn-error.json").read_text()
    assert "hunter2hunter2" not in text and "s3cretpw" not in text and "[REDACTED]" in text
    doc = json.loads(text)
    assert doc["lines"][0]["trace_id"] == TRACE_ID and "unrelated_attr" not in doc["lines"][0]


def test_secret_scan_quarantines_the_packet(backends, tmp_path):
    backends.log_line = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"
    inc = tmp_path / "INC-q"
    with pytest.raises(evidence.QuarantinedError) as exc:
        evidence.collect("INC-q", inc, alert(), now=NOW)
    assert not inc.exists()
    [moved] = list((tmp_path / "quarantine").iterdir())
    assert moved.name.startswith("INC-q-")
    assert "abcdefghijklmnopqrstuvwxyz" not in str(exc.value)  # the reason names files, never values


def test_values_from_dotenv_are_caught(backends, tmp_path):
    (tmp_path / ".env").write_text("GRAFANA_ADMIN_PASSWORD=Zq8-not-a-real-one\n")
    backends.log_line = "user typed Zq8-not-a-real-one into a form"
    with pytest.raises(evidence.QuarantinedError):
        evidence.collect("INC-e", tmp_path / "e", alert(), now=NOW)


@pytest.mark.parametrize("value, ok", [
    ("2026-09-30T09:50:00Z", True), ("2026-09-30T09:50:00.123+02:00", True),
    ("0001-01-01T00:00:00Z", False), ("2999-01-01T00:00:00Z", False), ("yesterday", False), (None, False), (5, False),
])
def test_parse_starts_at(value, ok):
    assert (evidence.parse_starts_at(value, NOW) is not None) is ok


def test_query_params_are_encoded(backends, tmp_path):
    evidence.collect("INC-a", tmp_path / "a", alert(), now=NOW)
    url, params = next((u, p) for u, p in backends.requests if u.endswith("/api/search"))
    assert params["q"] == evidence.TRACEQL_ERRORS and params["limit"] == evidence.TRACE_SEARCH_LIMIT
    assert parse_qs(urlparse(url).query) == {}  # params travel separately, encoded by http_get


def test_scan_reads_json_string_values(tmp_path, monkeypatch):
    monkeypatch.setattr(evidence, "ROOT", tmp_path)
    (tmp_path / "leak.json").write_text(json.dumps({"line": 'client API_KEY="abcdef123456" rejected'}))
    (tmp_path / "clean.json").write_text(json.dumps({"line": 'client API_KEY="[REDACTED]" rejected', "n_tokens": 12}))
    hits = evidence.scan(tmp_path)
    assert hits and all(h.startswith("leak.json") for h in hits)
