from __future__ import annotations

import http.client
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

import evidence
import responder

HOMEWORK_TEST = {"alerts": [{"status": "firing", "labels": {"alertname": "ResponderTest", "test": "true"},
                             "annotations": {"summary": "Test notification; no incident to fix"}}]}


def grafana_alert(**overrides):
    alert = {
        "status": "firing",
        "labels": {"alertname": "OrderTracker5xx", "route": "/api/orders/{order_id}", "severity": "critical"},
        "annotations": {"summary": "2 5xx response(s) on /api/orders/{order_id} in the last 1m"},
        "startsAt": "2026-09-30T09:00:00Z",
        "endsAt": "0001-01-01T00:00:00Z",
        "fingerprint": "a1b2c3d4e5f60718",
        "generatorURL": "http://localhost:3000/alerting/grafana/order-tracker-5xx/view",
        "dashboardURL": "http://localhost:3000/d/order-tracker-overview",
    }
    alert.update(overrides)
    return alert


def payload(*alerts):
    return json.dumps({"receiver": "responder", "status": "firing", "alerts": list(alerts)}).encode()


# ------------------------------------------------------------------ payload parsing


def test_parses_grafana_payload():
    [alert] = responder.parse_payload(payload(grafana_alert()))
    assert alert["status"] == "firing"
    assert alert["labels"]["route"] == "/api/orders/{order_id}"
    assert alert["fingerprint"] == "a1b2c3d4e5f60718"
    assert alert["startsAt"] == "2026-09-30T09:00:00Z"
    assert alert["raw"]["generatorURL"].endswith("/view")


def test_parses_homework_test_payload_without_timestamps():
    [alert] = responder.parse_payload(json.dumps(HOMEWORK_TEST).encode())
    assert alert["labels"] == {"alertname": "ResponderTest", "test": "true"}
    assert "startsAt" not in alert and "fingerprint" not in alert
    assert responder.is_test_alert(alert)


def test_keeps_resolved_alerts_for_the_caller_to_ignore():
    [alert] = responder.parse_payload(payload(grafana_alert(status="resolved")))
    assert alert["status"] == "resolved"


@pytest.mark.parametrize("body", [
    b"{not json", b"[]", b'{"alerts": {}}', b'{"alerts": []}', b'{"alerts": ["x"]}',
    b'{"alerts": [{"status": "exploded"}]}', b'{"alerts": [{"labels": {"a": 1}}]}',
    b'{"alerts": [{"labels": "x"}]}', b'{"alerts": [{"startsAt": 5}]}', b"\xff\xfe",
])
def test_malformed_payloads_are_400(body):
    with pytest.raises(responder.PayloadError) as exc:
        responder.parse_payload(body)
    assert exc.value.status == 400


def test_oversized_payload_is_413():
    with pytest.raises(responder.PayloadError) as exc:
        responder.parse_payload(b" " * (responder.MAX_BODY_BYTES + 1))
    assert exc.value.status == 413


# ------------------------------------------------------------------ deduplication


def test_dedupe_key_uses_fingerprint_and_starts_at():
    a = responder.parse_payload(payload(grafana_alert()))[0]
    repeat = responder.parse_payload(payload(grafana_alert(annotations={"summary": "3 5xx"})))[0]
    new_activation = responder.parse_payload(payload(grafana_alert(startsAt="2026-09-30T09:30:00Z")))[0]
    assert responder.dedupe_key(a) == responder.dedupe_key(repeat)
    assert responder.dedupe_key(a) != responder.dedupe_key(new_activation)
    assert responder.dedupe_key(a).startswith("fp:")


def test_dedupe_key_falls_back_to_payload_hash():
    [a] = responder.parse_payload(json.dumps(HOMEWORK_TEST).encode())
    [b] = responder.parse_payload(json.dumps(HOMEWORK_TEST).encode())
    assert responder.dedupe_key(a) == responder.dedupe_key(b)
    assert responder.dedupe_key(a).startswith("hash:")


def test_deduper_expires_hash_keys_but_keeps_fingerprints(tmp_path):
    now = [1_000_000.0]
    d = responder.Deduper(tmp_path / "seen.json", clock=lambda: now[0])
    assert d.first_time("hash:x") and d.first_time("fp:f:t")
    assert not d.first_time("hash:x") and not d.first_time("fp:f:t")
    now[0] += responder.DEDUPE_HASH_TTL + 1
    assert d.first_time("hash:x")
    assert not d.first_time("fp:f:t")
    reloaded = responder.Deduper(tmp_path / "seen.json", clock=lambda: now[0])
    assert not reloaded.first_time("fp:f:t")


# ------------------------------------------------------------------ HTTP endpoint


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(responder, "INCIDENTS", tmp_path / "incidents")
    worker = responder.Worker()  # not started: jobs stay queued for inspection
    srv = ThreadingHTTPServer(("127.0.0.1", 0), responder.make_handler(worker, responder.Deduper(None)))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv, worker
    srv.shutdown()
    srv.server_close()


def post(srv, body: bytes, headers=None, path="/alerts"):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
    conn.request("POST", path, body=body, headers={"Content-Type": "application/json", **(headers or {})})
    resp = conn.getresponse()
    status, data = resp.status, resp.read()
    conn.close()
    return status, json.loads(data)


def test_post_alerts_accepts_dedupes_and_ignores_resolved(server):
    srv, worker = server
    status, doc = post(srv, json.dumps(HOMEWORK_TEST).encode())
    assert status == 202 and len(doc["accepted"]) == 1 and doc["accepted"][0].endswith("respondertest")
    assert post(srv, json.dumps(HOMEWORK_TEST).encode()) == (202, {"accepted": [], "duplicates": 1, "resolved_ignored": 0})
    assert post(srv, payload(grafana_alert(status="resolved")))[1]["resolved_ignored"] == 1
    assert worker.jobs.qsize() == 1


def test_post_rejects_bad_input(server):
    srv, worker = server
    assert post(srv, b"{oops")[0] == 400
    assert post(srv, b"{}", headers={"Content-Length": str(responder.MAX_BODY_BYTES + 1)})[0] == 413
    assert post(srv, json.dumps(HOMEWORK_TEST).encode(), path="/other")[0] == 404
    assert worker.jobs.qsize() == 0


# ------------------------------------------------------------------ mode selection


def firing_rules(state="Alerting", route="/api/orders/{order_id}", name="OrderTracker5xx"):
    return {"status": "success", "data": {"groups": [{"name": "order-tracker-5xx", "rules": [
        {"name": name, "state": "firing", "alerts": [{"state": state, "labels": {"alertname": name, "route": route}}]},
    ]}]}}


def test_test_alert_never_enters_fix_mode_even_if_enabled_and_firing(monkeypatch):
    monkeypatch.setattr(responder, "FIX_MODE_ENABLED", True)
    [alert] = responder.parse_payload(payload(grafana_alert(labels={**grafana_alert()["labels"], "test": "true"})))
    mode = responder.select_mode(alert, rule_firing=lambda a: (True, "firing"))
    assert mode["mode"] == "read-only" and "test alert" in mode["reason"]


def test_fix_mode_is_off():
    assert responder.FIX_MODE_ENABLED is False
    [alert] = responder.parse_payload(payload(grafana_alert()))
    called = []
    mode = responder.select_mode(alert, rule_firing=lambda a: called.append(a) or (True, "firing"))
    assert mode == {"mode": "read-only", "reason": "fix mode not enabled (Q6)"}
    assert not called


def test_fix_mode_gate_requires_grafana_to_confirm_firing(monkeypatch):
    monkeypatch.setattr(responder, "FIX_MODE_ENABLED", True)
    [alert] = responder.parse_payload(payload(grafana_alert()))
    assert responder.select_mode(alert, rule_firing=lambda a: (False, "Normal"))["mode"] == "read-only"
    assert responder.select_mode(alert, rule_firing=lambda a: (True, "Alerting"))["mode"] == "fix"


# ------------------------------------------------------------------ Grafana firing check


@pytest.mark.parametrize("doc, expected", [
    (firing_rules(), True),
    (firing_rules(state="Alerting (NoData)"), False),
    (firing_rules(state="Alerting (Error)"), False),
    (firing_rules(state="Normal"), False),
    (firing_rules(state="Pending"), False),
    (firing_rules(route="/api/orders"), False),
    (firing_rules(name="SomethingElse"), False),
    ({"status": "error"}, False),
    ({"error": "request failed: URLError"}, False),
    (None, False),
])
def test_grafana_rule_firing(doc, expected):
    [alert] = responder.parse_payload(payload(grafana_alert()))
    urls = []
    firing, detail = responder.grafana_rule_firing(alert, get_json=lambda url: urls.append(url) or doc)
    assert firing is expected, detail
    assert urls == ["http://localhost:3000/api/prometheus/grafana/api/v1/rules"]


def test_grafana_rule_firing_needs_a_route():
    [alert] = responder.parse_payload(b'{"alerts": [{"labels": {"alertname": "OrderTracker5xx"}}]}')
    firing, detail = responder.grafana_rule_firing(alert, get_json=lambda url: firing_rules())
    assert firing is False and "no route" in detail


def test_worker_drops_queued_jobs_when_stopping(monkeypatch, tmp_path):
    monkeypatch.setattr(responder, "INCIDENTS", tmp_path)
    ran = []
    monkeypatch.setattr(responder, "pipeline", lambda alert, iid: ran.append(iid))
    worker = responder.Worker()
    (tmp_path / "INC-20260930-000000-a").mkdir()
    worker.stopping.set()
    worker.jobs.put(("INC-20260930-000000-a", {}))
    worker.jobs.put(None)
    worker.run()
    assert ran == [] and not (tmp_path / "INC-20260930-000000-a").exists()


def test_grafana_rule_firing_needs_an_alertname():
    [alert] = responder.parse_payload(b'{"alerts": [{"labels": {}}]}')
    assert responder.grafana_rule_firing(alert, get_json=lambda url: firing_rules()) == (False, "alert has no alertname")


# ------------------------------------------------------------------ claude command


def test_readonly_command_flags_are_exact():
    assert responder.readonly_command() == [
        "claude", "-p",
        "--output-format", "json",
        "--tools", "Read,Grep,Glob",
        "--permission-mode", "dontAsk",
        "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
        "--no-session-persistence",
        "--disable-slash-commands",
        "--no-chrome",
        "--setting-sources", "",
        "--settings", '{"advisorModel":""}',
        "--max-budget-usd", "0.50",
        "--model", "sonnet",
        "--append-system-prompt", responder.SYSTEM_PROMPT,
    ]
    cmd = responder.readonly_command()
    assert "--allowedTools" not in cmd and "Bash" not in " ".join(cmd) and "Edit" not in " ".join(cmd)


def test_responder_env_is_allowlisted(monkeypatch):
    monkeypatch.setenv("GRAFANA_ADMIN_PASSWORD", "x" * 12)
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector")
    env = responder.responder_env()
    assert set(env) <= set(responder.ENV_ALLOWLIST) | {"PATH"}


# ------------------------------------------------------------------ pipeline (all backends mocked)


class FakeRunner:
    def __init__(self, envelope):
        self.envelope, self.calls = envelope, []

    def run(self, cmd, prompt, cwd, env, timeout):
        self.calls.append({"cmd": cmd, "prompt": prompt, "cwd": cwd, "env": env})
        return 0, json.dumps(self.envelope), ""


def fake_backends(monkeypatch, tmp_path):
    monkeypatch.setattr(evidence, "http_get", lambda url, params=None, timeout=0: (200, b'{"status":"success","data":{"result":[]}}'))
    monkeypatch.setattr(evidence, "compose_ps", lambda: [{"Service": "app", "State": "running"}])
    monkeypatch.setattr(evidence, "git_state", lambda: {"head": "0" * 40, "status_short": []})
    monkeypatch.setattr(evidence, "ROOT", tmp_path)          # no .env there
    monkeypatch.setattr(evidence, "QUARANTINE", tmp_path / "quarantine")
    monkeypatch.setattr(responder, "INCIDENTS", tmp_path / "incidents")
    monkeypatch.setattr(responder, "claude_version", lambda env: "test")


def test_pipeline_for_homework_test_alert(monkeypatch, tmp_path):
    fake_backends(monkeypatch, tmp_path)
    runner = FakeRunner({"type": "result", "subtype": "success", "is_error": False, "num_turns": 3,
                         "total_cost_usd": 0.01, "result": "Nothing to fix.\nSummary: test notification only."})
    [alert] = responder.parse_payload(json.dumps(HOMEWORK_TEST).encode())
    iid = responder.new_incident_id(alert)
    assert responder.pipeline(alert, iid, runner=runner) == "analysed"

    inc = tmp_path / "incidents" / iid
    assert json.loads((inc / "alert.json").read_text()) == HOMEWORK_TEST["alerts"][0]
    assert json.loads((inc / "mode.json").read_text())["mode"] == "read-only"
    assert (inc / "answer.md").read_text().rstrip().endswith("Summary: test notification only.")
    events = [json.loads(line)["event"] for line in (inc / "timeline.jsonl").read_text().splitlines()]
    assert events == ["alert_received", "mode_selected", "evidence_collected", "responder_started",
                      "responder_finished", "final_secret_scan", "finished"]
    [call] = runner.calls
    assert call["cmd"] == responder.readonly_command()
    assert call["cwd"] == inc / "evidence"
    assert iid in call["prompt"] and "alert.json" in call["prompt"]
    assert "Test notification" not in call["prompt"]  # alert text reaches the model only as a file
    assert "command: claude -p --output-format json" in (inc / "responder-command.txt").read_text()


def test_pipeline_stops_on_quarantine(monkeypatch, tmp_path):
    fake_backends(monkeypatch, tmp_path)
    leaky = json.dumps({"status": "success", "data": {"result": [
        {"stream": {"detected_level": "ERROR"}, "values": [["1790000000000000000", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123"]]}]}})
    monkeypatch.setattr(evidence, "http_get", lambda url, params=None, timeout=0: (200, leaky.encode()))
    runner = FakeRunner({})
    [alert] = responder.parse_payload(json.dumps(HOMEWORK_TEST).encode())
    iid = responder.new_incident_id(alert)
    assert responder.pipeline(alert, iid, runner=runner) == "quarantined"
    assert not runner.calls
    assert not (tmp_path / "incidents" / iid).exists()
    assert len(list((tmp_path / "quarantine").iterdir())) == 1


def test_incident_id_is_safe_for_untrusted_alertnames(monkeypatch, tmp_path):
    monkeypatch.setattr(responder, "INCIDENTS", tmp_path)
    [alert] = responder.parse_payload(b'{"alerts": [{"labels": {"alertname": "../../etc/passwd; rm -rf /"}}]}')
    iid = responder.new_incident_id(alert)
    assert responder.INCIDENT_ID_RE.match(iid) and "/" not in iid and ".." not in iid
    assert Path(tmp_path / iid).parent == tmp_path


def test_pipeline_quarantines_when_the_answer_leaks(monkeypatch, tmp_path):
    fake_backends(monkeypatch, tmp_path)
    runner = FakeRunner({"type": "result", "subtype": "success", "is_error": False,
                         "result": "Found it: Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"})
    [alert] = responder.parse_payload(json.dumps(HOMEWORK_TEST).encode())
    iid = responder.new_incident_id(alert)
    assert responder.pipeline(alert, iid, runner=runner) == "quarantined"
    assert not (tmp_path / "incidents" / iid).exists()
