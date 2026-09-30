"""Fix-mode gates, driven against a synthetic dummy app (never Order Tracker's code)."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

import evidence
import fixmode
import responder

ROUTE = "/api/shapes/{shape_id}"
DUMMY_APP = {
    "app/__init__.py": "",
    "app/shapes.py": 'def area(width, height):\n    """Area of a rectangle."""\n    return width + height\n',
    "app/data.json": '{"unit": "cm"}\n',
}
DUMMY_TESTS = {"tests/test_shapes.py": "from app.shapes import area\n\n\ndef test_area_of_square():\n    assert area(2, 2) == 4\n"}
FIXED = 'def area(width, height):\n    """Area of a rectangle."""\n    return width * height\n'


def write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)


def span(method="GET", path="/api/shapes/sq-1", status=500):
    attrs = [{"key": "http.request.method", "value": {"stringValue": method}},
             {"key": "url.path", "value": {"stringValue": path}},
             {"key": "http.route", "value": {"stringValue": ROUTE}},
             {"key": "http.response.status_code", "value": {"intValue": str(status)}}]
    return {"name": f"{method} {ROUTE}", "attributes": attrs}


def trace(*spans):
    return {"trace": {"resourceSpans": [{"scopeSpans": [{"spans": list(spans)}]}]}}


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    write_tree(root, DUMMY_APP | DUMMY_TESTS)
    incident = tmp_path / "incidents" / "INC-20260930-000000-shapes"
    (incident / "evidence").mkdir(parents=True)
    (incident / "evidence" / "tempo-trace-1.json").write_text(json.dumps(trace(span())))
    (incident / "evidence" / "alert.json").write_text("{}")
    return root, incident


def alert(**labels):
    return {"labels": {"alertname": "Shapes5xx", "route": ROUTE, **labels}, "annotations": {}}


class Recorder:
    """Fake subprocess runner for git / docker / uv; records every command."""

    def __init__(self, porcelain="", pytest_rc=0, restart_rcs=(0, 0), baseline_status=500, patched_status=200):
        self.cmds: list[list[str]] = []
        self.porcelain, self.pytest_rc = porcelain, pytest_rc
        self.restart_rcs = list(restart_rcs)
        self.replay_statuses = [baseline_status, patched_status]

    def __call__(self, cmd, cwd, timeout, env=None):
        self.cmds.append(cmd)
        if cmd[:2] == ["git", "status"]:
            return 0, self.porcelain
        if cmd[:3] == ["docker", "compose", "cp"]:
            Path(cmd[-1]).write_text("db copy")
            return 0, ""
        if cmd[:3] == ["docker", "compose", "up"]:
            return self.restart_rcs.pop(0), "restarted"
        if "replay_inproc.py" in cmd:
            requests = json.loads((Path(cwd) / cmd[-2]).read_text())
            status = self.replay_statuses.pop(0)
            results = [{"method": m, "path": p, "status": status} for m, p in requests]
            (Path(cwd) / cmd[-1]).write_text(json.dumps(results))
            return 0, "warnings on stderr do not matter"
        if "pytest" in cmd:
            return self.pytest_rc, "1 passed" if self.pytest_rc == 0 else "1 failed"
        raise AssertionError(f"unexpected command {cmd}")

    def ran(self, *prefix):
        return [c for c in self.cmds if c[:len(prefix)] == list(prefix)]


def fixing_agent(new_text=FIXED, rel="app/shapes.py"):
    def agent(incident_dir, workspace):
        (workspace / rel).write_text(new_text)
        return {"ok": True}
    return agent


def make_deps(root, tmp_path, recorder, agent=None, live=200, rule_states=("Normal",)):
    states = list(rule_states)
    return fixmode.Deps(root=root, state=tmp_path / "state", run=recorder, live_status=lambda path: live,
                        rule_firing=lambda a: (True, "Alerting"),
                        rule_state=lambda a: states.pop(0) if len(states) > 1 else states[0],
                        run_agent=agent or fixing_agent(), sleep=lambda s: None, env=lambda: {})


# ------------------------------------------------------------------ preconditions


def preconditions(repo, tmp_path, is_test=False, **deps_kw):
    root, incident = repo
    deps = make_deps(root, tmp_path, deps_kw.pop("recorder", Recorder()), **deps_kw)
    lock = fixmode.FixLock(deps.state)
    ok, checks = fixmode.check_preconditions(alert(), incident, deps, lock, is_test=is_test)
    return ok, {c["precondition"]: c["passed"] for c in checks}, lock


def test_all_preconditions_pass(repo, tmp_path):
    ok, checks, lock = preconditions(repo, tmp_path)
    assert ok and all(checks.values()) and lock.held
    lock.release()


def test_precondition_test_alert_short_circuits(repo, tmp_path):
    recorder = Recorder()
    ok, checks, lock = preconditions(repo, tmp_path, is_test=True, recorder=recorder)
    assert not ok and checks == {"not_a_test_alert": False} and not recorder.cmds and not lock.held


def test_precondition_grafana_not_firing(repo, tmp_path):
    root, incident = repo
    deps = make_deps(root, tmp_path, Recorder())
    deps.rule_firing = lambda a: (False, "Normal")
    ok, checks = fixmode.check_preconditions(alert(), incident, deps, fixmode.FixLock(deps.state), is_test=False)
    assert not ok and {c["precondition"]: c["passed"] for c in checks}["grafana_rule_firing"] is False


def test_precondition_dirty_tree(repo, tmp_path):
    ok, checks, lock = preconditions(repo, tmp_path, recorder=Recorder(porcelain=" M app/shapes.py\n"))
    assert not ok and checks["app_and_tests_clean"] is False and not lock.held
    assert checks["no_other_fix_in_progress"] is None  # skipped, not failed: the lock is never taken


def test_precondition_one_attempt_per_incident(repo, tmp_path):
    (repo[1] / "fix-attempt.json").write_text("{}")
    ok, checks, _ = preconditions(repo, tmp_path)
    assert not ok and checks["first_fix_attempt_for_incident"] is False


def test_precondition_fix_already_in_progress(repo, tmp_path):
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "fix-run.lock").write_text(json.dumps({"pid": os.getppid(), "incident": "INC-other"}))
    ok, checks, _ = preconditions(repo, tmp_path)
    assert not ok and checks["no_other_fix_in_progress"] is False


def test_stale_fix_lock_is_taken_over(repo, tmp_path):
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "fix-run.lock").write_text(json.dumps({"pid": 2**22 + 12345, "incident": "INC-old"}))
    ok, checks, lock = preconditions(repo, tmp_path)
    assert ok and lock.held
    lock.release()


# ------------------------------------------------------------------ diff gate


@pytest.fixture
def workspace(repo):
    root, incident = repo
    return fixmode.build_workspace(root, incident) + (incident / "evidence",)


def test_workspace_holds_only_app_tests_and_evidence(repo, workspace):
    ws, baseline, _ = workspace
    assert sorted(p.name for p in ws.iterdir()) == ["app", "evidence", "tests"]
    assert sorted(p.name for p in baseline.iterdir()) == ["app", "tests"]


def test_diff_gate_accepts_a_small_app_fix(workspace):
    ws, baseline, ev = workspace
    (ws / "app/shapes.py").write_text(FIXED)
    result = fixmode.diff_gate(ws, baseline, ev)
    assert result.passed, result.reasons
    assert "-    return width + height" in result.patch and "+    return width * height" in result.patch
    assert list(result.changed) == ["app/shapes.py"] and result.changed_lines == 2


@pytest.mark.parametrize("mutate, reason", [
    (lambda ws: (ws / "tests/test_shapes.py").write_text("def test_nothing():\n    pass\n"), "tests/ was modified"),
    (lambda ws: (ws / "tests/test_new.py").write_text(""), "tests/ was modified"),
    (lambda ws: (ws / "app/helpers.py").write_text("X = 1\n"), "new files in app/"),
    (lambda ws: (ws / "app/__init__.py").unlink(), "deleted files in app/"),
    (lambda ws: (ws / "app/data.json").write_text('{"unit": "mm"}\n'), "non-Python files changed"),
    (lambda ws: (ws / "app/shapes.py").write_text(FIXED + "".join(f"# line {i}\n" for i in range(80))), "patch too large"),
    (lambda ws: (ws / "app/shapes.py").write_text(FIXED + 'API_KEY = "abcdef1234567890"\n'), "secret scan of the patch"),
    (lambda ws: (ws / "evidence/alert.json").write_text('{"x": 1}'), "evidence/ was modified"),
    (lambda ws: (ws / "notes.md").write_text("hi"), "files outside app/, tests/, evidence/"),
    (lambda ws: None, "no change was made"),
])
def test_diff_gate_rejections(workspace, mutate, reason):
    ws, baseline, ev = workspace
    mutate(ws)
    result = fixmode.diff_gate(ws, baseline, ev)
    assert not result.passed and any(reason in r for r in result.reasons), result.reasons


# ------------------------------------------------------------------ replay list


def test_replay_list_comes_from_evidence_traces_only(tmp_path):
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "tempo-trace-1.json").write_text(json.dumps(trace(
        span(path="/api/shapes/sq-1"),                       # kept
        span(path="/api/shapes/sq-1"),                       # duplicate
        span(path="/api/shapes/sq-2", status=200),           # not a failure
        span(method="POST", path="/api/shapes/sq-3"),        # GET only
        span(path="/api/other/sq-4"),                        # wrong route
        span(path="/api/shapes/a/b"),                        # more segments than the template
        span(path="/api/shapes/.."),                         # traversal segment
        span(path="/api/shapes/sq-5?x=1"),                   # query strings are not allowed
    )))
    (ev / "tempo-trace-2.json").write_text(json.dumps(trace(span(path="/api/shapes/sq-6", status=503))))
    (ev / "logs-warn-error.json").write_text(json.dumps({"lines": [{"line": "GET /api/shapes/sq-9 failed"}]}))
    (tmp_path / "answer.md").write_text("Replay GET /api/shapes/sq-7 and /admin/drop")  # model text: never used
    requests, notes = fixmode.replay_list(ev, ROUTE)
    assert requests == [("GET", "/api/shapes/sq-1"), ("GET", "/api/shapes/sq-6")]
    assert any("GET only" in n for n in notes)


@pytest.mark.parametrize("route", [None, "", "not-a-path", '/x"} or vector(1)'])
def test_replay_list_needs_a_valid_route(tmp_path, route):
    (tmp_path / "tempo-trace-1.json").write_text(json.dumps(trace(span())))
    assert fixmode.replay_list(tmp_path, route)[0] == []


def test_route_regex():
    rx = fixmode.route_regex(ROUTE)
    assert rx.match("/api/shapes/sq-1") and rx.match("/api/shapes/a.b_c~d")
    assert not rx.match("/api/shapes/") and not rx.match("/api/shapes/a/b") and not rx.match("/api/shapes/..")
    assert not rx.match("/api/shapesX/1") and not rx.match("http://evil/api/shapes/1")


# ------------------------------------------------------------------ the run: success, escalation, rollback


def run(repo, tmp_path, recorder, **kw):
    root, incident = repo
    deps = make_deps(root, tmp_path, recorder, **kw)
    return fixmode.run(alert(), incident, deps), root, incident


def test_fix_applied_after_all_gates(repo, tmp_path):
    recorder = Recorder()
    result, root, incident = run(repo, tmp_path, recorder)
    assert result["outcome"] == "fixed", result
    assert (root / "app/shapes.py").read_text() == FIXED
    gates = [g["gate"] for g in json.loads((incident / "gates.json").read_text())]
    assert gates == ["replay_list_from_evidence", "replay_reproduces_before_fix", "repo_untouched_by_agent",
                     "agent_run", "diff_gate",
                     "test_gate", "replay_before_restart", "real_tree_unchanged_since_workspace", "restart_app",
                     "replay_after_restart", "grafana_rule_normal"]
    assert len(recorder.ran("docker", "compose", "up")) == 1
    verification = json.loads((incident / "verification.json").read_text())
    assert verification["replay_after_restart"] == [{"method": "GET", "path": "/api/shapes/sq-1", "status": 200}]
    assert "+    return width * height" in (incident / "fix.patch").read_text()


def test_rollback_when_live_replay_still_fails(repo, tmp_path):
    original = (repo[0] / "app/shapes.py").read_bytes()
    recorder = Recorder()
    result, root, incident = run(repo, tmp_path, recorder, live=500)
    assert result["outcome"] == "rolled_back"
    assert (root / "app/shapes.py").read_bytes() == original
    assert len(recorder.ran("docker", "compose", "up")) == 2  # deploy + rollback rebuild
    assert json.loads((incident / "verification.json").read_text())["rollback"]["restored"] == ["app/shapes.py"]


def test_rollback_when_restart_fails(repo, tmp_path):
    original = (repo[0] / "app/shapes.py").read_bytes()
    result, root, _ = run(repo, tmp_path, Recorder(restart_rcs=(1, 0)))
    assert result["outcome"] == "rolled_back" and (root / "app/shapes.py").read_bytes() == original


def test_rollback_when_alert_does_not_clear(repo, tmp_path):
    original = (repo[0] / "app/shapes.py").read_bytes()
    clock = iter(range(0, 10_000, 60))
    root, incident = repo
    deps = make_deps(root, tmp_path, Recorder(), rule_states=("Alerting",))
    deps.clock = lambda: next(clock)
    result = fixmode.run(alert(), incident, deps)
    assert result["outcome"] == "rolled_back" and (root / "app/shapes.py").read_bytes() == original


def test_escalates_without_touching_the_tree_when_tests_fail(repo, tmp_path):
    original = (repo[0] / "app/shapes.py").read_bytes()
    recorder = Recorder(pytest_rc=1)
    result, root, _ = run(repo, tmp_path, recorder)
    assert result["outcome"] == "escalated" and result["failed_gate"]["gate"] == "test_gate"
    assert (root / "app/shapes.py").read_bytes() == original and not recorder.ran("docker", "compose", "up")


def test_escalates_when_the_agent_edits_tests(repo, tmp_path):
    recorder = Recorder()
    result, root, _ = run(repo, tmp_path, recorder, agent=fixing_agent("def test_x():\n    pass\n", "tests/test_shapes.py"))
    assert result["outcome"] == "escalated" and result["failed_gate"]["gate"] == "diff_gate"
    assert not recorder.ran("uv", "run", "--frozen", "pytest", "-q")


def test_escalates_before_the_agent_when_the_failure_does_not_reproduce(repo, tmp_path):
    called = []
    recorder = Recorder(baseline_status=200)
    result, _, _ = run(repo, tmp_path, recorder, agent=lambda i, w: called.append(1) or {"ok": True})
    assert result["outcome"] == "escalated" and result["failed_gate"]["gate"] == "replay_reproduces_before_fix"
    assert not called


def test_escalates_when_the_evidence_has_nothing_to_replay(repo, tmp_path):
    (repo[1] / "evidence" / "tempo-trace-1.json").unlink()
    result, _, _ = run(repo, tmp_path, Recorder())
    assert result["outcome"] == "escalated" and result["failed_gate"]["gate"] == "replay_list_from_evidence"


def test_scratch_copy_has_no_secrets_or_git(repo, tmp_path):
    root, _ = repo
    (root / ".env").write_text("GRAFANA_ADMIN_PASSWORD=not-copied\n")
    (root / ".git").mkdir()
    scratch = fixmode.make_scratch(root)
    try:
        assert sorted(p.name for p in scratch.iterdir()) == ["app", "replay_inproc.py", "tests"]
    finally:
        shutil.rmtree(scratch)


# ------------------------------------------------------------------ pipeline: test alerts never reach fix mode


def test_pipeline_never_runs_fix_mode_for_a_test_alert(monkeypatch, tmp_path):
    monkeypatch.setattr(responder, "FIX_MODE_ENABLED", True)
    monkeypatch.setattr(responder, "INCIDENTS", tmp_path / "incidents")
    monkeypatch.setattr(evidence, "http_get", lambda url, params=None, timeout=0: (200, b'{"status":"success","data":{"result":[]}}'))
    monkeypatch.setattr(evidence, "compose_ps", lambda: [])
    monkeypatch.setattr(evidence, "git_state", lambda: {})
    monkeypatch.setattr(evidence, "ROOT", tmp_path)
    monkeypatch.setattr(responder, "claude_version", lambda env: "test")
    monkeypatch.setattr(fixmode, "run", lambda *a, **k: pytest.fail("fix mode must not run for a test alert"))

    class Runner:
        cmds = []

        def run(self, cmd, prompt, cwd, env, timeout):
            self.cmds.append(cmd)
            return 0, json.dumps({"result": "ok", "is_error": False}), ""

    runner = Runner()
    deps = make_deps(tmp_path, tmp_path, Recorder())
    [a] = responder.parse_payload(json.dumps({"alerts": [{"labels": {"alertname": "Shapes5xx", "route": ROUTE,
                                                                     "test": "true"}}]}).encode())
    iid = responder.new_incident_id(a)
    assert responder.pipeline(a, iid, runner=runner, deps=deps) == "analysed"
    assert runner.cmds == [responder.readonly_command()]
    assert not (tmp_path / "incidents" / iid / "escalation.md").exists()


def test_pipeline_escalates_a_real_alert_whose_preconditions_fail(monkeypatch, tmp_path):
    monkeypatch.setattr(responder, "FIX_MODE_ENABLED", True)
    monkeypatch.setattr(responder, "INCIDENTS", tmp_path / "incidents")
    monkeypatch.setattr(evidence, "http_get", lambda url, params=None, timeout=0: (200, b'{"status":"success","data":{"result":[]}}'))
    monkeypatch.setattr(evidence, "compose_ps", lambda: [])
    monkeypatch.setattr(evidence, "git_state", lambda: {})
    monkeypatch.setattr(evidence, "ROOT", tmp_path)
    monkeypatch.setattr(responder, "claude_version", lambda env: "test")

    class Runner:
        def run(self, cmd, prompt, cwd, env, timeout):
            return 0, json.dumps({"result": "analysis\nFinal line.", "is_error": False}), ""

    deps = make_deps(tmp_path, tmp_path, Recorder())
    deps.rule_firing = lambda a: (False, "no rule named 'TestAlert'")
    [a] = responder.parse_payload(b'{"alerts": [{"labels": {"alertname": "TestAlert", "instance": "Grafana"}}]}')
    iid = responder.new_incident_id(a)
    assert responder.pipeline(a, iid, runner=Runner(), deps=deps) == "escalated"
    inc = tmp_path / "incidents" / iid
    assert "grafana_rule_firing" in (inc / "escalation.md").read_text()
    assert json.loads((inc / "mode.json").read_text())["mode"] == "read-only"
    assert "escalated" in (inc / "summary.md").read_text()
    assert not (tmp_path / "state" / "fix-run.lock").exists()


def test_escalates_when_the_agent_writes_into_the_real_repo(repo, tmp_path):
    root, _ = repo
    original = (root / "app/shapes.py").read_bytes()

    def rogue_agent(incident_dir, workspace):
        (root / "app/shapes.py").write_text(FIXED)          # straight into the real tree
        (root / "app/extra.py").write_text("X = 1\n")
        (root / ".env").write_text("SOMETHING=1\n")
        (workspace / "app/shapes.py").write_text(FIXED)
        return {"ok": True}

    recorder = Recorder()
    result, _, incident = run(repo, tmp_path, recorder, agent=rogue_agent)
    assert result["outcome"] == "escalated" and result["failed_gate"]["gate"] == "repo_untouched_by_agent"
    detail = result["failed_gate"]["detail"]
    assert detail["changed_outside_workspace"] == [".env", "app/extra.py", "app/shapes.py"]
    assert detail["restored_from_baseline"] == ["app/extra.py", "app/shapes.py"]
    assert (root / "app/shapes.py").read_bytes() == original and not (root / "app/extra.py").exists()
    assert not recorder.ran("docker", "compose", "up") and not recorder.ran("uv", "run", "--frozen", "pytest", "-q")


def test_repo_fingerprint_skips_runtime_folders(tmp_path):
    for rel in ("app/a.py", ".env", ".git/HEAD", ".venv/x", "incident-response/incidents/I/x", "incident-response/responder.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    assert sorted(fixmode.repo_fingerprint(tmp_path)) == [".env", "app/a.py", "incident-response/responder.py"]
