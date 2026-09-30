"""Fix mode: let the agent edit a working copy, then decide in code whether to deploy.

The model proposes a code change; everything else is done and decided here:

  preconditions  not a test alert; Grafana shows the rule firing for the alert's route;
                 `git status --porcelain app/ tests/` is clean; no other fix run in
                 progress (lock file); at most one fix attempt per incident
  workspace      incidents/<ID>/workspace/ = copies of app/ and tests/ + the evidence
                 (no .env, no .git, nothing else); pristine copies in baseline/
  agent          headless claude, canary variant (v): edits only inside the workspace,
                 tests/ and evidence/ denied by rule, no shell, no git; the whole repo
                 is fingerprinted around the run and any change outside the workspace
                 escalates (app/ and tests/ restored from baseline/)
  diff gate      only existing app/**.py files may change; no new/deleted files; size
                 cap; secret scan of the patch -> fix.patch
  replay list    GET requests that failed with 5xx, taken ONLY from the evidence (full
                 Tempo traces, incl. those of ERROR log lines), each path validated
                 against the alert's route template; replayed on localhost only
  replay gates   in-process against a scratch copy of the repo with a copy of the live
                 DB: the original code must reproduce >= 1 5xx, the patched code must
                 return non-5xx for every request
  test gate      `uv run --frozen pytest -q` in the patched scratch copy
  apply          copy the patched app/ files into the real tree, `docker compose up
                 --build -d --wait app`, replay against the live app, wait for the
                 Grafana rule to return to Normal for the route
  rollback       any failure after apply: restore the original app/ files from
                 baseline/ (no git), rebuild, escalate

Records: gates.json, fix.patch, verification.json, summary.md, escalation.md (on any
failure). Nothing is ever committed.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import evidence

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
STATE = HERE / "state"

MAX_CHANGED_LINES = 60
MAX_PATCH_BYTES = 20_000
MAX_REPLAYS = 10
SEGMENT = r"(?!\.\.?(?:/|$))[A-Za-z0-9._~\-]{1,100}"   # one path segment, never "." or ".."
COPY_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache")
# What the scratch repo needs to build and test the app (never .env, .git, data, incidents).
SCRATCH_FILES = ("pyproject.toml", "uv.lock", ".python-version")
SCRATCH_DIRS = ("app", "tests", "static")
DB_IN_CONTAINER = "/data/orders.db"
RULE_NORMAL_TIMEOUT_S = 300
RULE_POLL_S = 10

REPLAY_SCRIPT = '''\
import json, os, sys
os.environ["OTEL_CONSOLE_EXPORT"] = "false"
os.environ.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)
from fastapi.testclient import TestClient
from app.main import app
requests = json.load(open(sys.argv[1]))
results = []
with TestClient(app, raise_server_exceptions=False) as client:
    for method, path in requests:
        results.append({"method": method, "path": path, "status": client.request(method, path).status_code})
with open(sys.argv[2], "w") as fh:  # a file, not stdout: warnings on stderr must not mix in
    json.dump(results, fh)
'''


def utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------- dependencies


def _run(cmd: list[str], cwd: Path, timeout: float, env: dict[str, str] | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        return proc.returncode, (proc.stdout + proc.stderr)[-4000:]
    except subprocess.TimeoutExpired:
        return -9, f"timeout after {timeout}s"
    except OSError as exc:
        return -1, f"{type(exc).__name__}: {exc}"


def _live_status(path: str) -> int:
    port = int(os.getenv("ORDER_TRACKER_PORT", "8000"))
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as resp:  # noqa: S310 (localhost)
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, OSError):
        return 0


def tool_env() -> dict[str, str]:
    """Environment for uv/docker/git subprocesses: the basics, nothing secret."""

    keep = ("HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TMPDIR", "PATH", "DOCKER_HOST", "DOCKER_CONFIG",
            "XDG_RUNTIME_DIR", "XDG_CACHE_HOME", "UV_CACHE_DIR", "ORDER_TRACKER_PORT", "ORDER_TRACKER_TAG",
            "ORDER_TRACKER_SUBNET")
    return {k: os.environ[k] for k in keep if k in os.environ}


@dataclass
class Deps:
    """Everything with side effects, injectable for tests."""

    root: Path = ROOT
    state: Path = STATE
    run: Callable[..., tuple[int, str]] = _run
    live_status: Callable[[str], int] = _live_status
    rule_firing: Callable[[dict[str, Any]], tuple[bool, str]] | None = None
    rule_state: Callable[[dict[str, Any]], str | None] | None = None
    run_agent: Callable[[Path, Path], dict[str, Any]] | None = None   # (incident_dir, workspace) -> summary
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    env: Callable[[], dict[str, str]] = tool_env


# ---------------------------------------------------------------------------- records


class Gates:
    def __init__(self, incident_dir: Path) -> None:
        self.path = incident_dir / "gates.json"
        self.items: list[dict[str, Any]] = []

    def add(self, name: str, passed: bool, detail: Any = "") -> bool:
        self.items.append({"gate": name, "passed": passed, "detail": detail, "at": utc()})
        self.path.write_text(json.dumps(self.items, indent=2) + "\n", encoding="utf-8")
        return passed

    @property
    def failed(self) -> dict[str, Any] | None:
        return next((g for g in self.items if not g["passed"]), None)


# ---------------------------------------------------------------------------- preconditions


class FixLock:
    """One fix run at a time, across processes (lock file with the owner's pid)."""

    def __init__(self, state: Path) -> None:
        self.path = state / "fix-run.lock"
        self.held = False

    def acquire(self, incident_id: str) -> tuple[bool, str]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except FileExistsError:
                try:
                    owner = json.loads(self.path.read_text())
                    os.kill(int(owner["pid"]), 0)
                    return False, f"fix run for {owner.get('incident')} in progress (pid {owner['pid']})"
                except (ProcessLookupError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                    self.path.unlink(missing_ok=True)  # stale lock
                    continue
                except PermissionError:
                    return False, "fix lock held by another user's process"
            with os.fdopen(fd, "w") as fh:
                json.dump({"pid": os.getpid(), "incident": incident_id, "at": utc()}, fh)
            self.held = True
            return True, "lock acquired"
        return False, "could not acquire the fix lock"

    def release(self) -> None:
        if self.held:
            self.path.unlink(missing_ok=True)
            self.held = False


def check_preconditions(alert: dict[str, Any], incident_dir: Path, deps: Deps, lock: FixLock,
                        is_test: bool) -> tuple[bool, list[dict[str, Any]]]:
    """Evaluate every precondition (in order); the lock is only taken if all others pass."""

    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"precondition": name, "passed": passed, "detail": detail})

    add("not_a_test_alert", not is_test, 'labels.test == "true"' if is_test else "no test label")
    if is_test:  # a test alert never evaluates anything that could lead to fix mode
        return False, checks
    if deps.rule_firing is None:
        add("grafana_rule_firing", False, "no Grafana check configured")
    else:
        firing, detail = deps.rule_firing(alert)
        add("grafana_rule_firing", firing, detail)
    code, out = deps.run(["git", "status", "--porcelain", "--", "app/", "tests/"], deps.root, 60, deps.env())
    clean = code == 0 and not out.strip()
    add("app_and_tests_clean", clean, "clean" if clean else
        (f"git exited {code}" if code else f"uncommitted changes: {len(out.strip().splitlines())} path(s)"))
    attempted = (incident_dir / "fix-attempt.json").exists()
    add("first_fix_attempt_for_incident", not attempted, "already attempted" if attempted else "first attempt")
    if all(c["passed"] for c in checks):
        ok, detail = lock.acquire(incident_dir.name)
        add("no_other_fix_in_progress", ok, detail)
    else:  # the lock is only taken when everything else passed: recorded as skipped (None)
        checks.append({"precondition": "no_other_fix_in_progress", "passed": None,
                       "detail": "not checked: an earlier precondition failed"})
    return all(c["passed"] is True for c in checks), checks


# ---------------------------------------------------------------------------- workspace


def build_workspace(root: Path, incident_dir: Path) -> tuple[Path, Path]:
    workspace, baseline = incident_dir / "workspace", incident_dir / "baseline"
    for target in (workspace, baseline):
        if target.exists():
            shutil.rmtree(target)
        for sub in ("app", "tests"):
            shutil.copytree(root / sub, target / sub, ignore=COPY_IGNORE)
    shutil.copytree(incident_dir / "evidence", workspace / "evidence")
    return workspace, baseline


FINGERPRINT_SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache"}
FINGERPRINT_SKIP_PREFIXES = ("incident-response/incidents/", "incident-response/state/", "incident-response/logs/",
                             "incident-response/quarantine/", "incident-response/canary/runs/")


def repo_fingerprint(root: Path) -> dict[str, str]:
    """sha256 of every file in the repo (incl. gitignored ones such as .env), except .git,
    .venv, caches and the responder's own runtime folders. Used to prove the agent wrote
    nothing outside its workspace."""

    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = [d for d in dirnames if d not in FINGERPRINT_SKIP_DIRS
                       and not (prefix + d + "/").startswith(FINGERPRINT_SKIP_PREFIXES)]
        for name in filenames:
            rel = prefix + name
            if not rel.startswith(FINGERPRINT_SKIP_PREFIXES):
                try:
                    out[rel] = hashlib.sha256((Path(dirpath) / name).read_bytes()).hexdigest()
                except OSError:
                    out[rel] = "unreadable"
    return out


def restore_from_baseline(root: Path, baseline: Path, paths: list[str]) -> list[str]:
    """Put app/ and tests/ paths back as they were in baseline/; returns what was restored."""

    restored = []
    for rel in paths:
        if not rel.startswith(("app/", "tests/")):
            continue
        source, target = baseline / rel, root / rel
        if source.exists():
            shutil.copy2(source, target)
        else:
            target.unlink(missing_ok=True)
        restored.append(rel)
    return restored


def tree_files(base: Path) -> dict[str, bytes]:
    if not base.exists():
        return {}
    return {str(p.relative_to(base)): p.read_bytes() for p in sorted(base.rglob("*"))
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}


# ---------------------------------------------------------------------------- diff gate


@dataclass
class DiffResult:
    passed: bool
    reasons: list[str] = field(default_factory=list)
    patch: str = ""
    changed: dict[str, bytes] = field(default_factory=dict)   # "app/x.py" -> new content
    changed_lines: int = 0


def diff_gate(workspace: Path, baseline: Path, evidence_dir: Path) -> DiffResult:
    reasons: list[str] = []
    extra = sorted(p.name for p in workspace.iterdir() if p.name not in ("app", "tests", "evidence"))
    if extra:
        reasons.append(f"files outside app/, tests/, evidence/: {extra}")
    if tree_files(workspace / "tests") != tree_files(baseline / "tests"):
        reasons.append("tests/ was modified")
    if tree_files(workspace / "evidence") != tree_files(evidence_dir):
        reasons.append("evidence/ was modified")

    before, after = tree_files(baseline / "app"), tree_files(workspace / "app")
    added, deleted = sorted(set(after) - set(before)), sorted(set(before) - set(after))
    if added:
        reasons.append(f"new files in app/: {added}")
    if deleted:
        reasons.append(f"deleted files in app/: {deleted}")
    modified = sorted(f for f in set(before) & set(after) if before[f] != after[f])
    non_py = [f for f in modified if not f.endswith(".py")]
    if non_py:
        reasons.append(f"non-Python files changed in app/: {non_py}")

    patch_parts, changed_lines = [], 0
    for rel in modified:
        try:
            old, new = before[rel].decode("utf-8").splitlines(keepends=True), after[rel].decode("utf-8").splitlines(keepends=True)
        except UnicodeDecodeError:
            reasons.append(f"app/{rel} is not UTF-8 text")
            continue
        diff = list(difflib.unified_diff(old, new, f"a/app/{rel}", f"b/app/{rel}"))
        changed_lines += sum(1 for line in diff if line[:1] in "+-" and not line.startswith(("+++", "---")))
        patch_parts.append("".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
                                   for line in diff))
    patch = "".join(patch_parts)
    if not modified and not reasons:
        reasons.append("no change was made")
    if changed_lines > MAX_CHANGED_LINES:
        reasons.append(f"patch too large: {changed_lines} changed lines (max {MAX_CHANGED_LINES})")
    if len(patch.encode()) > MAX_PATCH_BYTES:
        reasons.append(f"patch too large: {len(patch.encode())} bytes (max {MAX_PATCH_BYTES})")
    secret_hits = patch_secret_hits(patch)
    if secret_hits:
        reasons.append(f"secret scan of the patch: {secret_hits}")
    return DiffResult(not reasons, reasons, patch, {f"app/{f}": after[f] for f in modified}, changed_lines)


def patch_secret_hits(patch: str) -> list[str]:
    added = "\n".join(line[1:] for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++"))
    hits = [f"added line: {h}" for h in evidence.key_value_hits("patch.py", added)]
    hits += [label for label, regex in evidence.SCAN_PATTERNS.items() if regex.search(added)]
    if any(v in added for v in evidence.known_secret_values()):
        hits.append("value of a key-like .env setting")
    return hits


# ---------------------------------------------------------------------------- replay list


def route_regex(route: str) -> re.Pattern[str]:
    parts = re.split(r"(\{[A-Za-z_][A-Za-z0-9_]*\})", route)
    return re.compile("^" + "".join(SEGMENT if p.startswith("{") else re.escape(p) for p in parts) + "$")


def _attrs(span: dict[str, Any]) -> dict[str, str]:
    out = {}
    for attr in span.get("attributes") or []:
        value = attr.get("value") or {}
        out[attr.get("key")] = next((str(v) for v in value.values()), "")
    return out


def replay_list(evidence_dir: Path, route: str | None) -> tuple[list[tuple[str, str]], list[str]]:
    """Failing requests to replay, from the evidence's full Tempo traces only.

    Only GET server spans with a 5xx status whose url.path matches the alert's route
    template are kept. Returns (requests, notes about what was skipped).
    """

    notes: list[str] = []
    if not route or not evidence.ROUTE_RE.match(route):
        return [], ["no valid route in the alert"]
    pattern = route_regex(route)
    requests: list[tuple[str, str]] = []
    for trace_file in sorted(evidence_dir.glob("tempo-trace-*.json")):
        try:
            doc = json.loads(trace_file.read_text())
        except json.JSONDecodeError:
            notes.append(f"{trace_file.name}: not JSON")
            continue
        body = (doc.get("trace") or doc) if isinstance(doc, dict) else {}
        batches = body.get("resourceSpans") or body.get("batches") or []
        for batch in batches:
            for scope in batch.get("scopeSpans") or batch.get("instrumentationLibrarySpans") or []:
                for span in scope.get("spans") or []:
                    a = _attrs(span)
                    method, path, status = a.get("http.request.method"), a.get("url.path"), a.get("http.response.status_code", "")
                    if not (method and path and status.isdigit() and int(status) >= 500):
                        continue
                    if method != "GET":
                        notes.append(f"{trace_file.name}: skipped {method} (GET only)")
                    elif not pattern.match(path):
                        notes.append(f"{trace_file.name}: skipped a path that does not match {route}")
                    elif (method, path) not in requests:
                        requests.append((method, path))
    return requests[:MAX_REPLAYS], notes


# ---------------------------------------------------------------------------- scratch repo + replays


def make_scratch(root: Path) -> Path:
    scratch = Path(tempfile.mkdtemp(prefix="ot-fix-"))
    for name in SCRATCH_FILES:
        if (root / name).exists():
            shutil.copy2(root / name, scratch / name)
    for name in SCRATCH_DIRS:
        if (root / name).exists():
            shutil.copytree(root / name, scratch / name, ignore=COPY_IGNORE)
    (scratch / "replay_inproc.py").write_text(REPLAY_SCRIPT)
    return scratch


def copy_live_db(deps: Deps, dest: Path) -> tuple[bool, str]:
    code, out = deps.run(["docker", "compose", "cp", f"app:{DB_IN_CONTAINER}", str(dest)], deps.root, 120, deps.env())
    return code == 0 and dest.exists(), (out.strip()[-300:] or "copied")


def replay_inprocess(deps: Deps, scratch: Path, requests: list[tuple[str, str]], label: str) -> tuple[list[dict[str, Any]] | None, str]:
    db = scratch / f"orders-{label}.db"
    ok, detail = copy_live_db(deps, db)
    if not ok:
        return None, f"could not copy the live DB: {detail}"
    (scratch / "replay-requests.json").write_text(json.dumps(requests))
    results_file = scratch / "replay-results.json"
    results_file.unlink(missing_ok=True)
    env = deps.env() | {"ORDER_DB_PATH": str(db), "OTEL_CONSOLE_EXPORT": "false"}
    code, out = deps.run(["uv", "run", "--frozen", "python", "replay_inproc.py", "replay-requests.json",
                          "replay-results.json"], scratch, 600, env)
    db.unlink(missing_ok=True)
    try:
        results = json.loads(results_file.read_text())
        return (results, f"exit {code}") if code == 0 and isinstance(results, list) else (None, f"replay exit {code}")
    except (OSError, json.JSONDecodeError):
        return None, f"replay failed (exit {code}): {out[-300:]}"


def replay_live(deps: Deps, requests: list[tuple[str, str]]) -> list[dict[str, Any]]:
    return [{"method": m, "path": p, "status": deps.live_status(p)} for m, p in requests]


def non_5xx(results: list[dict[str, Any]]) -> bool:
    return bool(results) and all(0 < r["status"] < 500 for r in results)


# ---------------------------------------------------------------------------- apply / rollback


def write_files(root: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        (root / rel).write_bytes(data)


def restart_app(deps: Deps) -> tuple[bool, str]:
    code, out = deps.run(["docker", "compose", "up", "--build", "-d", "--wait", "app"], deps.root, 900, deps.env())
    return code == 0, f"exit {code}: {out.strip()[-300:]}"


def wait_rule_normal(deps: Deps, alert: dict[str, Any]) -> tuple[bool, str]:
    if deps.rule_state is None:
        return False, "no Grafana state check configured"
    deadline, state = deps.clock() + RULE_NORMAL_TIMEOUT_S, None
    while True:
        state = deps.rule_state(alert)
        if state == "Normal":
            return True, "rule instance for the route is Normal"
        if deps.clock() >= deadline:
            return False, f"rule still {state!r} after {RULE_NORMAL_TIMEOUT_S}s"
        deps.sleep(RULE_POLL_S)


# ---------------------------------------------------------------------------- the run


def run(alert: dict[str, Any], incident_dir: Path, deps: Deps) -> dict[str, Any]:
    """Execute a fix attempt (preconditions already passed, lock held). Returns the outcome."""

    gates = Gates(incident_dir)
    (incident_dir / "fix-attempt.json").write_text(json.dumps({"started_at": utc()}) + "\n")
    route = evidence.alert_route(alert)
    evidence_dir = incident_dir / "evidence"
    verification: dict[str, Any] = {}
    applied: dict[str, bytes] = {}
    scratch: Path | None = None
    outcome: dict[str, Any]

    def finish(result: str, why: str = "") -> dict[str, Any]:
        (incident_dir / "verification.json").write_text(json.dumps(verification, indent=2) + "\n")
        return {"outcome": result, "why": why, "failed_gate": gates.failed}

    try:
        workspace, baseline = build_workspace(deps.root, incident_dir)
        requests, notes = replay_list(evidence_dir, route)
        if not gates.add("replay_list_from_evidence", bool(requests),
                         {"requests": requests, "notes": notes} if requests else
                         {"requests": [], "notes": notes or ["no failing GET request for this route in the evidence"]}):
            return finish("escalated", "nothing in the evidence to verify a fix against")

        scratch = make_scratch(deps.root)
        baseline_results, detail = replay_inprocess(deps, scratch, requests, "baseline")
        reproduced = baseline_results is not None and any(r["status"] >= 500 for r in baseline_results)
        if not gates.add("replay_reproduces_before_fix", reproduced, {"results": baseline_results, "detail": detail}):
            return finish("escalated", "the failing requests do not fail against the current code")

        before = repo_fingerprint(deps.root)
        agent = deps.run_agent(incident_dir, workspace) if deps.run_agent else {"ok": False, "detail": "no agent"}
        after = repo_fingerprint(deps.root)
        touched = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        if not gates.add("repo_untouched_by_agent", not touched,
                         "no file outside the workspace changed" if not touched else
                         {"changed_outside_workspace": touched,
                          "restored_from_baseline": restore_from_baseline(deps.root, baseline, touched)}):
            return finish("escalated", "the agent changed files outside its workspace (app/ and tests/ restored)")
        if not gates.add("agent_run", bool(agent.get("ok")), agent):
            return finish("escalated", "the agent run did not complete")

        diff = diff_gate(workspace, baseline, evidence_dir)
        (incident_dir / "fix.patch").write_text(diff.patch, encoding="utf-8")
        if not gates.add("diff_gate", diff.passed, {"reasons": diff.reasons, "files": sorted(diff.changed),
                                                    "changed_lines": diff.changed_lines}):
            return finish("escalated", "the change was rejected by the diff gate")

        write_files(scratch, diff.changed)
        code, out = deps.run(["uv", "run", "--frozen", "pytest", "-q"], scratch, 900, deps.env())
        (incident_dir / "test-gate.log").write_text(out, encoding="utf-8")
        if not gates.add("test_gate", code == 0, {"exit_code": code, "tail": out.strip().splitlines()[-1:] if out else []}):
            return finish("escalated", "the test suite failed with the patch")

        patched_results, detail = replay_inprocess(deps, scratch, requests, "patched")
        verification["replay_before_restart"] = patched_results
        if not gates.add("replay_before_restart", patched_results is not None and non_5xx(patched_results),
                         {"results": patched_results, "detail": detail}):
            return finish("escalated", "the patched code still fails the replayed requests")

        # ---- apply to the real tree (everything below rolls back on failure) ----
        current = {rel: (deps.root / rel).read_bytes() for rel in diff.changed}
        originals = {rel: (baseline / rel).read_bytes() for rel in diff.changed}
        if not gates.add("real_tree_unchanged_since_workspace", current == originals,
                         "app/ matches the workspace baseline" if current == originals else "app/ changed meanwhile"):
            return finish("escalated", "the real app/ changed during the fix run")
        write_files(deps.root, diff.changed)
        applied = originals
        ok, detail = restart_app(deps)
        if not gates.add("restart_app", ok, detail):
            raise RuntimeError("restart failed")
        live = replay_live(deps, requests)
        verification["replay_after_restart"] = live
        if not gates.add("replay_after_restart", non_5xx(live), live):
            raise RuntimeError("live replay still fails")
        ok, detail = wait_rule_normal(deps, alert)
        verification["grafana_rule_normal"] = {"passed": ok, "detail": detail}
        if not gates.add("grafana_rule_normal", ok, detail):
            raise RuntimeError("the alert did not return to Normal")
        outcome = finish("fixed")
    except Exception as exc:  # noqa: BLE001 - after apply, ANY failure must roll back
        if not applied:
            gates.add("unexpected_error", False, f"{type(exc).__name__}: {exc}")
            return finish("escalated", f"unexpected error before any change was applied: {type(exc).__name__}")
        write_files(deps.root, applied)
        ok, detail = restart_app(deps)
        verification["rollback"] = {"restored": sorted(applied), "rebuild_ok": ok, "detail": detail}
        gates.add("rollback", ok, {"restored": sorted(applied), "rebuild": detail})
        outcome = finish("rolled_back", f"{exc}; original app/ files restored")
    finally:
        if scratch:
            shutil.rmtree(scratch, ignore_errors=True)
    return outcome
