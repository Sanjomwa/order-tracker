"""Collect a bounded, repeatable, read-only evidence packet for one incident.

Every query is a fixed template in this file. The only inputs taken from the alert are
a validated route (used as an exact label match) and a time window derived from its
startsAt ("now" when absent or unparsable). Nothing here changes state: HTTP GETs to
Prometheus, Loki and Tempo on localhost, `docker compose ps`, and read-only git.

Every text file is redacted before it is written (key-like secret values, credentials
in URLs), then the whole packet is scanned. On any hit the incident folder is moved to
incident-response/quarantine/ (gitignored) and the responder must not run on it.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import redact_secrets

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
QUARANTINE = HERE / "quarantine"

PROM = "http://localhost:9090"
LOKI = "http://localhost:3100"
TEMPO = "http://localhost:3200"
SERVICE = "order-tracker"
METRIC = "http_server_request_duration_seconds_count"

LOG_LOOKBACK = timedelta(minutes=15)      # logs/traces: startsAt - 15m -> now
METRIC_LOOKBACK = timedelta(minutes=60)   # metrics: startsAt - 60m -> now (was it healthy before?)
STEP_SECONDS = 30
LOG_LIMIT = 200
TRACE_SEARCH_LIMIT = 20
FULL_TRACES = 3            # from the Tempo error-trace search
FULL_TRACES_FROM_LOGS = 3  # more, for trace ids on ERROR log lines not already fetched
HTTP_TIMEOUT = 20

ROUTE_RE = re.compile(r"^/[A-Za-z0-9_/{}.\-]{0,120}$")
TRACE_ID_RE = re.compile(r"^[0-9a-fA-F]{16,32}$")
# Loki structured metadata worth keeping per line; everything else is dropped.
LOG_FIELDS = (
    "detected_level", "severity_text", "trace_id", "span_id", "service_version",
    "http_route", "http_request_method", "http_response_status_code", "order_id",
    "code_function_name", "code_file_path", "code_line_number",
    "exception_type", "exception_message", "exception_stacktrace",
)
COMPOSE_PS_FIELDS = ("Service", "State", "Health", "Status", "Image", "RunningFor", "ExitCode")

URL_CREDENTIALS_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/@:]+:[^\s/@]+@")
SCAN_PATTERNS = {
    "credentials in a URL": URL_CREDENTIALS_RE,
    "bearer credential": re.compile(r"[Bb]earer\s+[A-Za-z0-9_.~+/=\-]{20,}"),
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "Anthropic API key": re.compile(r"sk-ant-[A-Za-z0-9_\-]{10,}"),
}


class QuarantinedError(RuntimeError):
    """The packet failed the secret scan and was moved out of incidents/."""


# ------------------------------------------------------------------------ helpers


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_starts_at(value: Any, now: datetime | None = None) -> datetime | None:
    """Grafana's startsAt (RFC 3339). None when absent, unparsable, zero or in the future."""

    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if dt.year < 2000 or dt > (now or utcnow()) + timedelta(minutes=5):
        return None
    return dt


def alert_route(alert: dict[str, Any]) -> str | None:
    labels = alert.get("labels") or {}
    for key in ("route", "http_route"):
        value = labels.get(key)
        if isinstance(value, str) and ROUTE_RE.match(value):
            return value
    return None


def http_get(url: str, params: dict[str, Any] | None = None, timeout: float = HTTP_TIMEOUT) -> tuple[int, bytes]:
    """GET a localhost backend. Returns (status, body); status 0 on connection errors."""

    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (fixed localhost URLs)
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()[:2000]
    except (urllib.error.URLError, OSError) as exc:
        return 0, json.dumps({"error": f"request failed: {type(exc).__name__}"}).encode()


def get_json(url: str, params: dict[str, Any] | None = None) -> Any:
    status, body = http_get(url, params)
    try:
        doc = json.loads(body or b"null")
    except json.JSONDecodeError:
        doc = {"error": "response was not JSON", "body_prefix": body[:300].decode("utf-8", "replace")}
    if status != 200 and not (isinstance(doc, dict) and "error" in doc):
        doc = {"error": f"HTTP {status}", "response": doc}
    return doc


def redact(text: str, path_hint: str) -> str:
    return redact_secrets.redact_text(URL_CREDENTIALS_RE.sub(r"\1[REDACTED]@", text), path_hint)


def redact_values(doc: Any) -> Any:
    """Redact every string inside a JSON document before it is serialised: log lines and
    attributes contain quotes that would be escaped (\\") once serialised, which hides
    `KEY="value"` pairs from the text-level rules."""

    if isinstance(doc, str):
        return redact(doc, "value.conf")
    if isinstance(doc, list):
        return [redact_values(v) for v in doc]
    if isinstance(doc, dict):
        return {k: redact_values(v) for k, v in doc.items()}
    return doc


class Packet:
    """Writes evidence files (redacted) and records each in the manifest."""

    def __init__(self, evidence_dir: Path) -> None:
        self.dir = evidence_dir
        self.entries: list[dict[str, Any]] = []

    def write(self, name: str, doc: Any, kind: str, query: str) -> None:
        # JSON documents are redacted value by value (a text pass would trip over escaped
        # quotes and corrupt the JSON); plain text is redacted as text.
        text = redact(doc, name) if isinstance(doc, str) else json.dumps(redact_values(doc), indent=2) + "\n"
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        data = path.read_bytes()
        self.entries.append({
            "file": name, "kind": kind, "query": query, "timestamp": iso(utcnow()),
            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        })


# ------------------------------------------------------------------------ queries


def _label_filter(route: str | None, status_re: str | None = None) -> str:
    parts = [f'service_name="{SERVICE}"']
    if route:
        parts.append(f'http_route="{route}"')
    if status_re:
        parts.append(f'http_response_status_code=~"{status_re}"')
    return "{" + ", ".join(parts) + "}"


def prom_queries(route: str | None) -> dict[str, tuple[str, str]]:
    """file -> (kind, PromQL). Range queries use a 1m increase per step."""

    by = "http_route, http_request_method, http_response_status_code"
    return {
        "metrics-5xx-by-route.json": (
            "range", f"sum by ({by}) (increase({METRIC}{_label_filter(route, '5..')}[1m]))"),
        "metrics-requests-by-route-status.json": (
            "range", f"sum by ({by}) (increase({METRIC}{_label_filter(route)}[1m]))"),
        "metrics-request-totals.json": (
            "instant", f"sum by ({by}, service_version) ({METRIC}{_label_filter(route)})"),
    }


LOKI_QUERIES = {
    "logs-warn-error.json": f'{{service_name="{SERVICE}"}} | detected_level=~"(?i)warn|warning|error|fatal|critical"',
    "logs-recent.json": f'{{service_name="{SERVICE}"}}',
}
TRACEQL_ERRORS = f'{{resource.service.name="{SERVICE}" && status = error}}'


def compact_loki(doc: Any) -> Any:
    if not isinstance(doc, dict) or "data" not in doc:
        return doc
    lines = []
    for stream in (doc.get("data") or {}).get("result") or []:
        labels = stream.get("stream") or {}
        for ts, line in stream.get("values") or []:
            entry = {"time": iso(datetime.fromtimestamp(int(ts) / 1e9, timezone.utc)), "line": str(line)[:500]}
            for key in LOG_FIELDS:
                if key in labels:
                    value = str(labels[key])
                    entry[key] = value[:1500] if key == "exception_stacktrace" else value[:300]
            lines.append(entry)
    lines.sort(key=lambda e: e["time"], reverse=True)
    return {"count": len(lines), "lines": lines[:LOG_LIMIT]}


def compose_ps() -> Any:
    try:
        proc = subprocess.run(["docker", "compose", "ps", "--all", "--format", "json"], cwd=ROOT,
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": f"docker compose ps failed: {type(exc).__name__}"}
    if proc.returncode != 0:
        return {"error": f"docker compose ps exited {proc.returncode}"}
    services = []
    for line in proc.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        services.append({k: row.get(k) for k in COMPOSE_PS_FIELDS})
    return services


def git_state() -> Any:
    def run(*args: str) -> str:
        try:
            return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=30).stdout
        except (OSError, subprocess.TimeoutExpired):
            return ""
    status = [line for line in run("status", "--short").splitlines() if line.strip()]
    return {
        "head": run("rev-parse", "HEAD").strip() or None,
        "branch": run("rev-parse", "--abbrev-ref", "HEAD").strip() or None,
        "status_short": status[:100],
        "status_short_count": len(status),
    }


# ------------------------------------------------------------------------ packet


def collect(incident_id: str, incident_dir: Path, alert: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Write incident_dir/evidence/ and its manifest. Raises QuarantinedError on a scan hit."""

    now = now or utcnow()
    starts_at = parse_starts_at(alert.get("startsAt"), now)
    anchor = starts_at or now
    route = alert_route(alert)
    log_start, metric_start = anchor - LOG_LOOKBACK, anchor - METRIC_LOOKBACK
    ns = lambda dt: str(int(dt.timestamp() * 1e9))  # noqa: E731

    evidence = incident_dir / "evidence"
    if evidence.exists():
        shutil.rmtree(evidence)
    evidence.mkdir(parents=True)
    packet = Packet(evidence)

    packet.write("alert.json", alert, "input", "the alert as received (untrusted data; redacted copy)")
    window = {
        "incident_id": incident_id,
        "startsAt": alert.get("startsAt"),
        "anchor": iso(anchor),
        "anchor_source": "startsAt" if starts_at else "now (startsAt absent or unusable)",
        "route": route,
        "route_source": "alert labels" if route else "none in alert: all routes",
        "logs_and_traces": {"start": iso(log_start), "end": iso(now)},
        "metrics": {"start": iso(metric_start), "end": iso(now), "step_seconds": STEP_SECONDS},
    }
    packet.write("window.json", window, "input", "time window and route derived from the alert")

    for name, (kind, query) in prom_queries(route).items():
        if kind == "range":
            params = {"query": query, "start": int(metric_start.timestamp()), "end": int(now.timestamp()),
                      "step": STEP_SECONDS}
            packet.write(name, get_json(f"{PROM}/api/v1/query_range", params), "http_get",
                         f"GET {PROM}/api/v1/query_range query=[{query}] step={STEP_SECONDS}")
        else:
            packet.write(name, get_json(f"{PROM}/api/v1/query", {"query": query, "time": int(now.timestamp())}),
                         "http_get", f"GET {PROM}/api/v1/query query=[{query}]")

    logs: dict[str, Any] = {}
    for name, query in LOKI_QUERIES.items():
        params = {"query": query, "start": ns(log_start), "end": ns(now), "limit": LOG_LIMIT, "direction": "backward"}
        logs[name] = compact_loki(get_json(f"{LOKI}/loki/api/v1/query_range", params))
        packet.write(name, logs[name], "http_get",
                     f"GET {LOKI}/loki/api/v1/query_range query=[{query}] limit={LOG_LIMIT} (compacted: line<=500 chars)")

    search = get_json(f"{TEMPO}/api/search", {"q": TRACEQL_ERRORS, "limit": TRACE_SEARCH_LIMIT,
                                              "start": int(log_start.timestamp()), "end": int(now.timestamp())})
    packet.write("tempo-error-traces-search.json", search, "http_get",
                 f"GET {TEMPO}/api/search q=[{TRACEQL_ERRORS}] limit={TRACE_SEARCH_LIMIT}")
    searched = [t.get("traceID") for t in (search.get("traces") or [])] if isinstance(search, dict) else []
    searched = [t for t in searched if isinstance(t, str) and TRACE_ID_RE.match(t)][:FULL_TRACES]
    from_logs = []
    for line in (logs.get("logs-warn-error.json") or {}).get("lines") or []:
        tid = line.get("trace_id")
        if (str(line.get("detected_level", "")).upper() == "ERROR" and isinstance(tid, str) and TRACE_ID_RE.match(tid)
                and tid not in searched and tid not in from_logs):
            from_logs.append(tid)
    for n, (tid, source) in enumerate([(t, "error-trace search") for t in searched] +
                                      [(t, "trace_id of an ERROR log line") for t in from_logs[:FULL_TRACES_FROM_LOGS]], 1):
        packet.write(f"tempo-trace-{n}.json", get_json(f"{TEMPO}/api/v2/traces/{tid}"), "http_get",
                     f"GET {TEMPO}/api/v2/traces/{tid} (full trace; source: {source})")

    packet.write("docker-compose-ps.json", compose_ps(), "command",
                 f"docker compose ps --all --format json (fields: {', '.join(COMPOSE_PS_FIELDS)})")
    packet.write("git-state.json", git_state(), "command",
                 "git rev-parse HEAD; git rev-parse --abbrev-ref HEAD; git status --short (first 100 lines)")

    hits = scan(evidence)
    if hits:
        quarantine(incident_id, incident_dir, hits, now)

    manifest = {
        "incident_id": incident_id,
        "generated_at": iso(utcnow()),
        "read_only": True,
        "secret_scan": "passed (key-like values, URL credentials, bearer tokens, private keys, API keys, "
                       "values of key-like settings in .env)",
        "entries": packet.entries,
    }
    (evidence / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def quarantine(incident_id: str, incident_dir: Path, hits: list[str], now: datetime | None = None) -> None:
    """Move the whole incident folder out of incidents/ (gitignored) and raise."""

    QUARANTINE.mkdir(parents=True, exist_ok=True)
    target = QUARANTINE / f"{incident_id}-{int((now or utcnow()).timestamp())}"
    shutil.move(str(incident_dir), target)
    raise QuarantinedError(f"secret scan matched in {len(hits)} place(s): {', '.join(hits[:5])}; moved to {target}")


def known_secret_values() -> list[str]:
    """Values of key-like settings in the repo's .env (never printed; matched literally)."""

    env_file = ROOT / ".env"
    values = []
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            key, sep, value = line.partition("=")
            value = value.strip().strip("'\"")
            if sep and re.search(redact_secrets.KEY, key.strip(), re.I) and len(value) >= 6 \
                    and value.lower() not in redact_secrets.BENIGN_VALUES:
                values.append(value)
    return values


def json_strings(doc: Any) -> list[str]:
    if isinstance(doc, str):
        return [doc]
    if isinstance(doc, list):
        return [s for v in doc for s in json_strings(v)]
    if isinstance(doc, dict):
        return [s for k, v in doc.items() for s in (k, *json_strings(v))]
    return []


def key_value_hits(name: str, text: str) -> list[str]:
    """Key-like `KEY=value` / `KEY: value` pairs that escaped redaction (redact_secrets rules).

    JSON files are checked on their decoded string values, so escaped quotes do not hide
    (or fake) a match; other files line by line.
    """

    lines, regex, literal = text.splitlines(), redact_secrets.regex_for(name), redact_secrets.literal_only(name)
    if name.endswith(".json"):
        try:
            lines = [line for s in json_strings(json.loads(text)) for line in s.splitlines()]
            regex, literal = redact_secrets.CONFIG_RE, False
        except json.JSONDecodeError:
            pass
    hits = []
    for n, line in enumerate(lines, 1):
        if any(not redact_secrets._skip(m, line, literal) for m in regex.finditer(line)):
            hits.append(f"key-like value (item {n})")
    return hits


def scan(directory: Path) -> list[str]:
    """file:line (or file: reason) for anything secret-looking. Never returns the value itself."""

    hits = []
    secrets = known_secret_values()
    for file in sorted(p for p in directory.rglob("*") if p.is_file()):
        text = file.read_text(encoding="utf-8", errors="replace")
        rel = file.relative_to(directory)
        hits += [f"{rel}: {where}" for where in key_value_hits(file.name, text)]
        for label, regex in SCAN_PATTERNS.items():
            if regex.search(text):
                hits.append(f"{rel}: {label}")
        if any(value in text for value in secrets):
            hits.append(f"{rel}: value of a key-like .env setting")
    return hits
