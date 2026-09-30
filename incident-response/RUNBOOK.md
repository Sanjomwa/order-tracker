# Runbook: OrderTracker5xx and the automatic responder

**Alert:** `OrderTracker5xx` (Grafana-managed, folder "Order Tracker"). It fires when any
route returned at least one HTTP 5xx in the last minute. Dashboard:
<http://localhost:3000/d/order-tracker-overview/order-tracker-overview> ("5xx rate by route").

## The loop

```
Grafana rule fires -> policy routes OrderTracker5xx to contact point "incident-responder"
  -> POST http://host.docker.internal:8001/alerts (responder on the WSL host, 127.0.0.1:8001)
  -> 202, one incident at a time: incident-response/incidents/<ID>/
       alert.json, timeline.jsonl, mode.json, evidence/ (fixed queries, redacted, scanned)
  -> mode chosen in code (responder.select_mode + fixmode.check_preconditions)
       read-only: claude analyses the evidence (answer.md); real alerts also get escalation.md
       fix:       claude edits a working copy; gates decide; fixed or escalated/rolled back
  -> summary.md; final secret scan of the folder
```

## Modes and preconditions

- **Test alerts** (`labels.test == "true"`) are always read-only, never escalated, and never
  evaluate anything that could lead to fix mode.
- **Fix mode** requires ALL of:
  - the alert is not a test alert;
  - Grafana's own API shows the rule instance for the alert's `route` in state exactly
    `Alerting` (the webhook itself is untrusted);
  - `git status --porcelain app/ tests/` is clean (so a previous unreviewed fix blocks the next);
  - no other fix run in progress (`incident-response/state/fix-run.lock`, pid-checked);
  - no earlier fix attempt for this incident (`fix-attempt.json`).
  Any failure: read-only analysis + `escalation.md`.
- `RESPONDER_FIX_MODE=off incident-response/start-responder.sh start` disables fix mode
  entirely: every real alert is analysed read-only and escalated.

## Gates in fix mode (all decided by code; see `gates.json`)

| # | Gate | Passes when |
|---|---|---|
| 1 | replay_list_from_evidence | the evidence's full Tempo traces (error-trace search + traces of ERROR log lines) contain GET server spans with a 5xx whose `url.path` matches the alert's route template; never taken from the model's text |
| 2 | replay_reproduces_before_fix | in-process replay against the **current** code (scratch copy of the repo + a copy of the live DB) returns at least one 5xx; otherwise nothing proves a fix |
| 3 | repo_untouched_by_agent | a sha256 fingerprint of the whole repo (except .git, .venv, caches and the responder's runtime folders) is identical before and after the agent run; otherwise the changed app/ and tests/ files are restored from `baseline/` |
| 4 | agent_run | headless claude (fix flag set) finished in `incidents/<ID>/workspace/` (copies of app/ and tests/ + evidence; no .env, no .git) |
| 5 | diff_gate | only existing `app/**.py` files changed; no new/deleted files; no change to tests/ or evidence/; at most 60 changed lines / 20 kB; secret scan of the patch clean. Saved as `fix.patch` |
| 6 | test_gate | `uv run --frozen pytest -q` passes in the patched scratch copy (`test-gate.log`) |
| 7 | replay_before_restart | the same requests return non-5xx against the patched code (in-process, copied DB) |
| 8 | real_tree_unchanged_since_workspace | the real app/ files still equal the workspace baseline |
| 9 | restart_app | patched files copied into app/, `docker compose up --build -d --wait app` succeeds |
| 10 | replay_after_restart | the same requests return non-5xx from the live app (127.0.0.1 only) |
| 11 | grafana_rule_normal | Grafana shows the rule Normal for the route within 5 minutes |

A failure in 1-8 changes nothing in the real tree: the incident is escalated. A failure in
9-11 triggers a **rollback**: the original app/ files are restored from
`incidents/<ID>/baseline/` (no git), the app is rebuilt, and the incident is escalated.
Records: `gates.json`, `fix.patch`, `verification.json`, `summary.md`, `escalation.md`.

The agent never runs git, tests or the app, and nothing is ever committed automatically.

## After a successful automatic fix

The real tree now has an uncommitted change in app/ (same as `fix.patch`). Review it:

```bash
git diff app/
cat incident-response/incidents/<ID>/summary.md incident-response/incidents/<ID>/answer.md
```

Commit it yourself if it is right. Until app/ is clean again, fix mode refuses new runs.

## Escalations

Open `escalation.md` in the incident folder: it lists the failed precondition or gate and
the state of app/. Then read `answer.md` and `evidence/`, and check the dashboard. Useful:

```bash
tail -f incident-response/logs/responder.log
docker compose logs --since 15m app
curl -s http://localhost:3000/api/prometheus/grafana/api/v1/rules | jq '.data.groups[].rules[] | {name, state}'
```

## Manual revert

If a deployed automatic fix must be undone:

```bash
cp -r incident-response/incidents/<ID>/baseline/app/. app/   # original files at the time of the fix
docker compose up --build -d --wait app
git status --short app/                                       # should be clean again
```

(`git checkout -- app/` does the same if the fix was never committed.) If it was committed,
revert that commit and rebuild.

## Operating the responder

```bash
incident-response/start-responder.sh start|stop|status   # logs: incident-response/logs/responder.log
```

Stopping ends a running claude process and drops queued alerts. Grafana will not re-send
an alert that keeps firing for 12 h (`repeat_interval`), and the responder deduplicates on
fingerprint + startsAt, so an alert dropped by a restart is not retried automatically:
handle it as an escalation (or let it resolve and fire again).
