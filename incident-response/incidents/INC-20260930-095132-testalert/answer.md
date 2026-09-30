**Conclusion: this is a Grafana "Notification test" alert, not an application incident.**

**What the alert is**
- `alert.json` has `alertname: TestAlert`, `grafana_folder: "Test Folder"` and `annotations.summary: "Notification test"`.
- Its `valueString` refers to `go_threads` from `job=grafana`. That is Grafana's own metric, not an Order Tracker one.
- `window.json` shows no route in the alert, so the evidence covers all routes.

**What is affected**
- Nothing in the app shows a 5xx problem.
- `metrics-5xx-by-route.json` has an empty result.
- `logs-warn-error.json` has 0 lines and `tempo-error-traces-search.json` has 0 traces.
- `docker-compose-ps.json` shows all services running. The app has been up 55 minutes and reports healthy.
- `metrics-request-totals.json` shows only 5 requests since start that were not 2xx. All 5 were `GET /api/orders/{order_id}` returning 404.
- `metrics-requests-by-route-status.json` shows those 404s happened in the first few minutes, roughly 09:11–09:16 UTC (timestamps 1790759042–1790759252). Every value after that is 0. That pattern looks like clients asking for order IDs that don't exist, not a fault. The evidence doesn't say who sent them or why.
- Grafana was restarted recently (`docker-compose-ps.json`: "Up 36 seconds"). That fits someone reconfiguring alerting and pressing "test" on the contact point. `git-state.json` shows uncommitted alerting provisioning files, which supports this. It is an inference, not something the evidence proves.

**Cause**
- There is no service fault to explain. The only trigger is the test notification.

**Next steps**
- **On-call or the alerting owner:** Treat this as a successful end-to-end test of the Grafana → responder path. Close the incident.
- **Optional:** If the 5 × 404s matter, check where the requests came from. The evidence has no client or caller data to tell us.
- **Nothing else:** No action is needed on the app. I have changed and run nothing.

This was a Grafana test notification with no evidence of any Order Tracker fault: 0 5xx responses, 0 error logs, 0 error traces and healthy services.
