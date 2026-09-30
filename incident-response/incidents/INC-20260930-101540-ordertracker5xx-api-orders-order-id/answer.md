**Affected:** `GET /api/orders/{order_id}` returned a 500 for an express order. `alert.json` shows 1 5xx on that route in the last minute. The Loki error line is at 2026-09-30T10:14:43Z (`logs-warn-error.json`). The Tempo trace's span (`tempo-trace-1.json`) shows `url.path=/api/orders/express-1002` with status 500, and I saw no other 5xx in the evidence. I did not check `metrics-5xx-by-route.json` or `metrics-request-totals.json`, so the total 5xx count and the start time are not confirmed from the metrics.

**Cause:**
- `logs-warn-error.json` and the Tempo exception event both record `ValueError: day is out of range for month`.
- The trace identifies the failing order as `express-1002`.
- `order_detail()` in `app/main.py` computed the estimated delivery with `placed_at.replace(day=placed_at.day + 2)`. That fails when the day plus 2 goes past the end of the month.
- `init_db()` seeds `express-1002` with `created_at` set to the last day of the previous month. The seed is what makes this order fail, but the bug applies to any express order placed on the 29th or later.
- The stack trace in both files is truncated, so I did not see the exact failing line in the evidence. The code inspection and the error message together are what point to that line.

**Change:** in `order_detail()` in `app/main.py`, I replaced `placed_at.replace(day=placed_at.day + 2)` with `placed_at + timedelta(days=2)`. `timedelta` was already imported. Nothing else changed. Dates that don't cross a month boundary give the same result as before. Month-end dates now roll over into the next month.

**What the orchestrator should see:**
- `GET /api/orders/express-1002` should return 200 with an `estimated_delivery` two days after the previous month's last day, which is the 1st or 2nd of the current month.
- Standard orders should behave as before.
- The test suite and the replay of the failing request should show no new 500s.

I have not run or verified any of this, and nothing is deployed.

Fixed the month-end date overflow in `order_detail()` by using `timedelta(days=2)`, which should stop the 500 on `express-1002`, pending your verification.
