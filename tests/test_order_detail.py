import pytest
from fastapi.testclient import TestClient

from app import main


# Regression tests for the express delivery estimate (INC-20260930-101540: express-1002,
# placed on the last day of a month, returned 500). Orders are inserted with fixed
# created_at values so the month and year boundaries do not depend on today's date.


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "orders.db")
    # A 500 should fail the assertion on status_code, not raise inside the test.
    with TestClient(main.app, raise_server_exceptions=False) as test_client:
        yield test_client


def insert_order(order_id, priority, created_at):
    with main.connect() as db:
        db.execute(
            "INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?)",
            (order_id, "Test", "Item", priority, "received", created_at),
        )


@pytest.mark.parametrize(
    ("created_at", "expected"),
    [
        pytest.param("2026-01-31T09:00:00+00:00", "2026-02-02", id="last-day-of-31-day-month"),
        pytest.param("2026-04-30T09:00:00+00:00", "2026-05-02", id="30th-of-30-day-month"),
        pytest.param("2025-02-28T09:00:00+00:00", "2025-03-02", id="28-feb-non-leap-year"),
        pytest.param("2024-02-29T09:00:00+00:00", "2024-03-02", id="29-feb-leap-year"),
        pytest.param("2026-12-31T09:00:00+00:00", "2027-01-02", id="31-dec-crosses-year"),
        pytest.param("2026-09-15T09:00:00+00:00", "2026-09-17", id="mid-month"),
    ],
)
def test_express_estimated_delivery_is_two_days_later(client, created_at, expected):
    insert_order("express-test", "express", created_at)
    response = client.get("/api/orders/express-test")
    assert response.status_code == 200
    assert response.json()["estimated_delivery"] == expected


@pytest.mark.parametrize("created_at", ["2026-01-31T09:00:00+00:00", "2026-09-15T09:00:00+00:00"])
def test_standard_order_has_no_estimated_delivery(client, created_at):
    insert_order("standard-test", "standard", created_at)
    response = client.get("/api/orders/standard-test")
    assert response.status_code == 200
    assert "estimated_delivery" not in response.json()
