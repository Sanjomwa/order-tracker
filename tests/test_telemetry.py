import pytest
from fastapi.testclient import TestClient
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter, SimpleLogRecordProcessor
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from app import main, telemetry

ORDER_ROUTE = "/api/orders/{order_id}"
BOOM_ROUTE = "/__test__/boom"


class Signals:
    def __init__(self):
        self.spans = InMemorySpanExporter()
        self.metrics = InMemoryMetricReader()
        self.logs = InMemoryLogRecordExporter()

    def request_points(self):
        data = self.metrics.get_metrics_data()
        points = []
        for resource_metrics in data.resource_metrics if data else []:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    if metric.name == "http.server.request.duration":
                        points.extend(metric.data.data_points)
        return points

    def request_count(self, route, status_code):
        return sum(
            point.count
            for point in self.request_points()
            if point.attributes.get("http.route") == route
            and point.attributes.get("http.response.status_code") == status_code
        )

    def log_records(self):
        return [data.log_record for data in self.logs.get_finished_logs()]


@pytest.fixture
def signals(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "orders.db")
    captured = Signals()
    telemetry.configure(
        main.app,
        span_processors=[SimpleSpanProcessor(captured.spans)],
        metric_readers=[captured.metrics],
        log_processors=[SimpleLogRecordProcessor(captured.logs)],
    )
    yield captured
    telemetry.configure(main.app)


@pytest.fixture
def client(signals):
    with TestClient(main.app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def boom_route():
    def boom():
        raise RuntimeError("test-only failure")

    main.app.add_api_route(BOOM_ROUTE, boom, methods=["GET"])
    main.app.middleware_stack = None
    yield
    main.app.router.routes[:] = [r for r in main.app.router.routes if getattr(r, "path", None) != BOOM_ROUTE]
    main.app.middleware_stack = None


def test_lookup_records_route_and_status(client, signals):
    assert client.get("/api/orders/standard-1001").status_code == 200
    assert signals.request_count(ORDER_ROUTE, 200) == 1

    lookups = [r for r in signals.log_records() if r.attributes.get("order_id") == "standard-1001"]
    assert len(lookups) == 1
    assert lookups[0].severity_text == "INFO"
    assert lookups[0].attributes["http.response.status_code"] == 200
    assert lookups[0].trace_id != 0


def test_missing_order_records_404(client, signals):
    assert client.get("/api/orders/missing").status_code == 404
    assert signals.request_count(ORDER_ROUTE, 404) == 1
    assert signals.request_count(ORDER_ROUTE, 200) == 0


def test_healthz_is_not_instrumented(client, signals):
    assert client.get("/healthz").status_code == 200
    assert not [p for p in signals.request_points() if p.attributes.get("http.route") == "/healthz"]
    assert not signals.spans.get_finished_spans()


def test_excluded_paths_only_match_at_path_start(client, signals):
    # An order whose id looks like an excluded path is still a normal lookup.
    assert client.get("/api/orders/healthz").status_code == 404
    assert client.get("/api/orders/static").status_code == 404
    assert signals.request_count(ORDER_ROUTE, 404) == 2


def test_unhandled_exception_is_logged_and_marks_span(client, signals, boom_route):
    response = client.get(BOOM_ROUTE)
    assert response.status_code == 500
    assert signals.request_count(BOOM_ROUTE, 500) == 1

    server_spans = [s for s in signals.spans.get_finished_spans() if s.attributes.get("http.route") == BOOM_ROUTE]
    assert len(server_spans) == 1
    span = server_spans[0]
    assert span.status.status_code == StatusCode.ERROR
    assert any(event.name == "exception" for event in span.events)

    errors = [r for r in signals.log_records() if r.severity_text == "ERROR"]
    assert len(errors) == 1
    assert errors[0].trace_id == span.context.trace_id
    assert "RuntimeError" in errors[0].attributes.get("exception.stacktrace", "")
    assert errors[0].attributes["http.route"] == BOOM_ROUTE
