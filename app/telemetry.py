"""OpenTelemetry traces, metrics and logs for Order Tracker.

* Providers are built here and passed to the instrumentor explicitly; nothing is
  registered as the process-global provider, so ``configure`` can be called again
  (tests inject in-memory exporters) without OpenTelemetry's set-once warnings.
* Exporters come from the environment (``configure_from_env``):
  - console (stdout, so ``docker compose logs app`` shows them) unless
    ``OTEL_CONSOLE_EXPORT=false``;
  - OTLP over HTTP/protobuf only when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set.
* Secrets: no HTTP headers are captured (``http_capture_headers_*`` are left unset),
  request bodies are never read, and metric labels are fixed low-cardinality values
  (route template, method, status code), never order ids.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Sequence
from typing import Any

# Opt in to the stable HTTP semantic conventions (http.server.request.duration in
# seconds, http.route, http.response.status_code). This has to be set before the
# instrumentation packages are imported.
os.environ.setdefault("OTEL_SEMCONV_STABILITY_OPT_IN", "http")

from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler, LogRecordProcessor
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, ConsoleLogRecordExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    ConsoleMetricExporter,
    MetricReader,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

SERVICE_NAME = "order-tracker"
LOGGER = logging.getLogger("order_tracker.telemetry")

# Matched with re.search against the full request URL (scheme://host/path), so each
# pattern is anchored to the start of the path: /api/orders/healthz must still count.
# The container healthcheck (every 5s) and static assets are not worth a trace or a
# metric point each.
EXCLUDED_URLS = ",".join([r"^https?://[^/]+/healthz(\?.*)?$", r"^https?://[^/]+/static(/.*)?$"])

METRIC_EXPORT_INTERVAL_MS = 10_000

_OTEL_HANDLER_NAME = "order-tracker-otel"
_STDOUT_HANDLER_NAME = "order-tracker-stdout"


def build_resource() -> Resource:
    return Resource.create(
        {
            "service.name": SERVICE_NAME,
            "service.version": os.getenv("ORDER_TRACKER_VERSION", "dev"),
            "deployment.environment.name": os.getenv("DEPLOYMENT_ENVIRONMENT", "local"),
        }
    )


class _OtelLogHandler(LoggingHandler):
    """Forward records to the OTel logger provider, except the SDK's own records
    (which would feed back into export)."""

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith("opentelemetry"):
            return
        super().emit(record)


class _TraceContextFilter(logging.Filter):
    """Add trace_id/span_id of the active span (or "-") to every stdout record."""

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = trace.get_current_span().get_span_context()
        record.trace_id = format(ctx.trace_id, "032x") if ctx.is_valid else "-"
        record.span_id = format(ctx.span_id, "016x") if ctx.is_valid else "-"
        return True


class _State:
    tracer_provider: TracerProvider | None = None
    meter_provider: MeterProvider | None = None
    logger_provider: LoggerProvider | None = None


_state = _State()


def _install_log_handlers(logger_provider: LoggerProvider) -> None:
    # uvicorn's own loggers (uvicorn, uvicorn.access) do not propagate to the root
    # logger, so its access log keeps its own handler and is not duplicated here.
    root = logging.getLogger()
    root.handlers = [h for h in root.handlers if h.get_name() not in (_OTEL_HANDLER_NAME, _STDOUT_HANDLER_NAME)]

    otel_handler = _OtelLogHandler(level=logging.NOTSET, logger_provider=logger_provider)
    otel_handler.set_name(_OTEL_HANDLER_NAME)
    root.addHandler(otel_handler)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.set_name(_STDOUT_HANDLER_NAME)
    stdout_handler.addFilter(_TraceContextFilter())
    stdout_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s trace_id=%(trace_id)s span_id=%(span_id)s %(message)s")
    )
    root.addHandler(stdout_handler)

    logging.getLogger("order_tracker").setLevel(logging.INFO)


def configure(
    app: Any,
    *,
    span_processors: Sequence[SpanProcessor] = (),
    metric_readers: Sequence[MetricReader] = (),
    log_processors: Sequence[LogRecordProcessor] = (),
) -> None:
    """(Re)build providers and instrumentation. Safe to call repeatedly."""

    shutdown()
    resource = build_resource()

    tracer_provider = TracerProvider(resource=resource)
    for processor in span_processors:
        tracer_provider.add_span_processor(processor)
    meter_provider = MeterProvider(resource=resource, metric_readers=list(metric_readers))
    logger_provider = LoggerProvider(resource=resource)
    for log_processor in log_processors:
        logger_provider.add_log_record_processor(log_processor)

    # Uninstrument first: the instrumentor ignores a second instrument_app() call.
    if getattr(app, "_is_instrumented_by_opentelemetry", False):
        FastAPIInstrumentor.uninstrument_app(app)
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
        excluded_urls=EXCLUDED_URLS,
        exclude_spans=["receive", "send"],  # per-message ASGI spans are pure noise here
    )
    # uninstrument_app() eagerly builds the middleware stack, and Starlette keeps
    # using a built stack; force a rebuild so the (re)installed middleware is in it.
    app.middleware_stack = None

    _install_log_handlers(logger_provider)

    _state.tracer_provider = tracer_provider
    _state.meter_provider = meter_provider
    _state.logger_provider = logger_provider


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name, "").strip().lower()
    if not value:
        return default
    return value not in ("0", "false", "no", "off")


def configure_from_env(app: Any) -> None:
    """Production entry point: console export by default, OTLP when an endpoint is set."""

    span_processors: list[SpanProcessor] = []
    metric_readers: list[MetricReader] = []
    log_processors: list[LogRecordProcessor] = []

    if _env_flag("OTEL_CONSOLE_EXPORT", True):
        span_processors.append(BatchSpanProcessor(ConsoleSpanExporter()))
        metric_readers.append(
            PeriodicExportingMetricReader(ConsoleMetricExporter(), export_interval_millis=METRIC_EXPORT_INTERVAL_MS)
        )
        log_processors.append(BatchLogRecordProcessor(ConsoleLogRecordExporter()))

    otlp = bool(os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip())
    if otlp:
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        span_processors.append(BatchSpanProcessor(OTLPSpanExporter()))
        metric_readers.append(
            PeriodicExportingMetricReader(OTLPMetricExporter(), export_interval_millis=METRIC_EXPORT_INTERVAL_MS)
        )
        log_processors.append(BatchLogRecordProcessor(OTLPLogExporter()))

    configure(app, span_processors=span_processors, metric_readers=metric_readers, log_processors=log_processors)
    if otlp:
        LOGGER.info("OTLP export enabled")


def shutdown() -> None:
    """Flush and stop the current providers (used before reconfiguring)."""

    for provider in (_state.tracer_provider, _state.meter_provider, _state.logger_provider):
        if provider is not None:
            try:
                provider.shutdown()
            except Exception:  # pragma: no cover - best effort
                pass
    _state.tracer_provider = _state.meter_provider = _state.logger_provider = None
