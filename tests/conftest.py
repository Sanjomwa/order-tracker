import os

# Keep console exporters (and their background export threads) out of the test
# run; tests that inspect telemetry install in-memory exporters themselves.
os.environ["OTEL_CONSOLE_EXPORT"] = "false"
os.environ.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)
