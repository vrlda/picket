"""Watchtower SDK (stdlib only): exception capture and custom events.

Report exceptions (grouped by fingerprint) and structured application/
business events (e.g. "payment.request_failed") to a watchtower server;
rules turn them into incidents. Configure via env:

    WATCHTOWER_ENDPOINT     required, e.g. http://server:18788
    WATCHTOWER_TOKEN        required, bearer token
    WATCHTOWER_HOST_ID      default: socket hostname
    WATCHTOWER_SERVICE      default: app
    WATCHTOWER_ENVIRONMENT  default: prod
"""

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request


def _env(name, default=None):
    return os.environ.get(name, default)


class Client:
    def __init__(self, endpoint=None, token=None, host_id=None,
                 service=None, environment=None):
        self.endpoint = (endpoint or _env("WATCHTOWER_ENDPOINT", "")).rstrip("/")
        self.token = token or _env("WATCHTOWER_TOKEN", "")
        self.host_id = host_id or _env("WATCHTOWER_HOST_ID", socket.gethostname())
        self.service = service or _env("WATCHTOWER_SERVICE", "app")
        self.environment = environment or _env("WATCHTOWER_ENVIRONMENT", "prod")

    def capture(self, level, exception_type, message, frames=None):
        """frames: list of (file, line, function). Best-effort, one retry."""
        if not self.endpoint or not self.token:
            return False
        frames = frames or []
        body = json.dumps({
            "host_id": self.host_id,
            "service": self.service,
            "environment": self.environment,
            "exception": {
                "type": exception_type,
                "message": message,
                "level": level,
                "frames": [
                    {"file": f[0], "line": f[1], "function": f[2] if len(f) > 2 else ""}
                    for f in frames
                ],
            },
        }).encode("utf-8")
        return self._post("/v1/errors", body)

    def capture_event(self, kind, summary, severity="info", subject="",
                      attributes=None, measurements=None, id=None, ts=None,
                      source=None, environment=None):
        """Emit a custom event (POST /v1/events). `kind` is a dotted name
        like "payment.request_failed"; `attributes` are dimensions
        (merchant_id, endpoint, ...); `measurements` are numbers rules can
        compare. Best-effort, one retry; returns True when stored."""
        if not self.endpoint or not self.token:
            return False
        event = {
            "kind": kind,
            "summary": summary,
            "severity": severity,
            "source": source or self.service,
            "environment": environment or self.environment,
        }
        if subject:
            event["subject"] = subject
        if attributes:
            event["attributes"] = attributes
        if measurements:
            event["measurements"] = measurements
        if id:
            event["id"] = id
        if ts is not None:
            event["ts"] = int(ts)
        return self._post("/v1/events", json.dumps(event).encode("utf-8"))

    def _post(self, path, body):
        url = self.endpoint + path
        for attempt in (0, 1):
            try:
                req = urllib.request.Request(
                    url, data=body, method="POST",
                    headers={"Content-Type": "application/json",
                             "Authorization": "Bearer " + self.token})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return 200 <= resp.status < 300
            except urllib.error.HTTPError as e:
                if 400 <= e.code < 500:
                    return False  # rejected (invalid event / auth): don't retry
                if attempt == 0:
                    time.sleep(0.2)
            except (urllib.error.URLError, OSError, ValueError):
                if attempt == 0:
                    time.sleep(0.2)
        return False

    def capture_exception(self, level="error"):
        """Capture the currently-handled exception (sys.exc_info)."""
        exc_type, exc_value, exc_tb = sys.exc_info()
        if exc_type is None:
            return False
        frames = []
        tb = exc_tb
        while tb is not None:
            code = tb.tb_frame.f_code
            frames.append((code.co_filename, tb.tb_lineno, code.co_name))
            tb = tb.tb_next
        return self.capture(level, exc_type.__name__, str(exc_value), frames)
