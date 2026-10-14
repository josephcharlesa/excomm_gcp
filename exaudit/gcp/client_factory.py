"""Google API client factory with dependency injection for tests."""
from __future__ import annotations
import threading
from typing import Any

DISCOVERY = {
    "compute": ("compute", "v1"),
    "sqladmin": ("sqladmin", "v1beta4"),
    "storage": ("storage", "v1"),
    "recommender": ("recommender", "v1"),
}

class GcpClients:
    def __init__(
        self, credentials: Any = None, *, project_id: str = "",
        overrides: dict[str, Any] | None = None,
    ):
        self.credentials = credentials
        self.project_id = project_id
        self.overrides = overrides or {}
        self._clients: dict[str, Any] = {}
        self._lock = threading.Lock()

    def client(self, service: str) -> Any:
        if service in self.overrides:
            value = self.overrides[service]
            return value() if callable(value) and not hasattr(value, "execute") else value
        with self._lock:
            if service not in self._clients:
                if service not in DISCOVERY:
                    raise ValueError(f"unsupported GCP API: {service}")
                try:
                    from googleapiclient.discovery import build
                except ImportError as exc:
                    raise RuntimeError("Install GCP dependencies with: pip install '.[gcp]'") from exc
                api, version = DISCOVERY[service]
                self._clients[service] = build(
                    api, version, credentials=self.credentials, cache_discovery=False
                )
            return self._clients[service]
