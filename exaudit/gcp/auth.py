"""Keyless GCP authentication using external-account WIF credentials."""
from __future__ import annotations
import json
import re
from typing import Any


def validate_audit_id(audit_id: str) -> str:
    """Validate an audit identifier before using it in tenant mapping."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", audit_id or ""):
        raise ValueError("audit_id must be 3-128 safe ASCII characters")
    return audit_id


def audit_attribute(audit_id: str) -> str:
    """Compatibility alias for the audit-reference validator."""
    return validate_audit_id(audit_id)


def credentials_from_wif(
    config_path: str,
    *,
    scopes: list[str] | None = None,
    target_service_account: str | None = None,
) -> Any:
    """Load only external-account WIF config and optionally impersonate a service account.

    The config must be deployment-managed and point at a trusted provider. This helper
    explicitly rejects service-account key JSON so a private key cannot be used by mistake.
    """
    try:
        with open(config_path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("WIF config must be a readable, valid JSON file") from exc
    if not isinstance(config, dict) or config.get("type") != "external_account":
        raise ValueError(
            "credentials file must be a Workload Identity Federation external-account config; "
            "service-account private-key JSON is not accepted"
        )

    try:
        import google.auth
        from google.auth import impersonated_credentials
    except ImportError as exc:
        raise RuntimeError("Install GCP dependencies with: pip install '.[gcp]'") from exc

    requested_scopes = scopes or [
        "https://www.googleapis.com/auth/cloud-platform.read-only"
    ]
    source, _ = google.auth.load_credentials_from_file(
        config_path, scopes=requested_scopes
    )
    if not target_service_account:
        return source
    return impersonated_credentials.Credentials(
        source_credentials=source,
        target_principal=target_service_account,
        target_scopes=requested_scopes,
        lifetime=3600,
    )
