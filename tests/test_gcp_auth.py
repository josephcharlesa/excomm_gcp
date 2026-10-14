import json

import pytest

from exaudit.gcp.auth import credentials_from_wif


def test_wif_loader_rejects_service_account_private_key_json(tmp_path):
    config = tmp_path / "service-account.json"
    config.write_text(json.dumps({
        "type": "service_account",
        "private_key": "never-a-real-key",
        "client_email": "example@example.invalid",
    }), encoding="utf-8")

    with pytest.raises(ValueError, match="private-key JSON is not accepted"):
        credentials_from_wif(str(config))


def test_wif_loader_rejects_invalid_json(tmp_path):
    config = tmp_path / "invalid.json"
    config.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="valid JSON"):
        credentials_from_wif(str(config))
