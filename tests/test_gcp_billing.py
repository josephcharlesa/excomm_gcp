from datetime import date, timedelta
from types import ModuleType, SimpleNamespace
import sys

import pytest

from exaudit.gcp.billing import BillingExport


def test_billing_rejects_invalid_lookback_even_without_client():
    with pytest.raises(ValueError, match="lookback_days"):
        BillingExport().monthly_cost(lookback_days=0)


def test_billing_query_fills_missing_dates_for_anomaly_baseline(monkeypatch):
    bigquery = ModuleType("google.cloud.bigquery")
    bigquery.QueryJobConfig = lambda query_parameters: SimpleNamespace(query_parameters=query_parameters)
    bigquery.ScalarQueryParameter = lambda name, kind, value: (name, kind, value)
    google = ModuleType("google")
    cloud = ModuleType("google.cloud")
    cloud.bigquery = bigquery
    google.cloud = cloud
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.cloud", cloud)
    monkeypatch.setitem(sys.modules, "google.cloud.bigquery", bigquery)

    class Job:
        def result(self):
            return [SimpleNamespace(usage_date=date(2026, 10, 13), currency="USD", net_cost=5)]

    class Client:
        sql = ""
        config = None

        def query(self, sql, job_config):
            self.sql, self.config = sql, job_config
            return Job()

    client = Client()
    result = BillingExport(client, "demo-project.billing_export.gcp_costs").monthly_cost(
        end_date=date(2026, 10, 14), lookback_days=30
    )

    assert "GENERATE_DATE_ARRAY" in client.sql
    assert result["period_start"] == (date(2026, 10, 14) - timedelta(days=30)).isoformat()
    assert result["period_end_exclusive"] == "2026-10-14"
    assert result["lookback_days"] == 30
