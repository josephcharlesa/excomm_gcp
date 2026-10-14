"""Optional BigQuery billing export reader; never invents missing costs."""
from __future__ import annotations

from datetime import date, timedelta
import re
from typing import Any


class BillingExport:
    def __init__(self, client: Any = None, table: str = ""):
        self.client, self.table = client, table

    def monthly_cost(self, *, end_date: date | None = None, lookback_days: int = 30) -> dict[str, Any]:
        if not isinstance(lookback_days, int) or not 1 <= lookback_days <= 366:
            raise ValueError("lookback_days must be an integer from 1 to 366")
        end = end_date or date.today()
        start = end - timedelta(days=lookback_days)
        period = {
            "period_start": start.isoformat(),
            "period_end_exclusive": end.isoformat(),
            "lookback_days": lookback_days,
        }
        if self.client is None or not self.table:
            return {
                "available": False, "currency": None, "monthly_cost": None,
                "daily_costs": [], "anomalies": [],
                "message": "BigQuery billing export is not configured; cost totals are unavailable.",
                **period,
            }
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+", self.table):
            raise ValueError("billing table must be project.dataset.table")
        try:
            from google.cloud import bigquery
        except ImportError as exc:
            raise RuntimeError("Install GCP dependencies with: pip install '.[gcp]'") from exc

        # Fill dates with zero spend so missing usage days do not distort the anomaly baseline.
        # The table identifier is validated above; dates are bound query parameters.
        sql = f"""WITH daily AS (
  SELECT DATE(usage_start_time) AS usage_date, currency,
    SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS net_cost
  FROM `{self.table}`
  WHERE DATE(usage_start_time) >= @start_date AND DATE(usage_start_time) < @end_date
  GROUP BY usage_date, currency
), currencies AS (
  SELECT DISTINCT currency FROM daily
), dates AS (
  SELECT day AS usage_date
  FROM UNNEST(GENERATE_DATE_ARRAY(@start_date, DATE_SUB(@end_date, INTERVAL 1 DAY))) AS day
)
SELECT dates.usage_date, currencies.currency, IFNULL(daily.net_cost, 0) AS net_cost
FROM dates CROSS JOIN currencies
LEFT JOIN daily USING (usage_date, currency)
ORDER BY dates.usage_date, currencies.currency"""
        config = bigquery.QueryJobConfig(query_parameters=[
            bigquery.ScalarQueryParameter("start_date", "DATE", start),
            bigquery.ScalarQueryParameter("end_date", "DATE", end),
        ])
        rows = list(self.client.query(sql, job_config=config).result())
        if not rows:
            return {
                "available": True, "currency": None, "monthly_cost": 0.0,
                "daily_costs": [], "anomalies": [],
                "message": "No billing rows in the selected window.",
                **period,
            }
        currencies = {str(row.currency) for row in rows}
        if len(currencies) != 1:
            return {
                "available": True, "currency": None, "monthly_cost": None,
                "daily_costs": [], "anomalies": [],
                "message": "Multiple currencies found; totals were not combined.",
                **period,
            }
        daily: dict[str, float] = {}
        for row in rows:
            day = row.usage_date.isoformat() if hasattr(row.usage_date, "isoformat") else str(row.usage_date)
            daily[day] = daily.get(day, 0.0) + float(row.net_cost or 0)
        daily_costs = [{"date": day, "cost": round(cost, 2)} for day, cost in sorted(daily.items())]
        vals = [x["cost"] for x in daily_costs]
        anomalies = []
        if len(vals) >= 14:
            recent = vals[-7:]
            baseline = vals[-28:-7] if len(vals) >= 28 else vals[:-7]
            base_avg = sum(baseline) / len(baseline) if baseline else 0.0
            recent_avg = sum(recent) / len(recent)
            if base_avg > 0 and recent_avg > base_avg * 1.5 and recent_avg - base_avg >= 10:
                anomalies.append({
                    "type": "daily_spend_increase", "severity": "medium",
                    "baseline_daily_average": round(base_avg, 2),
                    "recent_daily_average": round(recent_avg, 2),
                    "increase_percent": round((recent_avg / base_avg - 1) * 100, 1),
                })
        return {
            "available": True, "currency": str(rows[0].currency),
            "monthly_cost": round(sum(vals), 2), "daily_costs": daily_costs,
            "anomalies": anomalies,
            "message": "Billing-export costs analyzed; anomaly signals are heuristic.",
            **period,
        }
