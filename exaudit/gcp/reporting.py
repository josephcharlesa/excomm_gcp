"""Provider-specific JSON, CSV and HTML output for GCP scans.

This renderer deliberately does not generate cleanup scripts: GCP recommendations
must never be passed to the existing AWS-only cleanup.sh workflow.
"""
from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from typing import Any


def to_json(report: Any) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str)


def _csv_cell(value: Any) -> Any:
    """Neutralize spreadsheet formulas in resource-controlled text fields."""
    if value is None:
        return ""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\\t", "\\r"):
        return "'" + value
    return value


def to_csv(report: Any) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow([
        "category", "severity", "resource_id", "current_monthly_cost",
        "estimated_monthly_savings", "currency", "confidence", "recommendation",
        "evidence", "source",
    ])
    for finding in report.findings:
        writer.writerow([_csv_cell(value) for value in (
            finding.category, finding.severity, finding.resource_id,
            finding.current_monthly_cost, finding.estimated_monthly_savings,
            finding.currency, finding.confidence, finding.recommendation,
            finding.evidence, finding.source,
        )])
    return output.getvalue()


def to_html(report: Any) -> str:
    esc = lambda value: html.escape("" if value is None else str(value), quote=True)
    finding_rows = "".join(
        "<tr>"
        f"<td>{esc(f.category)}</td><td>{esc(f.severity)}</td>"
        f"<td><code>{esc(f.resource_id)}</code></td>"
        f"<td>{esc(f.current_monthly_cost)}</td>"
        f"<td>{esc(f.estimated_monthly_savings)}</td>"
        f"<td>{esc(f.recommendation)}</td><td>{esc(f.evidence)}</td>"
        "</tr>"
        for f in report.findings
    ) or '<tr><td colspan="7">No findings were returned.</td></tr>'
    note_rows = "".join(
        f"<li><b>{esc(n.get('check'))}:</b> {esc(n.get('message'))}</li>"
        for n in report.notes
    ) or "<li>No coverage notes.</li>"
    billing = report.billing or {}
    billing_text = (
        f"Available: {esc(billing.get('available'))}; "
        f"currency: {esc(billing.get('currency'))}; "
        f"reported 30-day cost: {esc(billing.get('monthly_cost'))}"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>GCP Cloud Audit {esc(report.audit_id)}</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#17202a}}
h1,h2{{line-height:1.2}}.meta{{color:#4b5563}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #d1d5db;padding:.65rem;text-align:left;vertical-align:top}}
th{{background:#f3f4f6}}code{{overflow-wrap:anywhere}}.note{{background:#f9fafb;padding:1rem}}
</style></head><body>
<h1>Google Cloud Infrastructure Audit</h1>
<p class="meta">Project: <b>{esc(report.project_id)}</b> · Audit: <b>{esc(report.audit_id)}</b></p>
<h2>Billing</h2><p>{billing_text}</p>
<h2>Findings ({len(report.findings)})</h2>
<table><thead><tr><th>Category</th><th>Severity</th><th>Resource</th>
<th>Current monthly cost</th><th>Estimated monthly savings</th>
<th>Recommendation</th><th>Evidence</th></tr></thead>
<tbody>{finding_rows}</tbody></table>
<h2>Coverage notes</h2><ul class="note">{note_rows}</ul>
<p class="meta">Read-only scan. Costs and savings remain unavailable unless supported by reliable billing or pricing data. This report does not execute changes.</p>
</body></html>"""


def write_bundle(report: Any, directory: str | Path) -> Path:
    """Write GCP-only report artifacts. Never creates an AWS cleanup script."""
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=True)
    (output / "findings.json").write_text(to_json(report), encoding="utf-8")
    (output / "findings.csv").write_text(to_csv(report), encoding="utf-8", newline="")
    (output / "report.html").write_text(to_html(report), encoding="utf-8")
    return output
