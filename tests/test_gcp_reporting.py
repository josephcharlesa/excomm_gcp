from pathlib import Path
from types import SimpleNamespace
import csv

import pytest

from exaudit.gcp.findings import FindingRecord
from exaudit.gcp.reporting import to_csv, to_html, write_bundle


def make_report():
    finding = FindingRecord(
        category="storage",
        severity="low",
        resource_id='bucket-<script>alert("x")</script>',
        current_monthly_cost=None,
        estimated_monthly_savings=None,
        recommendation="Review & confirm",
        evidence="No cost estimate",
    )
    return SimpleNamespace(
        project_id="demo-project",
        audit_id="audit-123",
        findings=[finding],
        notes=[{"check": "storage", "message": "permission denied <unsafe>"}],
        billing={"available": False, "currency": None, "monthly_cost": None},
        to_dict=lambda: {
            "provider": "gcp",
            "project_id": "demo-project",
            "audit_id": "audit-123",
            "findings": [finding.to_dict()],
            "notes": [{"check": "storage", "message": "permission denied <unsafe>"}],
            "billing": {"available": False, "currency": None, "monthly_cost": None},
        },
    )


def test_gcp_html_escapes_resource_ids_and_notes():
    output = to_html(make_report())
    assert "<script>" not in output
    assert "&lt;script&gt;" in output
    assert "permission denied &lt;unsafe&gt;" in output


def test_gcp_csv_includes_null_costs_as_empty_cells():
    output = to_csv(make_report())
    assert "resource_id" in output
    header = next(csv.reader(output.splitlines()))
    row = next(csv.reader(output.splitlines()[1:]))
    assert row[header.index("resource_id")] == 'bucket-<script>alert("x")</script>'
    assert "None" not in output


@pytest.mark.parametrize("payload", [
    '=HYPERLINK("https://example.invalid")',
    '+1+1',
    '-2+3',
    '@SUM(A1:A2)',
    '\t=1+1',
    '\r=1+1',
    '  =1+1',
    '\n@SUM(A1:A2)',
])
def test_gcp_csv_neutralizes_spreadsheet_formula_prefixes(payload):
    report = make_report()
    report.findings[0].resource_id = payload
    row = next(csv.reader(to_csv(report).splitlines()[1:]))
    assert row[2].startswith("'")


def test_gcp_bundle_never_generates_aws_cleanup_scripts(tmp_path: Path):
    output = write_bundle(make_report(), tmp_path / "delivery")
    assert (output / "findings.json").exists()
    assert (output / "findings.csv").exists()
    assert (output / "report.html").exists()
    assert not (output / "cleanup.sh").exists()
    assert not (output / "remove-access.sh").exists()
