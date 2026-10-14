from pathlib import Path
from types import SimpleNamespace

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
    import csv
    header = next(csv.reader(output.splitlines()))
    row = next(csv.reader(output.splitlines()[1:]))
    assert row[header.index("resource_id")] == 'bucket-<script>alert("x")</script>'
    assert "None" not in output


def test_gcp_csv_neutralizes_spreadsheet_formulas():
    import csv
    report = make_report()
    report.findings[0].resource_id = '=HYPERLINK("https://example.invalid")'
    row = next(csv.reader(to_csv(report).splitlines()[1:]))
    assert row[2].startswith("'=HYPERLINK(")


def test_gcp_bundle_never_generates_aws_cleanup_scripts(tmp_path: Path):
    output = write_bundle(make_report(), tmp_path / "delivery")
    assert (output / "findings.json").exists()
    assert (output / "findings.csv").exists()
    assert (output / "report.html").exists()
    assert not (output / "cleanup.sh").exists()
    assert not (output / "remove-access.sh").exists()
