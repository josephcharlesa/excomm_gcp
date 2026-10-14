# eXommerce GCP Cloud Audit Scanner

A read-only Google Cloud inventory and cost-audit module intended to align with the eXommerce AWS scanner's findings and reporting conventions.

## MVP scope

- Workload Identity Federation and optional service-account impersonation using short-lived credentials.
- Compute Engine inventory checks (stopped VMs, unattached persistent disks, unused reserved external IPs).
- Cloud Storage bucket lifecycle and empty-bucket review signals.
- Cloud SQL stopped-instance review signals.
- Optional BigQuery billing-export analysis with explicit data-availability notes.
- Recommender API integration for native optimization recommendations.
- Normalized findings with category, severity, resource ID, current monthly cost, estimated monthly savings, and recommendation.

## Security

- Never store customer service-account private-key JSON files.
- Use least-privilege, read-only IAM roles and audit-specific identity restrictions.
- Keep tokens short-lived and never log tokens or credential material.
- Treat findings as recommendations only; the scanner does not modify customer resources.

## Validation status

- GitHub Actions unit tests pass on Python 3.10, 3.11, and 3.12.
- Tests use mocked Google API clients and do not access a live GCP project.
- This is an MVP, not production-ready: WIF trust/IAM setup, billing-export schema variations, recommendation coverage, and integration with the existing AWS CLI/report pipeline still require validation.

## Development

Install development dependencies with `python -m pip install -e '.[dev]'` and run `python -m pytest -q`.
Install GCP runtime dependencies as well with `python -m pip install -e '.[dev,gcp]'`.
