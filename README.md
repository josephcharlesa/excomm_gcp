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

## Status

Initial repository setup. The MVP source, mocked tests, and architecture notes are to be added and validated before production use. Live GCP validation is required before calling this production-ready.

## Development

Install the package with the `gcp` optional dependencies and run the test suite with pytest once the implementation and tests are committed.
