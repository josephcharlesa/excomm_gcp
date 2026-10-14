# GCP Scanner Architecture (MVP)

## Authentication

Use Workload Identity Federation with short-lived credentials. Where needed, impersonate a customer-authorized service account. Never request or persist customer service-account private-key JSON files. Bind each audit ID to a trusted identity mapping; an audit ID by itself is not an authorization mechanism.

## IAM

Grant only the permissions needed for read-only inventory. Start from a least-privilege role set rather than assuming Project Viewer covers every service. Configure explicit permissions for Compute Engine, Cloud Storage, Cloud SQL, Recommender, and billing data. BigQuery billing export requires read access to the exported dataset in addition to relevant billing visibility.

## API mapping

| Area | API | MVP checks |
|---|---|---|
| Billing | BigQuery billing export | Daily costs, optional heuristic anomaly flag; gracefully report missing export |
| Compute | Compute Engine API | Stopped VMs for review, unattached disks, unused reserved external IPs |
| Storage | Cloud Storage JSON API | Empty-bucket review candidates, lifecycle policy review |
| Databases | Cloud SQL Admin API | Stopped instance review |
| Recommendations | Recommender API | Native optimization recommendations |

## Findings

Every finding includes category, severity, resource ID, current monthly cost, estimated monthly savings, and recommendation, with optional evidence, source, currency, and confidence. Costs and savings remain null unless a reliable pricing method is implemented; the scanner must not fabricate estimates.

## Limitations before production

- Add utilization metrics and pricing-backed calculations before labeling resources idle or quoting savings.
- Expand recommender locations and confirm supported recommender IDs for the target resource types.
- Add service-specific IAM permission tests and WIF trust-condition validation.
- Add mocked tests for pagination, API errors, malformed responses, and partial coverage.
- Validate billing export schema variations, credits, adjustments, currencies, and incomplete current-day data.
- Integrate this package with the existing audit CLI and report interface after confirming its contract.
- Run full CI and a controlled live GCP test project before production release.
