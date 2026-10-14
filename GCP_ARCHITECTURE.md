# GCP Scanner Architecture (MVP)

## Authentication

Use Workload Identity Federation with short-lived credentials. The authentication helper accepts only JSON configs whose `type` is `external_account`; it rejects service-account private-key JSON. Where needed, impersonate a customer-authorized service account. The external-account config must be deployment-managed and point at a trusted provider with narrow attribute conditions.

Bind each audit ID to a trusted identity mapping; an audit ID by itself is not an authorization mechanism. A hosted multi-tenant service must map audit references to authorized project IDs server-side rather than trusting a caller-supplied project ID.

## IAM

Grant only the permissions needed for read-only inventory. Start from a least-privilege role set rather than assuming Project Viewer covers every service. Configure explicit permissions for Compute Engine, Cloud Storage, Cloud SQL, Recommender, and billing data. BigQuery billing export requires read access to the exported dataset in addition to relevant billing visibility.

## API mapping

| Area | API | MVP checks |
|---|---|---|
| Billing | BigQuery billing export | Daily costs, zero-filled daily series, heuristic spend-increase signal; gracefully report missing export |
| Compute | Compute Engine API | Stopped VMs for review, unattached disks, unused reserved external IPs |
| Storage | Cloud Storage JSON API | Empty-bucket review candidates, lifecycle policy review |
| Databases | Cloud SQL Admin API | Stopped instance review |
| Recommendations | Recommender API | Native optimization recommendations; raw cost projections are not treated as monthly savings until their period and currency are normalized |

## Findings and reporting

Every finding includes category, severity, resource ID, current monthly cost, estimated monthly savings, and recommendation, with optional evidence, source, currency, and confidence. Costs and savings remain null unless supported by a reliable pricing method; the scanner must not fabricate estimates. The GCP renderer escapes HTML output and neutralizes spreadsheet formulas in CSV cells. It intentionally does not create AWS `cleanup.sh` or `remove-access.sh` scripts.

## Validation status

- GitHub Actions unit tests run on Python 3.10, 3.11, and 3.12.
- Mocked tests cover pagination, partial API failures, WIF key-file rejection, report escaping, CSV formula neutralization, and billing query windows.
- Tests do not access a live GCP project.

## Limitations before production

- Add utilization metrics and pricing-backed calculations before labeling resources idle or quoting savings.
- Expand recommender locations and confirm supported recommender IDs for the target resource types.
- Configure and independently verify WIF trust conditions and least-privilege IAM in a dedicated test project.
- Validate billing export schema variations, adjustments, currencies, and incomplete current-day data.
- Integrate the GCP package with the existing AWS CLI/report workflow using a separate GCP command and GCP-specific report bundle. Never route GCP findings into the AWS cleanup script.
- Run a controlled live GCP test project before production release.
