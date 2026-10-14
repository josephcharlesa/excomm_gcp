"""Read-only inventory checks for Compute Engine, Storage, Cloud SQL and Recommender."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from .billing import BillingExport
from .client_factory import GcpClients
from .findings import FindingRecord
from .auth import validate_audit_id

@dataclass
class ScanConfig:
    project_id: str
    audit_id: str
    billing_table: str = ""
    billing_client: Any = None
    recommender_locations: tuple[str, ...] = ("global",)

@dataclass
class ScanReport:
    project_id: str
    audit_id: str
    findings: list[FindingRecord] = field(default_factory=list)
    notes: list[dict[str, str]] = field(default_factory=list)
    billing: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"provider": "gcp", "project_id": self.project_id, "audit_id": self.audit_id,
                "findings": [f.to_dict() for f in self.findings], "notes": self.notes, "billing": self.billing}

class GcpScanner:
    def __init__(self, clients: GcpClients, config: ScanConfig):
        if not config.project_id:
            raise ValueError("project_id is required")
        validate_audit_id(config.audit_id)
        self.clients, self.config = clients, config
        self.report = ScanReport(config.project_id, config.audit_id)

    @staticmethod
    def _execute(request: Any) -> dict:
        return request.execute() if hasattr(request, "execute") else request

    def _note(self, check: str, message: str, level: str = "warning") -> None:
        self.report.notes.append({"check": check, "message": message, "level": level})

    def _finding(self, **kwargs: Any) -> None:
        self.report.findings.append(FindingRecord(**kwargs))

    def scan_billing(self) -> None:
        try:
            self.report.billing = BillingExport(self.config.billing_client, self.config.billing_table).monthly_cost()
            if not self.report.billing.get("available"):
                self._note("billing", self.report.billing.get("message", "Billing data unavailable."), "info")
        except Exception as exc:
            self._note("billing", f"Billing analysis unavailable: {type(exc).__name__}: {exc}")

    def scan_compute(self) -> None:
        api = self.clients.client("compute")
        for resource, collection, check in (("instances", "instances", "compute"),
                                             ("disks", "disks", "compute_disks"),
                                             ("addresses", "addresses", "external_ips")):
            token = None
            try:
                while True:
                    response = self._execute(getattr(api, resource)().aggregatedList(
                        project=self.config.project_id, pageToken=token))
                    for scope in response.get("items", {}).values():
                        for item in scope.get(collection, []):
                            rid = item.get("selfLink", item.get("name", "unknown"))
                            if resource == "instances" and item.get("status") == "TERMINATED":
                                self._finding(category="compute", severity="low", resource_id=rid,
                                    current_monthly_cost=None, estimated_monthly_savings=None,
                                    recommendation="Review the stopped VM and confirm whether it is still required.",
                                    evidence="Stopped VM detected; savings are not inferred without pricing and utilization data.")
                            elif resource == "disks" and not item.get("users"):
                                self._finding(category="storage", severity="medium", resource_id=rid,
                                    current_monthly_cost=None, estimated_monthly_savings=None,
                                    recommendation="Verify retention requirements, then snapshot or delete this unattached disk if unnecessary.",
                                    evidence="No attached VM was listed; cost depends on disk type, size and region.")
                            elif resource == "addresses" and item.get("status") == "RESERVED" and not item.get("users"):
                                self._finding(category="network", severity="low", resource_id=rid,
                                    current_monthly_cost=None, estimated_monthly_savings=None,
                                    recommendation="Confirm this reserved external IP is unused and release it if unnecessary.",
                                    evidence="Reserved address has no associated users; applicable charges vary.")
                    token = response.get("nextPageToken")
                    if not token: break
            except Exception as exc:
                self._note(check, f"Inventory unavailable: {type(exc).__name__}: {exc}")

    def scan_storage(self) -> None:
        try:
            api = self.clients.client("storage")
            token = None
            while True:
                response = self._execute(api.buckets().list(project=self.config.project_id, pageToken=token))
                for bucket in response.get("items", []):
                    name = bucket.get("name", "unknown")
                    rid = bucket.get("selfLink", name)
                    if not bucket.get("lifecycle", {}).get("rule", []):
                        self._finding(category="storage", severity="low", resource_id=rid,
                            current_monthly_cost=None, estimated_monthly_savings=None,
                            recommendation="Review object age, access patterns and retention requirements; configure lifecycle rules where useful.",
                            evidence="No lifecycle rules returned. This is a policy review, not proof the bucket is idle.")
                    try:
                        objects = self._execute(api.objects().list(bucket=name, maxResults=1))
                        if not objects.get("items"):
                            self._finding(category="storage", severity="low", resource_id=rid,
                                current_monthly_cost=None, estimated_monthly_savings=None,
                                recommendation="Confirm this bucket is intentionally empty and not used by an application before deleting it.",
                                evidence="First-page object listing returned no objects; verify permissions, versioning and soft-delete settings.")
                    except Exception as exc:
                        self._note("storage_objects", f"Object listing for {name} unavailable: {type(exc).__name__}: {exc}", "info")
                token = response.get("nextPageToken")
                if not token: break
        except Exception as exc:
            self._note("storage", f"Cloud Storage inventory unavailable: {type(exc).__name__}: {exc}")

    def scan_cloud_sql(self) -> None:
        try:
            api = self.clients.client("sqladmin")
            token = None
            while True:
                response = self._execute(api.instances().list(project=self.config.project_id, pageToken=token))
                for db in response.get("items", []):
                    if db.get("state") == "STOPPED":
                        self._finding(category="database", severity="low",
                            resource_id=db.get("selfLink", db.get("name", "unknown")),
                            current_monthly_cost=None, estimated_monthly_savings=None,
                            recommendation="Review the stopped Cloud SQL instance and its storage, backup and availability requirements.",
                            evidence="Stopped instances can still incur storage and backup charges.")
                token = response.get("nextPageToken")
                if not token: break
        except Exception as exc:
            self._note("cloud_sql", f"Cloud SQL inventory unavailable: {type(exc).__name__}: {exc}")

    def scan_recommender(self) -> None:
        recommender_ids = ("google.compute.instance.MachineTypeRecommender",
                           "google.compute.disk.IdleResourceRecommender",
                           "google.cloudsql.instance.MachineTypeRecommender")
        try:
            api = self.clients.client("recommender")
            for location in self.config.recommender_locations:
                for recommender_id in recommender_ids:
                    parent = f"projects/{self.config.project_id}/locations/{location}/recommenders/{recommender_id}"
                    try:
                        token = None
                        while True:
                            response = self._execute(api.projects().locations().recommenders().recommendations().list(
                                parent=parent, pageToken=token))
                            for item in response.get("recommendations", []):
                                groups = item.get("content", {}).get("operationGroups") or []
                                operations = groups[0].get("operations", []) if groups else []
                                resource = operations[0].get("resource") if operations else None
                                self._finding(category="optimization", severity="medium",
                                    resource_id=resource or item.get("name", parent),
                                    current_monthly_cost=None, estimated_monthly_savings=None,
                                    recommendation=item.get("description") or "Review the Google Cloud Recommender suggestion.",
                                    evidence=f"Recommender={recommender_id}; state={item.get('stateInfo', {}).get('state', 'unknown')}; savings not inferred.")
                            token = response.get("nextPageToken")
                            if not token: break
                    except Exception as exc:
                        self._note("recommender", f"{recommender_id} at {location}: {type(exc).__name__}: {exc}", "info")
        except Exception as exc:
            self._note("recommender", f"Recommender API unavailable: {type(exc).__name__}: {exc}")

    def scan(self) -> ScanReport:
        self.scan_billing()
        try:
            self.scan_compute()
        except Exception as exc:
            self._note("compute", f"Compute API unavailable: {type(exc).__name__}: {exc}")
        self.scan_storage()
        self.scan_cloud_sql()
        self.scan_recommender()
        return self.report
