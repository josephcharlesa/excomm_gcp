from types import SimpleNamespace

import pytest

from exaudit.gcp.auth import validate_audit_id
from exaudit.gcp.billing import BillingExport
from exaudit.gcp.findings import FindingRecord
from exaudit.gcp.scanner import GcpScanner, ScanConfig


class Request:
    def __init__(self, value):
        self.value = value

    def execute(self):
        return self.value


class Resource:
    def __init__(self, response):
        self.response = response

    def aggregatedList(self, **kwargs):
        return Request(self.response)


class Compute:
    def __init__(self):
        self._instances = Resource({"items": {"zones/asia-south1-a": {
            "instances": [{"name": "stopped-vm", "status": "TERMINATED",
                           "selfLink": "projects/demo/zones/asia-south1-a/instances/stopped-vm"}]
        }}})
        self._disks = Resource({"items": {}})
        self._addresses = Resource({"items": {}})

    def instances(self):
        return self._instances

    def disks(self):
        return self._disks

    def addresses(self):
        return self._addresses


class EmptyStorage:
    def buckets(self):
        return SimpleNamespace(list=lambda **kwargs: Request({"items": []}))


class EmptySql:
    def instances(self):
        return SimpleNamespace(list=lambda **kwargs: Request({"items": []}))


class EmptyRecommender:
    def projects(self):
        return SimpleNamespace(locations=lambda: SimpleNamespace(recommenders=lambda:
            SimpleNamespace(recommendations=lambda: SimpleNamespace(
                list=lambda **kwargs: Request({"recommendations": []})))))


class Clients:
    def client(self, name):
        return {
            "compute": Compute(),
            "storage": EmptyStorage(),
            "sqladmin": EmptySql(),
            "recommender": EmptyRecommender(),
        }[name]


def test_audit_id_validation():
    assert validate_audit_id("audit-123") == "audit-123"
    with pytest.raises(ValueError):
        validate_audit_id("x")


def test_finding_serializes_required_schema():
    finding = FindingRecord("compute", "low", "vm-1", None, None, "Review VM")
    data = finding.to_dict()
    assert {"category", "severity", "resource_id", "current_monthly_cost",
            "estimated_monthly_savings", "recommendation"} <= data.keys()


def test_billing_fallback_does_not_invent_costs():
    result = BillingExport().monthly_cost()
    assert result["available"] is False
    assert result["monthly_cost"] is None


def test_scan_flags_stopped_vm_without_inventing_savings():
    scanner = GcpScanner(Clients(), ScanConfig(project_id="demo", audit_id="audit-123"))
    report = scanner.scan()
    vm = next(item for item in report.findings if item.resource_id.endswith("stopped-vm"))
    assert vm.category == "compute"
    assert vm.current_monthly_cost is None
    assert vm.estimated_monthly_savings is None
    assert report.to_dict()["provider"] == "gcp"
