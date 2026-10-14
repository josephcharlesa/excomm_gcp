"""Mock-only coverage for Storage and Cloud SQL scanner checks.

These tests never authenticate to Google Cloud and create no cloud resources.
"""
from exaudit.gcp.scanner import GcpScanner, ScanConfig


class Request:
    def __init__(self, response):
        self.response = response

    def execute(self):
        return self.response


class FakeBuckets:
    def list(self, **kwargs):
        return Request({"items": [
            {"name": "empty-no-lifecycle", "selfLink": "bucket/empty-no-lifecycle"},
            {"name": "configured-bucket", "lifecycle": {"rule": [{"action": {"type": "Delete"}}]}},
        ]})


class FakeObjects:
    def list(self, **kwargs):
        assert kwargs.get("maxResults") == 1
        if kwargs["bucket"] == "empty-no-lifecycle":
            return Request({})
        return Request({"items": [{"name": "example.txt"}]})


class FakeStorage:
    def buckets(self):
        return FakeBuckets()

    def objects(self):
        return FakeObjects()


class FakeSqlInstances:
    def list(self, **kwargs):
        return Request({"items": [
            {"name": "stopped-db", "state": "STOPPED", "selfLink": "sql/stopped-db"},
            {"name": "running-db", "state": "RUNNABLE", "selfLink": "sql/running-db"},
        ]})


class FakeSql:
    def instances(self):
        return FakeSqlInstances()


class Clients:
    def __init__(self, **items):
        self.items = items

    def client(self, name):
        return self.items[name]


def test_storage_flags_empty_bucket_and_lifecycle_review_without_cost_claims():
    scanner = GcpScanner(
        Clients(storage=FakeStorage()),
        ScanConfig(project_id="demo", audit_id="audit-123"),
    )
    scanner.scan_storage()

    findings = scanner.report.findings
    assert any("empty-no-lifecycle" in f.resource_id and "empty" in f.recommendation.lower()
               for f in findings)
    assert any("empty-no-lifecycle" in f.resource_id and "lifecycle" in f.recommendation.lower()
               for f in findings)
    assert all(f.current_monthly_cost is None for f in findings)
    assert all(f.estimated_monthly_savings is None for f in findings)


def test_storage_object_listing_failure_is_recorded_as_note():
    class FailingObjects:
        def list(self, **kwargs):
            raise PermissionError("mock access denied")

    class StorageWithFailure:
        def buckets(self):
            return FakeBuckets()

        def objects(self):
            return FailingObjects()

    scanner = GcpScanner(
        Clients(storage=StorageWithFailure()),
        ScanConfig(project_id="demo", audit_id="audit-123"),
    )
    scanner.scan_storage()

    assert any(note["check"] == "storage_objects" for note in scanner.report.notes)


def test_cloud_sql_only_flags_stopped_instances_and_does_not_invent_savings():
    scanner = GcpScanner(
        Clients(sqladmin=FakeSql()),
        ScanConfig(project_id="demo", audit_id="audit-123"),
    )
    scanner.scan_cloud_sql()

    assert len(scanner.report.findings) == 1
    finding = scanner.report.findings[0]
    assert finding.resource_id == "sql/stopped-db"
    assert finding.current_monthly_cost is None
    assert finding.estimated_monthly_savings is None
