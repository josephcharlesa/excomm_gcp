"""Additional scanner regression tests for pagination and partial failures."""
from exaudit.gcp.scanner import GcpScanner, ScanConfig


class PagedRequest:
    def __init__(self, response):
        self.response = response

    def execute(self):
        return self.response


class PagedCollection:
    def __init__(self, pages):
        self.pages = pages
        self.tokens_seen = []

    def aggregatedList(self, **kwargs):
        token = kwargs.get("pageToken")
        self.tokens_seen.append(token)
        index = 0 if token is None else 1
        return PagedRequest(self.pages[index])


class PagedCompute:
    def __init__(self):
        self.instance_pages = PagedCollection([
            {
                "items": {"zones/asia-south1-a": {"instances": [
                    {"name": "vm-page-1", "status": "TERMINATED"}
                ]}},
                "nextPageToken": "next-page",
            },
            {
                "items": {"zones/asia-south1-b": {"instances": [
                    {"name": "vm-page-2", "status": "TERMINATED"}
                ]}}
            },
        ])
        self.disks_pages = PagedCollection([{"items": {}}])
        self.address_pages = PagedCollection([{"items": {}}])

    def instances(self):
        return self.instance_pages

    def disks(self):
        return self.disks_pages

    def addresses(self):
        return self.address_pages


class BrokenCollection:
    def aggregatedList(self, **kwargs):
        raise PermissionError("permission denied")


class FaultyCompute:
    def instances(self):
        return BrokenCollection()

    def disks(self):
        return PagedCollection([{"items": {}}])

    def addresses(self):
        return PagedCollection([{"items": {}}])


class NoopClient:
    def buckets(self):
        return type("Buckets", (), {"list": lambda self, **kwargs: PagedRequest({"items": []})})()

    def instances(self):
        return type("Instances", (), {"list": lambda self, **kwargs: PagedRequest({"items": []})})()

    def projects(self):
        return type("Projects", (), {
            "locations": lambda self: type("Locations", (), {
                "recommenders": lambda self: type("Recommenders", (), {
                    "recommendations": lambda self: type("Recommendations", (), {
                        "list": lambda self, **kwargs: PagedRequest({"recommendations": []})
                    })()
                })()
            })()
        })()


class InjectedClients:
    def __init__(self, **clients):
        self.clients = clients

    def client(self, name):
        if name in self.clients:
            return self.clients[name]
        return NoopClient()


def test_compute_scanner_follows_next_page_token():
    compute = PagedCompute()
    scanner = GcpScanner(
        InjectedClients(compute=compute),
        ScanConfig(project_id="demo", audit_id="audit-123"),
    )

    scanner.scan_compute()

    ids = {finding.resource_id for finding in scanner.report.findings}
    assert "vm-page-1" in ids
    assert "vm-page-2" in ids
    assert compute.instance_pages.tokens_seen == [None, "next-page"]


def test_compute_collection_failure_is_recorded_and_other_collections_continue():
    scanner = GcpScanner(
        InjectedClients(compute=FaultyCompute()),
        ScanConfig(project_id="demo", audit_id="audit-123"),
    )

    scanner.scan_compute()

    assert any(note["check"] == "compute" and "PermissionError" in note["message"]
               for note in scanner.report.notes)
