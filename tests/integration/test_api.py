import pytest
from fastapi.testclient import TestClient

from scanner.api.app import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_dashboard_summary(client):
    r = client.get("/api/v1/dashboard/summary")
    assert r.status_code == 200
    data = r.json()
    assert "scans" in data
    assert "findings" in data
    assert "targets" in data


def test_targets_lifecycle(client):
    # Create
    r = client.post("/api/v1/targets", json={
        "url": "https://testphase11.example.com",
        "name": "Phase 11 Test Target",
        "description": "Created in integration test",
        "group": "test"
    })
    assert r.status_code == 201
    target = r.json()
    target_id = target["id"]
    assert target["url"] == "https://testphase11.example.com"

    # List
    r = client.get("/api/v1/targets")
    assert r.status_code == 200
    found = any(t["id"] == target_id for t in r.json())
    assert found

    # Get by ID
    r = client.get(f"/api/v1/targets/{target_id}")
    assert r.status_code == 200

    # Update
    r = client.put(f"/api/v1/targets/{target_id}", json={"name": "Updated Name"})
    assert r.status_code == 200
    assert r.json()["name"] == "Updated Name"

    # Delete
    r = client.delete(f"/api/v1/targets/{target_id}")
    assert r.status_code == 204

    # Confirm deleted
    r = client.get(f"/api/v1/targets/{target_id}")
    assert r.status_code == 404


def test_target_ssrf_protection(client):
    r = client.post("/api/v1/targets", json={
        "url": "http://localhost/admin",
        "name": "SSRF Attempt"
    })
    assert r.status_code == 400
    assert "blocked" in r.json()["detail"].lower()


def test_create_and_list_scan(client):
    import uuid
    unique_url = f"https://scantest-{uuid.uuid4()}.example.com"
    # Create target
    r = client.post("/api/v1/targets", json={
        "url": unique_url,
        "name": "Scan Test Target",
    })
    assert r.status_code == 201

    # Create scan
    r = client.post("/api/v1/scans", json={
        "target_url": unique_url,
        "scan_type": "passive",
        "profile": "default"
    })
    assert r.status_code == 201
    scan = r.json()
    scan_id = scan["id"]
    assert scan["status"] in ("running", "pending")

    # List scans
    r = client.get("/api/v1/scans")
    assert r.status_code == 200
    assert any(s["id"] == scan_id for s in r.json())

    # Get scan
    r = client.get(f"/api/v1/scans/{scan_id}")
    assert r.status_code == 200

    # Cancel scan
    r = client.post(f"/api/v1/scans/{scan_id}/cancel")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"


def test_findings(client):
    r = client.get("/api/v1/findings")
    assert r.status_code == 200
    data = r.json()
    assert "findings" in data
    assert "count" in data


def test_technologies(client):
    r = client.get("/api/v1/technologies")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_analytics(client):
    r = client.get("/api/v1/analytics/severity-breakdown")
    assert r.status_code == 200
    assert isinstance(r.json(), dict)

    r = client.get("/api/v1/analytics/findings-trend")
    assert r.status_code == 200
    assert isinstance(r.json(), list)

    r = client.get("/api/v1/analytics/risk-distribution")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
