# import os
# import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from app.database import Base, get_db
from app import models
from app.main import app

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


def test_create_and_retrieve_unprotected_share_link():
    token = register_and_login()
    scan = client.post("/scans", json={
        "title": "Shared finding",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()

    created = client.post(f"/scans/{scan['id']}/share", headers=auth_headers(token))
    assert created.status_code == 200
    share_url = created.json()["share_url"]
    assert share_url.startswith("http://localhost:8000/share/")

    shared = client.get(share_url.replace("http://localhost:8000", ""))
    assert shared.status_code == 200
    assert shared.json()["title"] == "Shared finding"
    assert "owner_id" not in shared.json()


def test_password_protected_share_link_requires_correct_password():
    token = register_and_login()
    scan = client.post("/scans", json={
        "title": "Protected finding",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()
    created = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": "stakeholder-secret"},
        headers=auth_headers(token),
    )
    share_path = created.json()["share_url"].replace("http://localhost:8000", "")

    assert client.get(share_path).status_code == 401
    assert client.get(share_path, params={"password": "wrong"}).status_code == 401
    response = client.get(share_path, params={"password": "stakeholder-secret"})
    assert response.status_code == 200
    assert response.json()["title"] == "Protected finding"


def test_share_link_expires_after_24_hours():
    token = register_and_login()
    scan = client.post("/scans", json={
        "title": "Expiring finding",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()
    created = client.post(f"/scans/{scan['id']}/share", json={}, headers=auth_headers(token))
    share_path = created.json()["share_url"].replace("http://localhost:8000", "")

    db = TestingSessionLocal()
    try:
        link = db.query(models.SharedReportLink).one()
        assert link.expires_at <= datetime.utcnow() + timedelta(hours=24)
        link.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    assert client.get(share_path).status_code == 404


def test_share_link_cannot_be_created_for_another_users_scan():
    owner_token = register_and_login()
    scan = client.post("/scans", json={
        "title": "Private finding",
        "affected_component": "API",
    }, headers=auth_headers(owner_token)).json()
    other_token = register_and_login("bob", "bob@example.com")

    response = client.post(
        f"/scans/{scan['id']}/share",
        json={},
        headers=auth_headers(other_token),
    )
    assert response.status_code == 404
