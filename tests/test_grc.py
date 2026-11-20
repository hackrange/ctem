"""Tests for GRC exceptions, compliance, suppliers, and tags endpoints."""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession


# ── GRC exceptions auth ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_exceptions_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/grc/exceptions")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_exceptions_it_user_denied(client_it_user):
    r = await client_it_user.get("/api/v1/grc/exceptions")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_exceptions_list_empty(client_cyber):
    r = await client_cyber.get("/api/v1/grc/exceptions")
    assert r.status_code == 200
    d = r.json()
    assert "exceptions" in d
    assert isinstance(d["exceptions"], list)


@pytest.mark.asyncio
async def test_create_exception_missing_reason(client_cyber):
    r = await client_cyber.post("/api/v1/grc/exceptions", json={
        "reason": "short",
        "is_permanent": True,
    })
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_exception_no_expiry_non_permanent(client_cyber):
    r = await client_cyber.post("/api/v1/grc/exceptions", json={
        "reason": "This is a valid business justification",
        "is_permanent": False,
        "expires_at": None,
    })
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_and_revoke_exception(client_cyber):
    # Create
    r = await client_cyber.post("/api/v1/grc/exceptions", json={
        "cve_id": "CVE-2024-00001",
        "reason": "Compensating control in place via firewall segmentation",
        "is_permanent": True,
    })
    assert r.status_code == 200
    exc_id = r.json()["id"]

    # List -- should appear
    r = await client_cyber.get("/api/v1/grc/exceptions")
    ids = [e["id"] for e in r.json()["exceptions"]]
    assert exc_id in ids

    # Revoke
    r = await client_cyber.delete(f"/api/v1/grc/exceptions/{exc_id}")
    assert r.status_code == 200
    assert r.json()["revoked"] is True

    # List -- should no longer appear
    r = await client_cyber.get("/api/v1/grc/exceptions")
    ids = [e["id"] for e in r.json()["exceptions"]]
    assert exc_id not in ids


@pytest.mark.asyncio
async def test_revoke_nonexistent_exception(client_cyber):
    import uuid
    r = await client_cyber.delete(f"/api/v1/grc/exceptions/{uuid.uuid4()}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_revoke_bad_uuid(client_cyber):
    r = await client_cyber.delete("/api/v1/grc/exceptions/not-a-uuid")
    assert r.status_code == 404


# ── Compliance ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_compliance_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/grc/compliance")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_compliance_returns_frameworks(client_cyber):
    r = await client_cyber.get("/api/v1/grc/compliance")
    assert r.status_code == 200
    d = r.json()
    # Real frameworks come from FairTPRM (see test_fairtprm_grc); no more hardcoded placeholders
    assert isinstance(d["frameworks"], list)
    for f in d["frameworks"]:
        assert {"slug", "name", "score", "passed", "total"} <= set(f)


# ── Tags ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tags_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/tags")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_tags_read_only_allowed(client_read_only):
    r = await client_read_only.get("/api/v1/tags")
    assert r.status_code == 200
    assert "tags" in r.json()


@pytest.mark.asyncio
async def test_tags_empty(client_cyber):
    r = await client_cyber.get("/api/v1/tags")
    assert r.status_code == 200
    assert isinstance(r.json()["tags"], list)


# ── Suppliers ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_suppliers_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/grc/suppliers")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_suppliers_list_empty(client_cyber):
    r = await client_cyber.get("/api/v1/grc/suppliers")
    assert r.status_code == 200
    assert "suppliers" in r.json()


@pytest.mark.asyncio
async def test_supplier_gaps_bad_uuid(client_cyber):
    r = await client_cyber.get("/api/v1/grc/suppliers/not-a-uuid/gaps")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_supplier_gaps_nonexistent(client_cyber):
    import uuid
    r = await client_cyber.get(f"/api/v1/grc/suppliers/{uuid.uuid4()}/gaps")
    assert r.status_code == 404
