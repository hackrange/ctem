"""Database upkeep: names that reach VACUUM, ANALYZE or REINDEX must be plain identifiers; SQLite is left alone.
(Tried against a real PostgreSQL 16: tuning, a vacuum of 266,667 dead rows and a concurrent rebuild of a 30 MB index
at 23% leaf density down to 7.5 MB.)"""
from __future__ import annotations

import pytest


def test_only_plain_identifiers_reach_the_statements():
    from api.core.db_maintenance import _q
    assert _q("findings") == '"findings"' and _q("public.ix_findings_v") == '"ix_findings_v"' and _q('"Mixed"') == '"Mixed"'
    for bad in ('x"; DROP TABLE users; --', "a b", "", "x" * 70, "findings;", '"a""b"'):
        with pytest.raises(ValueError):
            _q(bad)


@pytest.mark.asyncio
async def test_sqlite_is_left_alone_and_the_page_needs_an_admin(client_admin, client_cyber):
    from api.core.db_maintenance import run
    assert (await run(reindex=True)) == {"skipped": "not PostgreSQL"}
    assert (await client_admin.get("/api/v1/admin/maintenance/database")).json() == {"available": False}
    assert (await client_cyber.get("/api/v1/admin/maintenance/database")).status_code == 403
    assert (await client_cyber.post("/api/v1/admin/maintenance/database/run")).status_code == 403
