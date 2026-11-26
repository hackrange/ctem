"""Discovered Users cards: counted over everyone (not one page), and each card filters the list to who it counts."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import delete


async def test_cards_count_everyone_and_filter_the_list(client_cyber, client_it_user, db):
    from api.models.risk import RiskScore
    from api.models.user import User
    tag = "".join(chr(97 + int(c, 16)) for c in uuid.uuid4().hex[:8])
    now = datetime.now(timezone.utc)
    admin = User(username=f"cadm{tag}", is_local=False, is_active=True, ad_groups=["CN=Domain Admins,OU=Groups,DC=acme,DC=example"],
                 idp={"factors": ["push"]})
    nomfa = User(username=f"cnom{tag}", is_local=False, is_active=True, idp={"factors": []}, idv_verified_at=now)
    svc = User(username=f"csvc{tag}", is_local=False, is_active=True, is_service_account=True, idp={"factors": ["sms"]})
    db.add_all([admin, nomfa, svc])
    await db.flush()
    db.add(RiskScore(entity_type="user", entity_id=nomfa.id, score=90.0, grade="F", calculated_at=now))
    await db.commit()
    try:
        before = (await client_cyber.get("/api/v1/directory/users/summary")).json()
        assert set(before) == {"total", "high_risk", "no_mfa", "privileged", "service", "idv"}
        assert before["total"] >= 3 and min(before.values()) >= 1
        want = {"privileged": f"cadm{tag}", "no_mfa": f"cnom{tag}", "service": f"csvc{tag}", "idv": f"cnom{tag}",
                "high_risk": f"cnom{tag}"}
        for card, name in want.items():
            r = await client_cyber.get(f"/api/v1/directory/users?card={card}&q={tag}&limit=200")
            assert r.status_code == 200, card
            assert [u["username"] for u in r.json()["users"]] == [name], card
        r = await client_cyber.get(f"/api/v1/directory/users?grade=F&q={tag}")
        assert [u["username"] for u in r.json()["users"]] == [f"cnom{tag}"]
        assert (await client_cyber.get("/api/v1/directory/users?card=everyone")).status_code == 422
        assert (await client_cyber.get("/api/v1/directory/users?grade=E")).status_code == 422
        assert (await client_it_user.get("/api/v1/directory/users/summary")).status_code == 403
    finally:
        await db.execute(delete(RiskScore).where(RiskScore.entity_id.in_([admin.id, nomfa.id, svc.id])))
        await db.execute(delete(User).where(User.username.like(f"%{tag}")))
        await db.commit()
