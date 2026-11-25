"""Seal every account and API token as it stands (api/auth/account_seal.py), the one time an upgrade crosses 1.13.2.
# python -m api.maintenance.seal_accounts     the installer runs it on that upgrade; run it by hand after a manual one

It blesses whatever the database holds right now, so run it only when you trust it: right after the upgrade, not
to "fix" accounts refused later. An account refused afterwards was changed outside CTEM; an admin resets it
(Admin > Users: new password, remove the authenticator), which seals it again."""
from __future__ import annotations

import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def run(db: AsyncSession) -> dict:
    from api.auth.account_seal import seal_token, user_seal
    from api.auth.local import totp_seal
    from api.models.user import ApiToken, User, UserRole
    roles: dict[str, list[str]] = {}
    for uid, name in (await db.execute(select(UserRole.user_id, UserRole.role_name))).all():
        roles.setdefault(str(uid), []).append(name)
    users = tokens = 0
    for u in (await db.execute(select(User))).scalars():
        if u.totp_secret and not u.totp_seal:
            u.totp_seal = totp_seal(str(u.id), u.totp_secret)
        u.auth_seal = user_seal(u, roles.get(str(u.id), []))
        users += 1
    for t in (await db.execute(select(ApiToken))).scalars():
        seal_token(t)
        tokens += 1
    from api.auth.account_seal import seal_collector
    from api.models.collector import CollectorToken
    shippers = 0
    for t in (await db.execute(select(CollectorToken))).scalars():
        seal_collector(t)
        shippers += 1
    await db.commit()
    return {"accounts": users, "api_tokens": tokens, "shipper_credentials": shippers}


async def _main() -> None:
    from api.core import db as core_db
    core_db.init_db_worker()
    async with core_db._session_factory() as db:
        print(f"sealed {await run(db)}")


if __name__ == "__main__":
    asyncio.run(_main())
