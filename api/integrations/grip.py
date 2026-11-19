"""Grip Security connector -- shadow SaaS discovery and risky OAuth grants."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.grip")

_BASE = "https://api.grip.security/v1"


@register(Vendor.grip)
class GripSecurityConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(f"{_BASE}/apps", headers=self._headers(), params={"limit": 1})
            return resp.status_code == 200
        except Exception as e:
            log.warning("Grip Security test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        apps = await self._list_risky_apps()
        users = await self._list_risky_users()
        a_count = await self._upsert_risky_apps(apps, db)
        u_count = await self._update_user_saas_risk(users, db)
        return a_count + u_count

    async def _list_risky_apps(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_BASE}/apps",
                headers=self._headers(),
                params={"risk_level": "high,critical", "limit": 500},
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("apps", [])

    async def _list_risky_users(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_BASE}/users",
                headers=self._headers(),
                params={"risk_level": "high,critical", "limit": 500},
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("users", [])

    async def _upsert_risky_apps(self, apps: list[dict], db: AsyncSession) -> int:
        """Cache shadow IT / risky SaaS apps as AppSettings for the UI."""
        from api.models.settings import AppSetting
        from sqlalchemy import select
        import json
        count = 0

        for app in apps:
            key = f"grip_saas_app_{app.get('id', '')}"
            result = await db.execute(select(AppSetting).where(AppSetting.key == key))
            setting = result.scalar_one_or_none() or AppSetting(key=key, is_sensitive=False)
            setting.value = json.dumps({
                "name": app.get("name"),
                "risk_level": app.get("risk_level"),
                "user_count": app.get("user_count"),
                "data_access": app.get("data_access_scopes", []),
                "source": "grip",
            })
            db.add(setting)
            count += 1

        await db.commit()
        return count

    async def _update_user_saas_risk(self, users: list[dict], db: AsyncSession) -> int:
        """Bump saas_risk_score on User records for Grip high-risk users."""
        from api.models.user import User
        from api.core.encryption import search_hash
        from sqlalchemy import select
        count = 0

        for u in users:
            email = u.get("email")
            if not email:
                continue
            email_hash = search_hash(email)
            result = await db.execute(select(User).where(User.email_hash == email_hash))
            user = result.scalar_one_or_none()
            if user:
                risk_level = u.get("risk_level", "medium")
                user.saas_risk_score = {"critical": 90, "high": 70, "medium": 40, "low": 10}.get(risk_level, 0)
                count += 1

        await db.commit()
        return count

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.config['api_key']}"}
