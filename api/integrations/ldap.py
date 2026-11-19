"""LDAP/AD connector. Pulls users, computers, and GPO data."""
from __future__ import annotations

import logging
from typing import Any

from ldap3 import ALL, SUBTREE, Connection, Server, Tls
from sqlalchemy.ext.asyncio import AsyncSession

from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.ldap")


@register(Vendor.ldap)
class LDAPConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            conn = self._connect()
            conn.unbind()
            return True
        except Exception as e:
            log.warning("LDAP test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        conn = self._connect()
        try:
            users = self._fetch_users(conn)
            computers = self._fetch_computers(conn)
            count = await self._upsert_all(users, computers, db)
        finally:
            conn.unbind()
        return count

    def _connect(self) -> Connection:
        host = self.config["host"]
        # UI sends use_tls, some configs use use_ssl -- accept both
        use_ssl = self.config.get("use_ssl", self.config.get("use_tls", False))
        port = int(self.config.get("port", 636 if use_ssl else 389))
        tls = Tls(validate=__import__("ssl").CERT_NONE) if use_ssl else None
        server = Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL)
        # UI sends bind_pass, some configs use bind_password
        password = self.config.get("bind_password") or self.config.get("bind_pass", "")
        conn = Connection(
            server,
            user=self.config["bind_dn"],
            password=password,
            auto_bind=True,
        )
        return conn

    @property
    def _ldap_type(self) -> str:
        """'ad' or 'openldap' -- determines object class / attribute names."""
        return self.config.get("ldap_type", "ad").lower()

    def _fetch_users(self, conn: Connection) -> list[dict]:
        base = self.config.get("user_base_dn", self.config["base_dn"])
        if self._ldap_type == "openldap":
            obj_filter = "(objectClass=inetOrgPerson)"
            attrs = ["cn", "uid", "mail", "displayName", "distinguishedName", "description", "title"]
        else:
            obj_filter = "(objectClass=user)"
            attrs = ["sAMAccountName", "mail", "displayName", "distinguishedName", "memberOf", "userAccountControl", "lastLogon"]
        conn.search(base, obj_filter, search_scope=SUBTREE, attributes=attrs)
        users = []
        for entry in conn.entries:
            if self._ldap_type == "openldap":
                uname = str(entry.uid) if entry.uid else str(entry.cn)
                desc  = str(entry.description) if entry.description else ""
                is_admin = "isAdmin=true" in desc or str(getattr(entry, "title", "")).lower().startswith("domain admin")
                users.append({
                    "username":     uname,
                    "email":        str(entry.mail) if entry.mail else None,
                    "display_name": str(entry.displayName) if entry.displayName else str(entry.cn),
                    "ad_dn":        str(entry.distinguishedName),
                    "groups":       [],  # OpenLDAP groups resolved separately
                    "disabled":     False,
                })
            else:
                uac = int(entry.userAccountControl.value or 0)
                users.append({
                    "username":     str(entry.sAMAccountName),
                    "email":        str(entry.mail) if entry.mail else None,
                    "display_name": str(entry.displayName) if entry.displayName else None,
                    "ad_dn":        str(entry.distinguishedName),
                    "groups":       [str(g) for g in (entry.memberOf.values if entry.memberOf else [])],
                    "disabled":     bool(uac & 0x2),
                })
        return users

    def _fetch_computers(self, conn: Connection) -> list[dict]:
        base = self.config.get("computer_base_dn", self.config["base_dn"])
        if self._ldap_type == "openldap":
            obj_filter = "(objectClass=device)"
            attrs = ["cn", "l", "distinguishedName", "description"]
        else:
            obj_filter = "(objectClass=computer)"
            attrs = ["name", "dNSHostName", "distinguishedName", "operatingSystem", "lastLogonDate"]
        conn.search(base, obj_filter, search_scope=SUBTREE, attributes=attrs)
        computers = []
        for entry in conn.entries:
            if self._ldap_type == "openldap":
                desc = str(entry.description) if entry.description else ""
                os_val = ""
                for part in desc.split(";"):
                    if part.startswith("os="):
                        os_val = part[3:]
                computers.append({
                    "hostname": str(entry.cn),
                    "fqdn":     str(entry.l) if entry.l else None,
                    "ad_dn":    str(entry.distinguishedName),
                    "os":       os_val or None,
                })
            else:
                computers.append({
                    "hostname": str(entry.name),
                    "fqdn":     str(entry.dNSHostName) if entry.dNSHostName else None,
                    "ad_dn":    str(entry.distinguishedName),
                    "os":       str(entry.operatingSystem) if entry.operatingSystem else None,
                })
        return computers

    async def _upsert_all(self, users: list[dict], computers: list[dict], db: AsyncSession) -> int:
        from api.core.encryption import encrypt, search_hash
        from api.models.user import User
        from api.models.device import Device
        from sqlalchemy import select

        count = 0
        for u in users:
            if not u["username"]:
                continue
            result = await db.execute(select(User).where(User.username == u["username"]))
            user = result.scalar_one_or_none()
            if user is None:
                user = User(username=u["username"], is_local=False)
                db.add(user)
            if u.get("email"):
                user.email = u["email"]
                user.email_hash = search_hash(u["email"])
            if u.get("display_name"):
                user.display_name = u["display_name"]
            if u.get("ad_dn"):
                user.ad_dn = u["ad_dn"]
            user.ad_groups = u.get("groups", [])
            count += 1

        for c in computers:
            if not c["hostname"]:
                continue
            result = await db.execute(
                select(Device).where(Device.hostname == c["hostname"])
            )
            device = result.scalar_one_or_none()
            if device is None:
                from api.models.device import DeviceType
                device = Device(hostname=c["hostname"], device_type=DeviceType.workstation, source="ldap")
                db.add(device)
            device.fqdn = c.get("fqdn")
            device.ad_dn = c.get("ad_dn")
            device.os = c.get("os")
            device.ad_joined = True
            count += 1

        await db.commit()
        return count
