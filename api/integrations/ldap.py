"""LDAP/AD connector. Pulls users, computers, and GPO data."""
from __future__ import annotations

import logging
from typing import Any

from ldap3 import ALL, AUTO_BIND_TLS_BEFORE_BIND, SUBTREE, Connection, Server, Tls
from sqlalchemy.ext.asyncio import AsyncSession

from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.ldap")


def _on(v) -> bool:
    return str(v).lower() in ("true", "1", "yes", "on")


def tls_mode(config: dict) -> tuple[bool, bool]:
    """(LDAPS, StartTLS). The UI sends use_tls, some configs use use_ssl. New integrations are saved with
    start_tls on unless LDAPS was picked (api/routes/integrations.py); older ones without it stay as saved."""
    use_ssl = _on(config.get("use_ssl", config.get("use_tls", False)))
    return use_ssl, not use_ssl and _on(config.get("start_tls"))


def new_tls_settings(config: dict) -> dict:
    """What a new LDAP integration is saved with: LDAPS if picked, otherwise StartTLS, both verified."""
    return {} if tls_mode(config)[0] or "start_tls" in config else {"start_tls": True}


def tls_warnings(config: dict) -> list[str]:
    use_ssl, start_tls = tls_mode(config)
    if not use_ssl and not start_tls:
        return ["the bind password and directory data are sent without TLS; turn on LDAPS for this integration"]
    if _on(config.get("tls_skip_verify")):
        return ["the directory's TLS certificate is not checked (lab setting); turn off the skip once it has a trusted one"]
    return []


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
        self.warnings: list[str] = tls_warnings(self.config)
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
        use_ssl, start_tls = tls_mode(self.config)
        port = int(self.config.get("port") or (636 if use_ssl else 389))
        import ssl
        # Verify the certificate unless an admin explicitly opts out for a lab box
        skip = _on(self.config.get("tls_skip_verify"))
        tls = Tls(validate=ssl.CERT_NONE if skip else ssl.CERT_REQUIRED) if use_ssl or start_tls else None
        server = Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL)
        # UI sends bind_pass, some configs use bind_password
        password = self.config.get("bind_password") or self.config.get("bind_pass", "")
        if not start_tls:
            return Connection(server, user=self.config["bind_dn"], password=password, auto_bind=True)
        # StartTLS before the bind, so the password never crosses the wire in the clear
        return Connection(server, user=self.config["bind_dn"], password=password, auto_bind=AUTO_BIND_TLS_BEFORE_BIND)

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
            attrs = ["sAMAccountName", "mail", "displayName", "distinguishedName", "memberOf", "userAccountControl", "lastLogon",
                     "userPrincipalName"]
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
                    "upn":          str(entry.userPrincipalName) if entry.userPrincipalName else None,
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
        from api.integrations.ldap_ingest import upsert_directory
        return await upsert_directory(users, computers, db)
