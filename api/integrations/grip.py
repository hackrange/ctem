"""
Grip Security connector -- ITDR, posture management, shadow SaaS, shadow AI.

NOTE: If open-fairtprm is also integrated and has Grip configured, Grip telemetry
already flows through that channel. Set fairtprm_grip_passthrough=true in this
integration's config to skip the direct sync and avoid double-counting.

Auth: access-token header (NOT Bearer -- Grip returns 401 on Bearer tokens).
URL:  Tenant-specific, e.g. https://acme.dep.grip.security/public/saas
      Config key: base_url (the saas base URL above)
Pagination: offset/limit 200, stop on empty page (short page != end of data).
"""
from __future__ import annotations

import hashlib
import html
import json
import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.grip")

_PAGE = 200
_MAX_PAGES = 1000


@register(Vendor.grip)
class GripSecurityConnector(BaseConnector):
    """
    Syncs four distinct signals from Grip:
      1. ITDR threats    (/public/threats)
      2. Posture checks  (/public/posture-checks)
      3. SaaS apps       (base URL) -- shadow SaaS vs shadow AI by aiDepth.level
      4. AI agents       (/public/ai-agents)
    Then rolls up per-identity risk in IdentityRiskScore.
    """

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(self._saas_url(), headers=self._headers(), params={"limit": 1, "offset": 0})
            return resp.status_code == 200
        except Exception as exc:
            log.warning("Grip connection test failed: %s", exc)
            return False

    async def sync(self, db: AsyncSession) -> int:
        if self.config.get("fairtprm_grip_passthrough"):
            log.info("Grip: passthrough mode -- skipping direct sync (data flows via FairTPRM)")
            return 0

        counts = [
            await self._sync_itdr_threats(db),
            await self._sync_posture_checks(db),
            await self._sync_saas_apps(db),
            await self._sync_ai_agents(db),
            await self._sync_users(db),
        ]
        total = sum(counts)
        log.info("Grip sync complete: %d records across ITDR/posture/saas/ai/users", total)
        return total

    # ── ITDR Threats ──────────────────────────────────────────────────────────

    async def _sync_itdr_threats(self, db: AsyncSession) -> int:
        from api.models.identity import IdentityThreat, ItdrThreatType, ItdrAlertStatus
        from api.core.encryption import search_hash

        threats = await self._paginate(self._root_url() + "/threats")
        count = 0
        for t in threats:
            ext_id = str(t.get("alertId", ""))
            if not ext_id:
                continue

            result = await db.execute(
                select(IdentityThreat).where(
                    IdentityThreat.source == "grip",
                    IdentityThreat.external_id == ext_id,
                )
            )
            rec = result.scalar_one_or_none() or IdentityThreat(source="grip", external_id=ext_id)

            rec.threat_type = _map_threat_type(t.get("alertType", ""))
            rec.severity = (t.get("alertSeverity") or "medium").lower()
            rec.status = _map_alert_status(t.get("status", ""))
            rec.title = _decode_html(t.get("alertName") or t.get("description") or "Grip ITDR alert")
            rec.description = _decode_html(t.get("description") or "")
            rec.mitre_technique_id = _itdr_mitre(rec.threat_type)
            rec.app_name = t.get("relatedEntityName") if t.get("relatedEntityType") in ("saas_application", "Application") else None
            rec.app_external_id = t.get("relatedEntityId")

            # PII -- encrypt all identity fields
            raw_mail = t.get("relatedIdentityMail") or ""
            if raw_mail:
                rec.user_email_hash = search_hash(raw_mail.lower())
                rec.user_display = _mask_email(raw_mail)
            rec.user_external_id = t.get("relatedEntityId") if t.get("relatedEntityType") == "user" else None

            rec.detected_at = _parse_dt(t.get("createdAt"))
            if t.get("status", "").lower() in ("resolved", "closed"):
                rec.resolved_at = _parse_dt(t.get("updatedAt"))

            # Encrypted raw payload -- store unique fields and event logs
            rec.raw = {
                "uniqueFieldsData": t.get("uniqueFieldsData"),
                "eventLogs": t.get("eventLogs"),
                "mitigationSteps": t.get("mitigationSteps", []),
                "potentialImpacts": t.get("potentialImpacts", []),
                "alertUrl": t.get("alertUrl"),
            }

            db.add(rec)
            count += 1

        await db.commit()
        log.info("Grip ITDR: upserted %d threats", count)
        return count

    # ── Posture Checks (SSPM) ─────────────────────────────────────────────────

    async def _sync_posture_checks(self, db: AsyncSession) -> int:
        from api.models.identity import PostureFinding

        checks = await self._paginate(self._root_url() + "/posture-checks")
        count = 0
        for c in checks:
            ext_id = str(c.get("uuid", c.get("postureCheckId", "")))
            if not ext_id:
                continue

            result = await db.execute(
                select(PostureFinding).where(
                    PostureFinding.source == "grip",
                    PostureFinding.external_id == ext_id,
                )
            )
            rec = result.scalar_one_or_none() or PostureFinding(source="grip", external_id=ext_id)

            rec.finding_type = c.get("postureCheckId") or c.get("securityDomain") or "unknown"
            rec.severity = (c.get("severity") or "medium").lower()
            rec.title = _decode_html(c.get("description") or "Grip posture finding")
            rec.description = _decode_html(c.get("riskDescription") or "")
            rec.affected_count = int(c.get("findingsCount") or 0)
            rec.is_resolved = str(c.get("status", "")).lower() in ("resolved", "passed", "disabled")
            rec.detected_at = _parse_dt(c.get("updatedAt"))

            db.add(rec)
            count += 1

        await db.commit()
        log.info("Grip posture: upserted %d checks", count)
        return count

    # ── SaaS Apps (shadow SaaS + shadow AI detection) ─────────────────────────

    async def _sync_saas_apps(self, db: AsyncSession) -> int:
        from api.models.identity import SaasAppRecord

        apps = await self._paginate(self._saas_url())
        count = 0
        for app in apps:
            ext_id = str(app.get("id", ""))
            if not ext_id:
                continue

            gd = app.get("gripData") or {}
            ai_depth = gd.get("aiDepth") or {}
            is_shadow_ai = bool(ai_depth.get("level"))  # non-null aiDepth.level = AI app

            result = await db.execute(
                select(SaasAppRecord).where(
                    SaasAppRecord.source == "grip",
                    SaasAppRecord.external_id == ext_id,
                )
            )
            rec = result.scalar_one_or_none() or SaasAppRecord(source="grip", external_id=ext_id)

            rec.app_name = app.get("name") or ""
            rec.app_category = "ai" if is_shadow_ai else (gd.get("category") or "saas")
            rec.vendor = app.get("name")
            rec.is_shadow_ai = is_shadow_ai
            rec.is_sanctioned = str(gd.get("sanctionTag") or "").lower() in ("sanctioned", "approved")
            risk_raw = int(gd.get("riskScore") or 0)
            rec.risk_score = float(risk_raw)
            rec.risk_level = _score_to_level(risk_raw)
            rec.user_count = int(gd.get("numberOfUsers") or 0)
            rec.last_seen = _parse_dt(gd.get("latestEventTime"))

            # Store OAuth scope breakdown
            oauth = gd.get("oauthScopes") or {}
            rec.oauth_scopes = {
                "total": oauth.get("total"),
                "high": oauth.get("high", {}).get("count"),
                "high_scopes": oauth.get("high", {}).get("scopes", []),
                "medium": oauth.get("medium", {}).get("count"),
                "low": oauth.get("low", {}).get("count"),
            }
            # Data access scopes / compliance
            rec.data_access_scopes = gd.get("assets") or []

            db.add(rec)
            count += 1

        await db.commit()
        shadow_ai_n = sum(1 for a in apps if bool((a.get("gripData") or {}).get("aiDepth", {}) and (a.get("gripData") or {}).get("aiDepth", {}).get("level")))
        log.info("Grip SaaS: upserted %d apps (%d shadow AI, rest shadow SaaS)", count, shadow_ai_n)
        return count

    # ── AI Agents ─────────────────────────────────────────────────────────────

    async def _sync_ai_agents(self, db: AsyncSession) -> int:
        """AI agent instances (Copilots, custom GPTs, etc.) -- distinct from shadow AI apps."""
        from api.models.identity import SaasAppRecord
        from api.core.encryption import search_hash

        agents = await self._paginate(self._root_url() + "/ai-agents")
        count = 0
        for agent in agents:
            ext_id = str(agent.get("aiAgentApiId") or agent.get("id") or "")
            if not ext_id:
                continue

            result = await db.execute(
                select(SaasAppRecord).where(
                    SaasAppRecord.source == "grip_ai_agent",
                    SaasAppRecord.external_id == ext_id,
                )
            )
            rec = result.scalar_one_or_none() or SaasAppRecord(source="grip_ai_agent", external_id=ext_id)

            rec.app_name = agent.get("name") or ext_id
            rec.app_category = "ai_agent"
            rec.is_shadow_ai = True
            rec.is_sanctioned = str(agent.get("sanctionState") or "").lower() in ("sanctioned", "approved")
            rec.risk_score = float(agent.get("score") or 0)
            rec.risk_level = _score_to_level(int(agent.get("score") or 0))
            rec.last_seen = _parse_dt(agent.get("lastSeen") or agent.get("lastUsage"))

            # Sensitive fields encrypted via EncryptedJSON
            owner_mail = agent.get("ownerEmail") or ""
            rec.data_access_scopes = {
                "owner_email_hash": search_hash(owner_mail.lower()) if owner_mail else None,
                "owner_display": _mask_email(owner_mail) if owner_mail else None,
                "is_connected_to_internet": agent.get("isConnectedToInternet"),
                "saas_scopes": agent.get("saasScopes") or [],
                "sharing": agent.get("sharingAttributes"),
                # knowledge_files and identities_permissions are high-PII -- omit from storage
            }
            db.add(rec)
            count += 1

        await db.commit()
        log.info("Grip AI agents: upserted %d agents", count)
        return count

    # ── User risk rollup ──────────────────────────────────────────────────────

    async def _sync_users(self, db: AsyncSession) -> int:
        """Fetch Grip user list and build IdentityRiskScore per email_hash."""
        from api.models.identity import IdentityRiskScore
        from api.core.encryption import search_hash

        users = await self._paginate(self._root_url() + "/users")
        count = 0
        for u in users:
            mail = (u.get("mail") or "").lower().strip()
            if not mail:
                continue

            email_hash = search_hash(mail)
            result = await db.execute(
                select(IdentityRiskScore).where(IdentityRiskScore.user_email_hash == email_hash)
            )
            rec = result.scalar_one_or_none() or IdentityRiskScore(user_email_hash=email_hash)
            rec.user_display = _mask_email(mail)

            # Count active ITDR alerts for this identity
            from api.models.identity import IdentityThreat, ItdrAlertStatus
            alert_result = await db.execute(
                select(IdentityThreat).where(
                    IdentityThreat.user_email_hash == email_hash,
                    IdentityThreat.status == ItdrAlertStatus.active,
                )
            )
            active_alerts = alert_result.scalars().all()
            rec.active_itdr_alerts = len(active_alerts)

            # ITDR score: weight by severity
            itdr_raw = sum(_sev_weight(a.severity) for a in active_alerts)
            rec.itdr_score = min(100.0, float(itdr_raw))

            gd = u.get("gripData") or {}
            saas_count = int(gd.get("numberOfSaas") or 0)
            rec.shadow_saas_apps = saas_count
            rec.shadow_saas_score = min(100.0, saas_count * 5.0)   # 5 pts per shadow app

            rec.last_synced = datetime.now(timezone.utc)

            # Composite identity risk
            rec.composite_identity_score = round(
                rec.itdr_score * 0.50
                + rec.posture_score * 0.25
                + rec.shadow_saas_score * 0.15
                + rec.shadow_ai_score * 0.10,
                2,
            )

            db.add(rec)
            count += 1

        await db.commit()
        log.info("Grip identity scores: rolled up %d identities", count)
        return count

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    async def _paginate(self, url: str) -> list[dict]:
        seen_hashes: set[str] = set()
        results: list[dict] = []
        offset = 0

        for _ in range(_MAX_PAGES):
            async with safe_client() as client:
                resp = await client.get(
                    url, headers=self._headers(),
                    params={"limit": _PAGE, "offset": offset},
                )
            if resp.status_code != 200:
                log.warning("Grip %s returned %d", url, resp.status_code)
                break

            page = resp.json()
            # Response is either a list or {"items": [...]} or {"data": [...]}
            items = page if isinstance(page, list) else (page.get("items") or page.get("data") or [])

            if not items:
                break  # empty page = done (short page != end of data per Grip docs)

            page_hash = hashlib.md5(json.dumps(items, sort_keys=True).encode()).hexdigest()
            if page_hash in seen_hashes:
                log.warning("Grip pagination loop detected at offset %d, stopping", offset)
                break
            seen_hashes.add(page_hash)

            results.extend(items)
            offset += len(items)

        return results

    def _headers(self) -> dict:
        # Grip requires access-token header -- not Authorization: Bearer
        return {"access-token": self.config["api_key"]}

    def _saas_url(self) -> str:
        """Tenant-specific SaaS base URL, e.g. https://acme.dep.grip.security/public/saas"""
        return self.config["base_url"].rstrip("/")

    def _root_url(self) -> str:
        """Strip /public/saas suffix to get tenant root for other endpoints."""
        base = self._saas_url()
        for suffix in ("/public/saas", "/saas"):
            if base.endswith(suffix):
                return base[: -len(suffix)]
        return base.rsplit("/public/", 1)[0] + "/public" if "/public/" in base else base


# ── Pure helpers (no DB, no IO) ────────────────────────────────────────────────

def _decode_html(s: str) -> str:
    """Grip double-encodes display strings with HTML entities."""
    return html.unescape(html.unescape(s)) if s else ""


def _mask_email(email: str) -> str:
    """Show only the last 2 chars of the local part + domain -- minimal PII."""
    if not email or "@" not in email:
        return ""
    local, domain = email.rsplit("@", 1)
    masked = ("*" * max(0, len(local) - 2)) + local[-2:] if len(local) > 2 else local
    return f"{masked}@{domain}"


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _score_to_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _sev_weight(severity: str) -> float:
    return {"critical": 25.0, "high": 15.0, "medium": 7.0, "low": 2.0}.get(severity, 5.0)


def _map_threat_type(raw: str) -> "ItdrThreatType":
    from api.models.identity import ItdrThreatType
    mapping = {
        "credential": ItdrThreatType.credential_compromise,
        "impossible_travel": ItdrThreatType.impossible_travel,
        "mfa_bypass": ItdrThreatType.mfa_bypass,
        "mfa_fatigue": ItdrThreatType.mfa_fatigue,
        "account_takeover": ItdrThreatType.account_takeover,
        "privilege": ItdrThreatType.privilege_escalation,
        "oauth": ItdrThreatType.oauth_abuse,
        "exfil": ItdrThreatType.data_exfiltration,
        "brute": ItdrThreatType.brute_force,
        "session": ItdrThreatType.session_hijack,
        "risky_grant": ItdrThreatType.risky_oauth_grant,
        "anomalous": ItdrThreatType.anomalous_access,
    }
    lower = raw.lower()
    for key, val in mapping.items():
        if key in lower:
            return val
    return ItdrThreatType.unknown


def _map_alert_status(raw: str) -> "ItdrAlertStatus":
    from api.models.identity import ItdrAlertStatus
    lower = raw.lower()
    if lower in ("resolved", "closed"):
        return ItdrAlertStatus.resolved
    if "false" in lower or "fp" in lower:
        return ItdrAlertStatus.false_positive
    if lower in ("investigating", "in_progress", "pending"):
        return ItdrAlertStatus.investigating
    return ItdrAlertStatus.active


def _itdr_mitre(threat_type: "ItdrThreatType") -> str | None:
    from api.models.identity import ItdrThreatType
    return {
        ItdrThreatType.credential_compromise: "T1078",
        ItdrThreatType.impossible_travel: "T1078",
        ItdrThreatType.mfa_bypass: "T1621",
        ItdrThreatType.mfa_fatigue: "T1621",
        ItdrThreatType.account_takeover: "T1078",
        ItdrThreatType.privilege_escalation: "T1078.004",
        ItdrThreatType.oauth_abuse: "T1550",
        ItdrThreatType.risky_oauth_grant: "T1550",
        ItdrThreatType.session_hijack: "T1539",
        ItdrThreatType.brute_force: "T1110",
        ItdrThreatType.data_exfiltration: "T1567",
    }.get(threat_type)
