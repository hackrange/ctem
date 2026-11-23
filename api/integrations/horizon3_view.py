"""NodeZero's attacker view of each asset (api/integrations/horizon3_apply.py): how it rates the host, attack paths
that reach it, credentials it found there, and data stores it could read. Kept on the asset (Device.pentest) for
the asset's Pentest tab; a domain admin credential and a critical attack path also raise SIEM feed alerts."""
from __future__ import annotations

import re

_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
CRITICAL_IMPACTS = {"DomainCompromise", "CriticalInfrastructureCompromise", "SensitiveDataExposure", "BusinessEmailCompromise",
                    "RansomwareExposure", "CloudCompromise", "DomainUserCompromise"}
KEEP = 25   # per list, per asset


def hosts_with_something(weaknesses: list[dict], extra: dict) -> set:
    """IPs NodeZero found something on (a weakness, a credential, an attack path): those become assets if new."""
    out = {w.get("ip") for w in weaknesses if w.get("ip")}
    out |= {c.get("ip") for c in extra.get("creds") or [] if c.get("ip")}
    for p in extra.get("paths") or []:
        out |= set(_IP.findall(str(p.get("affected_asset_text") or "")))
    return out


def _txt(v, n):
    return str(v)[:n] if v not in (None, "") else None


async def apply(db, pentest: dict, when, extra: dict, cache: dict, find) -> None:
    from api.core.alert_feed import _add, existing
    views: dict[str, dict] = {}

    async def view_of(ip, name):
        d = await find(ip, name)
        if d is None:
            return None, None
        v = views.setdefault(str(d.id), {"pentest": _txt(pentest.get("name"), 200), "pentest_id": pentest.get("op_id"),
                                         "tested_at": when.isoformat(), "attack_paths": [], "credentials": [], "data_stores": [],
                                         "open_services": []})
        return d, v

    for h in extra.get("hosts") or []:
        d, v = await view_of(h.get("ip"), h.get("host_name"))
        if v is not None:
            v.update({"score": h.get("score"), "severity": _txt(h.get("severity"), 16), "os": (h.get("os_names") or [None])[0],
                      "domain_controller": bool(h.get("is_domain_controller")), "services": h.get("services_count"),
                      "weaknesses": h.get("weaknesses_count"), "credentials_found": h.get("credentials_count"),
                      "cloud": _txt(h.get("cloud_provider"), 32)})
    for sv in extra.get("services") or []:   # each open port NodeZero found, on the assets CTEM knows
        port = sv.get("port")
        if not isinstance(port, int) or not 0 < port < 65536:
            continue
        d, v = await view_of(sv.get("ip"), sv.get("host_name"))
        row = {"port": port, "protocol": _txt(str(sv.get("protocol") or "tcp").lower(), 8)}
        if v is not None and len(v["open_services"]) < 200 and row not in v["open_services"]:
            v["open_services"].append(row)
    alerts = []
    for p in extra.get("paths") or []:
        ips = _IP.findall(str(p.get("affected_asset_text") or ""))
        d, v = await view_of(ips[0] if ips else None, None)
        row = {"impact": _txt(p.get("impact_title"), 120), "impact_type": _txt(p.get("impact_type"), 64), "name": _txt(p.get("name"), 300),
               "score": p.get("score"), "severity": _txt(p.get("severity"), 16), "where": _txt(p.get("affected_asset_text"), 300),
               "minutes_to_find": round(p["time_to_finding_s"] / 60) if isinstance(p.get("time_to_finding_s"), (int, float)) else None}
        if v is not None and len(v["attack_paths"]) < KEEP:
            v["attack_paths"].append(row)
        if row["impact_type"] in CRITICAL_IMPACTS or (p.get("score") or 0) >= 9:
            alerts.append((f"pentest_impact:{pentest.get('op_id')}:{p.get('uuid')}", "critical" if (p.get("score") or 0) >= 9 else "high",
                           f"NodeZero: {row['impact'] or 'impact'} via {row['name'] or 'an attack path'}",
                           {**row, "hostname": d.hostname if d else None, "asset_id": str(d.id) if d else None,
                            "pentest": pentest.get("name"), "tested_at": when.isoformat()}))
    for c in extra.get("creds") or []:
        d, v = await view_of(c.get("ip"), c.get("host_name"))
        row = {"user": _txt(c.get("user_name"), 128), "type": _txt(c.get("cred_type"), 48), "cracked": bool(c.get("is_cracked")),
               "proved": bool(c.get("has_proof")), "domain_admin": bool(c.get("is_domain_admin"))}
        if v is not None and len(v["credentials"]) < KEEP:
            v["credentials"].append(row)
        if row["domain_admin"]:
            alerts.append((f"pentest_domain_admin:{pentest.get('op_id')}:{c.get('uuid')}", "critical",
                           f"NodeZero obtained a domain admin credential ({row['user']}) on {c.get('host_name') or c.get('ip')}",
                           {**row, "hostname": d.hostname if d else c.get("host_name"), "asset_id": str(d.id) if d else None,
                            "pentest": pentest.get("name"), "tested_at": when.isoformat()}))
    for st in extra.get("stores") or []:
        d, v = await view_of(st.get("ip"), st.get("host_name"))
        if v is not None and len(v["data_stores"]) < KEEP:
            v["data_stores"].append({"name": _txt(st.get("name"), 300), "type": _txt(st.get("data_store_type"), 48), "port": st.get("port")})
    if views:
        from sqlalchemy import select

        from api.models.device import Device
        # In id order and in small batches, so other writers to the same assets (a directory or EDR upload) wait
        # briefly instead of deadlocking against one long transaction
        ids = sorted(views)
        for i in range(0, len(ids), 200):
            chunk = ids[i:i + 200]
            for d in (await db.execute(select(Device).where(Device.id.in_(chunk)).order_by(Device.id)
                                       .with_for_update())).scalars():
                old = d.pentest or {}
                if not old.get("tested_at") or old["tested_at"] <= views[str(d.id)]["tested_at"]:   # the newest pentest wins
                    d.pentest = views[str(d.id)]
            await db.commit()
    have = await existing(db, [a[0] for a in alerts])
    for key, sev, title, body in alerts:
        await _add(db, have, key, key.split(":", 1)[0], sev, title, body)
