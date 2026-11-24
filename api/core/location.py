"""Where each asset probably is: office, city and state, with the evidence and how sure CTEM is.

An asset's own evidence comes first: the EDR's AD site for it, its assigned person's office, and the offices of the
people who sign in to it. An AD site learns its city and state from the people signing in at its machines. Then the
neighborhood: assets on one /24 (a /64 for IPv6) are almost always one site, and assets reaching the internet from one
public address leave from the same place. An asset with nothing of its own (a camera only a pentest found) takes its
neighborhood's answer, at a lower confidence. Evidence is kept as counts, never names, and encrypted."""
from __future__ import annotations

import ipaddress
import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone

from sqlalchemy import select, update

from api.core.ssrf import INTERNAL_NETS as _INTERNAL   # internal address space: a /24 there is one site

log = logging.getLogger("open-ctem.location")
SITE_W, OWNER_W, SIGNIN_W, MAX_PEOPLE = 3, 3, 2, 5
AGREE = 0.6   # share of a neighborhood's votes the winner needs




def subnet_of(ip: str | None) -> str | None:
    """The /24 (IPv4) or /64 (IPv6) an internal address sits in; None for public or junk addresses."""
    try:
        a = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return None
    if not any(a.version == n.version and a in n for n in _INTERNAL):
        return None
    return str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 64}", strict=False))


def _place(city, state) -> str | None:
    city, state = (city or "").strip(), (state or "").strip()
    return f"{city}, {state}" if city and state else city or state or None


class _Votes:
    """Weighted votes per dimension: AD site, office, and "City, ST"."""

    def __init__(self):
        self.site, self.office, self.place = Counter(), Counter(), Counter()

    def add(self, other: "_Votes"):
        self.site.update(other.site)
        self.office.update(other.office)
        self.place.update(other.place)

    def empty(self) -> bool:
        return not (self.site or self.office or self.place)


def _winner(c: Counter, need: float = 0.0):
    if not c:
        return None, 0.0
    top, n = c.most_common(1)[0]
    share = n / sum(c.values())
    return (top, share) if share >= need else (None, share)


async def recompute(db) -> int:
    """Infer every asset's location and store it. Returns how many changed."""
    from api.core.encryption import search_hash
    from api.core.user_match import UserIndex
    from api.models.device import Device, DeviceAssignment, HIDDEN_BY_DEFAULT
    from api.models.user import User

    people = await UserIndex.load(db)
    where_works = {}   # user id -> (office, "City, ST")
    for u in (await db.execute(select(User).where(User.is_local.is_(False)))).scalars():
        office, place = (u.office or "").strip() or None, _place(u.city, u.state)
        if office or place:
            where_works[u.id] = (office, place)
    assigned = dict((await db.execute(select(DeviceAssignment.device_id, DeviceAssignment.user_id)
                                      .where(DeviceAssignment.user_id.is_not(None)))).all())
    devs = (await db.execute(select(Device).where(Device.device_type.not_in(HIDDEN_BY_DEFAULT)))).scalars().all()

    own: dict[str, _Votes] = {}
    why: dict[str, list[str]] = defaultdict(list)
    site_places: dict[str, Counter] = defaultdict(Counter)
    for d in devs:
        v = _Votes()
        if d.edr_site:
            v.site[d.edr_site] += SITE_W
            why[d.id].append(f"AD site {d.edr_site} (from the EDR)")
        owner = assigned.get(d.id) or d.owner_user_id
        if owner in where_works:
            o, p = where_works[owner]
            if o:
                v.office[o] += OWNER_W
            if p:
                v.place[p] += OWNER_W
            why[d.id].append(f"its owner works at {' in '.join(x for x in (o, p) if x)}")
        names = [d.last_login_user, *((d.recent_logins or []) if isinstance(d.recent_logins, list) else [])]
        signers = {uid for uid in (people.resolve(n)[0] for n in names if n) if uid and uid != owner}
        offices = Counter()
        for uid in list(signers)[:MAX_PEOPLE]:
            if uid in where_works:
                o, p = where_works[uid]
                if o:
                    v.office[o] += SIGNIN_W
                if p:
                    v.place[p] += SIGNIN_W
                offices[p or o] += 1
        if offices:
            top, n = offices.most_common(1)[0]
            why[d.id].append(f"{n} of {sum(offices.values())} people who sign in here work in {top}")
        if d.edr_site and v.place:
            site_places[d.edr_site].update(v.place)
        own[d.id] = v

    # An AD site's city: what its machines' people say, everywhere CTEM sees that site
    site_city = {s: _winner(c, AGREE)[0] for s, c in site_places.items()}
    for d in devs:
        v = own[d.id]
        site, _ = _winner(v.site)
        if site and not v.place and site_city.get(site):
            v.place[site_city[site]] += SITE_W
            why[d.id].append(f"AD site {site} is in {site_city[site]} (from the people who sign in at its machines)")

    by_net, by_pub = defaultdict(list), defaultdict(list)
    nets = {}
    for d in devs:
        nets[d.id] = subnet_of(d.ip)
        if nets[d.id]:
            by_net[nets[d.id]].append(d.id)
        if d.public_ip_hash:
            by_pub[d.public_ip_hash].append(d.id)

    def pooled(ids, me):
        v, n = _Votes(), 0
        for i in ids:
            if i != me and not own[i].empty():
                v.add(own[i])
                n += 1
        return v, n

    changed, now = 0, datetime.now(timezone.utc)
    for d in devs:
        v, confidence, reasons = own[d.id], None, list(why[d.id])
        site, s_share = _winner(v.site)
        office, _ = _winner(v.office)
        place, p_share = _winner(v.place)
        if site or office or place:
            confidence = "high" if (site and place) or (place and p_share >= 0.75 and sum(v.place.values()) >= 2 * SIGNIN_W) else "medium"
        for label, group in ((f"its subnet {nets[d.id]}", by_net.get(nets[d.id]) or []),
                             ("its public internet address", by_pub.get(d.public_ip_hash) or [])):
            if (site and office and place) or len(group) < 2:
                continue
            nv, n = pooled(group, d.id)
            if not n:
                continue
            got = False
            for dim, cur in (("site", site), ("office", office), ("place", place)):
                if cur:
                    continue
                top, share = _winner(getattr(nv, dim), AGREE)
                if top:
                    if dim == "site":
                        site = top
                    elif dim == "office":
                        office = top
                    else:
                        place = top
                    got = True
            if got:
                agree = place or office or site
                reasons.append(f"{n} other asset{'s' if n != 1 else ''} on {label} point to {agree}")
                confidence = confidence or ("medium" if n >= 3 else "low")
        vals = {"loc_site": (site or None) and site[:128], "loc_office": (office or None) and office[:128],
                "loc_city": place.split(", ")[0][:128] if place else None,
                "loc_state": place.split(", ")[1][:64] if place and ", " in place else None,
                "loc_confidence": confidence, "subnet_hash": search_hash(nets[d.id]) if nets[d.id] else None}
        if any(getattr(d, k) != val for k, val in vals.items()) or (d.loc_evidence or []) != reasons[:8]:
            await db.execute(update(Device).where(Device.id == d.id).values(
                **vals, loc_evidence=reasons[:8] or None, loc_at=now).execution_options(synchronize_session=False))
            changed += 1
            if changed % 500 == 0:
                await db.commit()
    await db.commit()
    log.info("location: %d assets changed of %d", changed, len(devs))
    return changed
