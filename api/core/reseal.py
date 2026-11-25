"""Re-seal stored secrets in the bound (v2) envelope.

A v1 value has no associated data, so whoever can write to the database could copy a v1 integration config, shipper
secret or authenticator secret into a column a scoped reader sees, and it would open there. Once writes are v2, this
rewrites the secret-bearing values that are still v1 (or legacy plaintext) so they open only in their own column.

Runs at every app start and touches only values not yet v2: the tables are small, and a v1 value written meanwhile
by a process still on 1.11.3 is picked up next time. Older copies (an earlier dump or backup) are still v1 and still
open in unbound columns: rotate a credential if such a copy may have leaked. The two app settings are sealed as bare
values, so they are bound to that kind, not to their key. Each row is checked to open again before it is written, and
written only if nobody changed it since it was read. A value that doesn't open is left alone and logged."""
from __future__ import annotations

import logging

from sqlalchemy import Text, bindparam, select, text, type_coerce, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.core import encryption as enc

log = logging.getLogger("open-ctem.reseal")


def _columns():
    from api.models.collector import CollectorSecret
    from api.models.integration import IntegrationConfig
    from api.models.user import User
    return ((IntegrationConfig, "config"), (CollectorSecret, "envelope"), (User, "totp_secret"))


def _setting_keys() -> tuple[str, ...]:
    """App settings that hold a bare encrypt() value of a secret."""
    from api.auth.sso_config import SETTING_KEY
    from api.grc.evidence import KEY_SETTING
    return (SETTING_KEY, KEY_SETTING)


def _plain(stored: str, *, legacy_ok: bool) -> str | None:
    """The plaintext of a v1 value (or of legacy plaintext, where allowed); None when it should be left alone."""
    if stored.startswith(enc._V2):
        return None
    if not enc.looks_sealed(stored):
        return stored if legacy_ok else None
    try:
        return enc.decrypt(stored)
    except Exception:  # noqa: BLE001 - not ours to fix here; it stays refused when read
        return None


async def _swap(db: AsyncSession, col, row_id, old: str, new: str) -> int:
    raw = type_coerce(col, Text)
    values = {col.key: bindparam("new", new, type_=Text)}
    if "updated_at" in col.table.c:
        values["updated_at"] = col.table.c.updated_at   # same value, not "changed by someone at upgrade time"
    res = await db.execute(update(col.table).where(col.table.c.id == row_id, raw == bindparam("old", old, type_=Text))
                           .values(values))
    return res.rowcount or 0


async def reseal_secrets(db: AsyncSession) -> int:
    """Rewrite secret-bearing v1 / plaintext values as v2. Returns how many rows were rewritten."""
    if not enc.WRITE_V2:
        return 0
    done = skipped = 0
    if (await db.connection()).dialect.name == "postgresql":
        # runs before the app answers health checks: give up (and retry next start) rather than wait on a busy row
        await db.execute(text("SET LOCAL lock_timeout = '5s'"))
        await db.execute(text("SET LOCAL statement_timeout = '60s'"))
    for model, name in _columns():
        col = model.__table__.c[name]
        rows = (await db.execute(select(col.table.c.id, type_coerce(col, Text)).where(col.isnot(None)))).all()
        for row_id, stored in rows:
            plain = _plain(stored, legacy_ok=True)
            if plain is None:
                skipped += not stored.startswith(enc._V2)
                continue
            new = col.type._seal(plain)
            if col.type.open(new) != plain:   # never write a value that wouldn't read back
                skipped += 1
                continue
            done += await _swap(db, col, row_id, stored, new)
    from api.models.settings import AppSetting
    vcol = AppSetting.__table__.c.value
    rows = (await db.execute(select(AppSetting.id, vcol).where(AppSetting.key.in_(_setting_keys()),
                                                                vcol.isnot(None)))).all()
    for row_id, stored in rows:
        plain = _plain(stored, legacy_ok=False)
        if plain is None:
            skipped += not stored.startswith(enc._V2)
            continue
        new = enc.encrypt(plain)
        if enc.decrypt(new) != plain:
            skipped += 1
            continue
        done += await _swap(db, vcol, row_id, stored, new)
    await db.commit()
    if done or skipped:
        log.info("re-sealed %d stored secrets in the bound envelope; %d left as they were", done, skipped)
    return done
