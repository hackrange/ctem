"""After a restore, prove this server's keys open the restored data."""
# python -m api.maintenance.restore_check     exits 1 when the keys don't match the data
from __future__ import annotations

import asyncio
import sys
from base64 import b64decode

from sqlalchemy import Text, select, type_coerce
from sqlalchemy.ext.asyncio import create_async_engine

from api.core.config import get_settings
from api.core.encryption import EncryptedJSON, EncryptedString, decrypt

_SAMPLE = 20


def _looks_sealed(value: str) -> bool:
    # nonce + GCM tag alone is 28 bytes; legacy plaintext rows rarely decode to that
    try:
        return len(b64decode(value, validate=True)) >= 28
    except ValueError:
        return False


def _columns():
    from api.models.base import Base
    for mod in ("user", "device", "vuln", "risk", "integration", "tag", "settings", "identity", "collector", "grc",
                "rules", "dashboard", "tag_role", "user_access", "software", "edr_policy", "alert_feed", "hunt_data",
                "cloud", "utilization", "snapshot"):
        __import__(f"api.models.{mod}")
    for table in Base.metadata.sorted_tables:
        for col in table.columns:
            if isinstance(col.type, (EncryptedString, EncryptedJSON)):
                yield col


async def run() -> tuple[int, int]:
    engine = create_async_engine(get_settings().database_url)
    opened = failed = 0
    try:
        async with engine.connect() as conn:
            for col in _columns():
                # read as plain text so the column type doesn't quietly decrypt (or pass through) for us
                raw_col = type_coerce(col, Text())
                sql = select(raw_col).where(col.isnot(None)).limit(_SAMPLE)
                for (raw,) in (await conn.execute(sql)).all():
                    if not isinstance(raw, str) or not _looks_sealed(raw):
                        continue
                    try:
                        decrypt(raw)
                        opened += 1
                    except Exception:  # noqa: BLE001
                        failed += 1
    finally:
        await engine.dispose()
    return opened, failed


def main() -> int:
    opened, failed = asyncio.run(run())
    print(f"encrypted values checked: {opened + failed}, opened: {opened}, failed: {failed}")
    if failed > max(2, (opened + failed) // 20):
        print("The encryption keys in .env do not match the restored data.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
