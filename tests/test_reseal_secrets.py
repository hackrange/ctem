"""1.11.4 re-seals stored secrets in the bound envelope at start: an integration config, shipper secret,
authenticator secret, SSO settings or evidence key written before then can no longer be opened by copying it into
a column a scoped reader sees. Every value still reads the same afterwards."""
import os
import uuid
from base64 import b64encode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select, text


def _v1(plaintext: str) -> str:
    from api.core.encryption import _enc_key
    nonce = os.urandom(12)
    return b64encode(nonce + AESGCM(_enc_key()).encrypt(nonce, plaintext.encode(), None)).decode()


async def _raw(db, table, col, row_id):
    return (await db.execute(text(f"SELECT {col} FROM {table} WHERE id = :i"), {"i": row_id})).scalar()  # nosec B608 - test constants


async def _set_raw(db, table, col, row_id, value):
    await db.execute(text(f"UPDATE {table} SET {col} = :v WHERE id = :i"), {"v": value, "i": row_id})  # nosec B608 - test constants
    await db.commit()


async def _config(db, value):
    from api.models.integration import IntegrationConfig, Vendor
    ic = IntegrationConfig(vendor=next(iter(Vendor)), name=f"t-{uuid.uuid4().hex[:6]}", config={"x": 1})
    db.add(ic)
    await db.commit()
    await _set_raw(db, "integration_configs", "config", ic.id, value)
    return ic.id


async def _clear_settings(db):
    await db.execute(text("DELETE FROM app_settings WHERE key IN ('sso.oidc', 'grc_evidence_signing_key')"))
    await db.commit()


async def _device(db):
    from api.models.device import Device
    dev = Device(hostname=f"h-{uuid.uuid4().hex[:6]}", ip="10.0.0.9")
    db.add(dev)
    await db.commit()
    return dev.id


async def _device_ip_after_copy(db, stored, dev_id):
    from api.models.device import Device
    await _set_raw(db, "devices", "ip", dev_id, stored)
    db.expire_all()
    return (await db.execute(select(Device).where(Device.id == dev_id))).scalar_one().ip


async def test_old_integration_secret_copied_into_a_device_column_stays_shut_after_start(db):
    """The attack: DB write access, copy a v1 config into devices.ip, read it back as a scoped user."""
    from api.core.reseal import reseal_secrets
    ic_id = await _config(db, _v1('{"api_key": "s3cret"}'))
    dev_id = await _device(db)
    assert await _device_ip_after_copy(db, await _raw(db, "integration_configs", "config", ic_id), dev_id) \
        == '{"api_key": "s3cret"}'   # before: it opens
    assert await reseal_secrets(db) >= 1
    stored = await _raw(db, "integration_configs", "config", ic_id)
    assert stored.startswith("e2:")
    assert await _device_ip_after_copy(db, stored, dev_id) is None


async def test_values_read_the_same_after_reseal(db, admin_user):
    from api.auth import sso_config
    from api.core.encryption import decrypt, encrypt
    from api.core.reseal import reseal_secrets
    from api.grc import evidence
    from api.models.collector import CollectorSecret
    from api.models.integration import IntegrationConfig
    from api.models.settings import AppSetting
    from api.models.user import User
    uid = admin_user.id
    await _clear_settings(db)
    ic_id = await _config(db, _v1('{"api_key": "k", "n": [1, 2]}'))
    legacy_id = await _config(db, '{"plain": true}')
    cs = CollectorSecret(profile_id=str(uuid.uuid4()), kind="k", field="f", envelope="x", key_fp="fp")
    db.add(cs)
    await db.flush()
    cs_id = cs.id
    db.add(AppSetting(key=sso_config.SETTING_KEY, is_sensitive=True, value=_v1('{"client_id": "c"}')))
    db.add(AppSetting(key=evidence.KEY_SETTING, is_sensitive=True, value=_v1('{"private": "AAAA"}')))
    await db.commit()
    await _set_raw(db, "collector_secrets", "envelope", cs_id, _v1('{"sealed": "box"}'))
    inner = encrypt("JBSWY3DPEHPK3PXP")   # how sign-in stores it: a bare encrypt() inside the column
    await _set_raw(db, "users", "totp_secret", uid, _v1(inner))

    assert await reseal_secrets(db) >= 6
    for table, col, rid in (("integration_configs", "config", ic_id), ("integration_configs", "config", legacy_id),
                            ("collector_secrets", "envelope", cs_id), ("users", "totp_secret", uid)):
        assert (await _raw(db, table, col, rid)).startswith("e2:")
    db.expire_all()
    assert (await db.get(IntegrationConfig, ic_id)).config == {"api_key": "k", "n": [1, 2]}
    assert (await db.get(IntegrationConfig, legacy_id)).config == {"plain": True}
    assert (await db.get(CollectorSecret, cs_id)).envelope == '{"sealed": "box"}'
    assert decrypt((await db.get(User, uid)).totp_secret) == "JBSWY3DPEHPK3PXP"
    assert await sso_config.load_raw(db) == {"client_id": "c"}
    for key in (sso_config.SETTING_KEY, evidence.KEY_SETTING):
        v = (await db.execute(select(AppSetting.value).where(AppSetting.key == key))).scalar()
        assert v.startswith("e2:")
    assert await reseal_secrets(db) == 0   # nothing left to do on the next start


async def test_values_that_do_not_open_are_left_alone(db):
    from api.core.reseal import reseal_secrets
    from api.models.settings import AppSetting
    await _clear_settings(db)
    forged = b64encode(os.urandom(64)).decode()
    ic_id = await _config(db, forged)
    db.add(AppSetting(key="sso.oidc", is_sensitive=True, value="not encrypted"))
    other = AppSetting(key=f"other.{uuid.uuid4().hex[:6]}", is_sensitive=True, value=_v1("leave me"))
    db.add(other)
    await db.commit()
    await reseal_secrets(db)
    assert await _raw(db, "integration_configs", "config", ic_id) == forged
    assert (await db.execute(select(AppSetting.value).where(AppSetting.key == "sso.oidc"))).scalar() == "not encrypted"
    assert not (await db.execute(select(AppSetting.value).where(AppSetting.key == other.key))).scalar().startswith("e2:")


async def test_a_row_changed_since_it_was_read_is_not_overwritten(db):
    from api.core.reseal import _swap
    from api.models.integration import IntegrationConfig
    ic_id = await _config(db, _v1('{"a": 1}'))
    col = IntegrationConfig.__table__.c.config
    assert await _swap(db, col, ic_id, "something else", "e2:new") == 0
    await db.commit()
    assert not (await _raw(db, "integration_configs", "config", ic_id)).startswith("e2:")


async def test_reseal_keeps_when_the_row_was_last_changed(db):
    from api.core.reseal import reseal_secrets
    ic_id = await _config(db, _v1('{"a": 2}'))
    await db.execute(text("UPDATE integration_configs SET updated_at = '2020-01-02 03:04:05' WHERE id = :i"), {"i": ic_id})
    await db.commit()
    await reseal_secrets(db)
    assert (await _raw(db, "integration_configs", "config", ic_id)).startswith("e2:")
    assert str(await _raw(db, "integration_configs", "updated_at", ic_id)).startswith("2020-01-02 03:04:05")
