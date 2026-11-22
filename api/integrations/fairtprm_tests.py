"""Send a control test attestation to FairTPRM.

The full record goes to POST /api/v2/grc/controls/{id}/tests (idempotent by source + external_ref). A FairTPRM
without that endpoint answers 404: then only what its control update already accepts is sent (last tested,
next due, effectiveness). Needs a read_write token. Every outcome is recorded on the test, never raised."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.grc")


def body(test, control) -> dict:
    return {"source": "open-ctem", "external_ref": str(test.id), "tested_at": test.tested_at.isoformat(),
            "tested_by": test.tested_by, "what_tested": test.what_tested, "expected_result": test.expected_result,
            "outcome": test.outcome, "result": test.result,
            "failure_reason": test.failure_reason if test.result == "fail" else None,
            "next_test_due": test.next_test_due.isoformat() if test.next_test_due else None,
            "frequency_days": test.frequency_days}


async def send(db: AsyncSession, test, control) -> tuple[str, str]:
    """(status, detail): sent, summary, failed or not_connected. Also stored on the test."""
    from api.core.ssrf import safe_client
    from api.integrations.fairtprm import FairTPRMConnector
    from api.models.integration import IntegrationConfig, Vendor
    status, detail = "failed", ""
    cfg = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.fairtprm,
                                                            IntegrationConfig.is_enabled.is_(True)))).scalars().first()
    if cfg is None:
        status, detail = "not_connected", "FairTPRM isn't connected (Settings > Integrations)."
    elif control.source != "fairtprm" or not str(control.external_id).isdigit():
        status, detail = "not_connected", "This control isn't from FairTPRM."
    else:
        conn = FairTPRMConnector(cfg.config or {})
        url = f"{conn._api}/grc/controls/{int(control.external_id)}"
        try:
            async with safe_client(timeout=20.0) as client:
                r = await client.post(f"{url}/tests", headers=conn._headers(), json=body(test, control))
                if r.status_code in (200, 201):
                    status, detail = "sent", "Recorded on the control in FairTPRM."
                elif r.status_code == 404:   # an older FairTPRM: send what its control update accepts
                    summary = {"last_tested_at": test.tested_at.strftime("%Y-%m-%d %H:%M:%S"),
                               "next_test_due": test.next_test_due.isoformat() if test.next_test_due else None,
                               "effectiveness": "effective" if test.result == "pass" else "ineffective"}
                    r2 = await client.put(url, headers=conn._headers(), json=summary)
                    if r2.status_code == 200:
                        status, detail = "summary", ("FairTPRM took the dates and effectiveness; it needs the control "
                                                     "tests update to keep the full record.")
                    else:
                        status, detail = "failed", _why(r2.status_code)
                else:
                    status, detail = "failed", _why(r.status_code)
        except Exception:  # noqa: BLE001 -- transport trouble; the test is kept in CTEM and can be sent again
            log.exception("FairTPRM control test for %s not sent", control.control_ref)
            status, detail = "failed", "Couldn't reach FairTPRM. The test is saved in CTEM; send it again later."
    test.fairtprm_status, test.fairtprm_detail = status, detail[:300]
    test.fairtprm_at = datetime.now(timezone.utc)
    return status, detail


def _why(code: int) -> str:
    if code in (401, 403):
        return "FairTPRM's token for CTEM is read-only. Give it read_write scope to send control tests."
    if code == 404:
        return "FairTPRM doesn't know this control any more."
    return f"FairTPRM didn't accept it (HTTP {code})."
