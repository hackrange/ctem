"""What Persona checked in an identity verification, why one needs a person's decision, and what to look at first.

Persona runs a verification per thing the person presents: a government ID (driver's license, passport, national ID,
...), a selfie, sometimes a document or a database lookup. Each runs dozens of named checks that pass, fail, or don't
apply. CTEM keeps only that outline: the kind of verification, its status, the ID's type, country and how it was
captured, and each check's name, status and reason codes. Never the name, birth date, ID number, address or photos
on the ID; when an approver must compare the name, it is read from Persona live and shown, never kept
(api/routes/idv.py, /names)."""
from __future__ import annotations

import re

_NAME = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_KIND = re.compile(r"^verification/([a-z][a-z0-9\-]{2,40})$")
_COUNTRY = re.compile(r"^[A-Z]{2}$")
_WORD = re.compile(r"^[A-Za-z0-9 _.\-]{1,40}$")

# Only these attributes are asked for, per kind of verification (sparse fieldsets): no names, numbers or photos
VERIFICATION_FIELDS = {
    "verification/government-id": "status,country-code,id-class,capture-method,checks,completed-at",
    "verification/government-id-nfc": "status,country-code,id-class,checks,completed-at",
    "verification/selfie": "status,capture-method,checks,completed-at",
    "verification/document": "status,checks,completed-at",
    "verification/database": "status,checks,completed-at",
    "verification/database-standard": "status,checks,completed-at",
    "verification/aamva": "status,checks,completed-at",
    "verification/phone-number": "status,checks,completed-at",
    "verification/email-address": "status,checks,completed-at",
}
KIND_LABEL = {"government-id": "Government ID", "government-id-nfc": "Government ID (chip read)", "selfie": "Selfie",
              "document": "Document", "database": "Database lookup", "database-standard": "Database lookup",
              "aamva": "DMV record lookup", "phone-number": "Phone number", "email-address": "Email address"}

# name -> (what failing means, what the approver should validate before approving)
CHECKS = {
    "id_electronic_replica_detection": ("The ID looks like a photo of a screen or a printout, not the physical card.",
        "Ask the person to show the physical ID on a live video call; a picture of a picture is a common fraud pattern."),
    "id_inquiry_comparison": ("The name or birth date on the ID doesn't match what the person's account says.",
        "Compare the name on the ID with the directory (Show the name on the ID). Approve only for a known variation: "
        "nickname, married name, middle name, transliteration."),
    "id_account_comparison": ("The ID doesn't match the details already on the person's Persona account.",
        "Compare the name on the ID with the directory, and confirm with the person's manager."),
    "id_expired_detection": ("The ID is expired.", "Ask for a current ID; an expired one isn't proof of identity."),
    "id_tamper_detection": ("The ID shows signs of digital editing.", "Decline unless the person verifies again with the physical ID on a video call."),
    "id_physical_tamper_detection": ("The ID looks physically altered.", "Ask to see the ID on a video call; decline if it is altered."),
    "id_fabrication_detection": ("The ID looks fabricated.", "Treat as suspected fraud: decline and escalate to security."),
    "id_compromised_detection": ("This ID image is known from other fraud attempts.", "Treat as suspected fraud: decline and escalate to security."),
    "id_repeat_detection": ("The same ID was used in other verifications.", "Check whether those were this person's own retries (normal) or another person's."),
    "id_inconsistent_repeat_detection": ("The same ID appeared before with different details.", "Treat as suspected fraud unless the person explains it."),
    "id_public_figure_detection": ("The ID portrait looks like a public figure.", "Ask the person to verify on a video call."),
    "id_color_inconsistency_detection": ("The ID's colors look wrong (a black-and-white copy).", "Ask for the physical ID in color."),
    "id_double_side_detection": ("Only one side of a two-sided ID was captured.", "Ask the person to verify again with both sides."),
    "id_barcode_detection": ("The barcode on the back couldn't be read.", "Ask the person to verify again in better light."),
    "id_barcode_inconsistency_detection": ("The barcode doesn't match the front of the ID.", "Treat as a possible fake ID: decline unless verified on a video call."),
    "id_mrz_inconsistency_detection": ("The passport's machine-readable lines don't match the page.", "Treat as a possible fake passport."),
    "id_disallowed_country_detection": ("IDs from this country aren't accepted by the template.", "Confirm the person really works from there (HR record) before approving."),
    "id_disallowed_type_detection": ("This type of ID isn't accepted by the template.", "Ask for an accepted ID, like a driver's license or passport."),
    "id_portrait_detection": ("No face was found on the ID.", "Ask the person to verify again."),
    "id_portrait_clarity_detection": ("The face on the ID is unclear.", "Ask the person to verify again."),
    "id_extracted_properties_detection": ("Required details couldn't be read from the ID.", "Ask the person to verify again in better light."),
    "id_unprocessable_submission_detection": ("The ID image couldn't be processed.", "Ask the person to verify again."),
    "id_blur_detection": ("The ID photo is blurry.", "Ask the person to verify again."),
    "id_glare_detection": ("Glare covers part of the ID.", "Ask the person to verify again."),
    "id_age_comparison": ("The age on the ID doesn't fit the account.", "Compare with HR records."),
    "selfie_id_comparison": ("The selfie doesn't match the photo on the ID.", "Verify the person on a live video call against their ID."),
    "selfie_account_comparison": ("The selfie doesn't match the person's earlier verified selfie.", "Verify the person on a live video call."),
    "selfie_liveness_detection": ("The selfie may not be a live person (a photo, screen or mask).", "Verify on a live video call."),
    "selfie_suspicious_entity_detection": ("The selfie matches a face seen in fraud attempts.", "Treat as suspected fraud: decline and escalate to security."),
    "selfie_multiple_faces_detection": ("More than one face was in the selfie.", "Ask the person to verify again alone."),
    "selfie_public_figure_detection": ("The selfie looks like a public figure.", "Verify on a live video call."),
    "selfie_face_covering_detection": ("The face was covered.", "Ask the person to verify again."),
    "selfie_pose_detection": ("The selfie poses weren't followed.", "Ask the person to verify again."),
    "selfie_pose_repeat_detection": ("The same selfie frame was reused.", "Treat as a possible replayed video: verify on a live call."),
}
# Checks worth showing even when they pass, because they answer "is this really the person?"
KEY = {"selfie_id_comparison", "selfie_account_comparison", "selfie_liveness_detection", "id_inquiry_comparison",
       "id_electronic_replica_detection", "id_expired_detection", "id_tamper_detection"}
ID_CLASS = {"dl": "Driver's license", "pp": "Passport", "id": "National ID card", "rp": "Residence permit",
            "pr": "Permanent residence card", "visa": "Visa", "mil": "Military ID", "wp": "Work permit",
            "ppc": "Passport card", "tribal": "Tribal ID", "nric": "National ID card", "myn": "National ID card",
            "cid": "Consular ID", "keyp": "Proof of age card", "ipp": "Internal passport"}


def _check(c: dict) -> list | None:
    name, status = str(c.get("name") or ""), str(c.get("status") or "")
    if not _NAME.match(name) or status not in ("passed", "failed", "not_applicable"):
        return None
    if status == "not_applicable" and (c.get("requirement") != "required" or name not in KEY):
        return None
    reasons = [str(r)[:40] for r in (c.get("reasons") or []) if isinstance(r, str) and _NAME.match(r)][:4]
    return [name, status, reasons]


def verification_facts(included: list) -> list[dict]:
    """Each verification's outline, oldest first: kind, status, ID type, country, capture method, and the checks
    that failed or matter (KEY). Nothing else in the verification is copied."""
    out = []
    for v in included or []:
        m = _KIND.match(str((v or {}).get("type") or "")) if isinstance(v, dict) else None
        if not m:
            continue
        a = v.get("attributes") or {}
        f = {"kind": m[1], "status": str(a.get("status") or "")[:20]}
        cls = str(a.get("id-class") or "").lower()
        if cls and _WORD.match(cls):
            f["id_class"], f["id_type"] = cls, ID_CLASS.get(cls, cls.upper())
        cc = str(a.get("country-code") or "").upper()
        if _COUNTRY.match(cc):
            f["country"] = cc
        cap = str(a.get("capture-method") or "")
        if cap and _WORD.match(cap):
            f["capture"] = cap[:20]
        at = str(a.get("completed-at") or "")[:32]
        if at:
            f["at"] = at
        f["checks"] = [c for c in (_check(x) for x in a.get("checks") or [] if isinstance(x, dict)) if c]
        out.append(f)
    return sorted(out, key=lambda f: f.get("at") or "")


def gov_id_passed(facts: dict | None) -> bool | None:
    """True: a government ID passed in this inquiry. False: none did. None: not read yet."""
    vs = (facts or {}).get("verifications")
    if vs is None:
        return None
    return any(v.get("kind", "").startswith("government-id") and v.get("status") == "passed" for v in vs)


def explain(facts: dict | None) -> dict:
    """For the approver: what was presented, which checks failed and what each means, and what to validate."""
    vs = (facts or {}).get("verifications") or []
    presented = [{"kind": KIND_LABEL.get(v["kind"], v["kind"]), "status": v.get("status"), "id_type": v.get("id_type"),
                  "country": v.get("country"), "capture": v.get("capture"), "at": v.get("at")} for v in vs]
    failed, seen = [], set()
    for v in vs:
        for name, status, reasons in v.get("checks") or []:
            if status == "failed" and name not in seen:
                seen.add(name)
                what, todo = CHECKS.get(name, (name.replace("_", " ").capitalize() + " failed.",
                                               "Look at this check in Persona before deciding."))
                failed.append({"check": name, "on": KIND_LABEL.get(v["kind"], v["kind"]), "reasons": reasons,
                               "means": what, "validate": todo})
    key = []
    for v in vs:
        for name, status, reasons in v.get("checks") or []:
            if name in KEY and status != "failed":
                key.append({"check": name, "on": KIND_LABEL.get(v["kind"], v["kind"]), "status": status, "reasons": reasons})
    gov = gov_id_passed(facts)
    notes = []
    if vs and gov is False and any(v["kind"] == "selfie" and v.get("status") == "passed" for v in vs):
        notes.append("Only a selfie passed: no government ID was verified in this check.")
    if vs and not any(v["kind"].startswith("government-id") for v in vs):
        notes.append("No government ID was presented.")
    if vs and gov is False and any(v["kind"].startswith("government-id") for v in vs):
        notes.append("Every government ID the person presented failed.")
    return {"presented": presented, "failed": failed, "passed_key_checks": key, "notes": notes, "read": bool(vs) or gov is not None}


# Why an approver approved, declined or revoked: a short list, plus their note
APPROVE_REASONS = {
    "video_call": "Verified the person and their ID on a live video call",
    "in_person": "Verified the person and their ID in person",
    "name_variation": "Name differs only by a known variation (nickname, married name, transliteration)",
    "false_positive": "Persona's failed check is a false positive (reviewed in Persona)",
    "manager_confirmed": "Identity confirmed by the person's manager and HR record",
}
DECLINE_REASONS = {
    "name_mismatch": "Name on the ID doesn't match the name in the directory",
    "replica": "ID shown on a screen or as a copy, not the physical document",
    "selfie_mismatch": "Selfie doesn't match the ID photo",
    "tampered": "ID looks altered or fake",
    "expired": "ID is expired",
    "unreadable": "ID unreadable or incomplete",
    "wrong_person": "Not the person the account belongs to",
    "no_response": "Person didn't respond to follow-up",
    "other": "Other (explained in the note)",
}
REVOKE_REASONS = {
    "fraud_suspected": "Suspected fraud or account takeover",
    "approved_in_error": "Approved in error",
    "selfie_only": "Verified by selfie only, never with a government ID",
    "identity_changed": "Legal name or identity details changed",
    "reverify_required": "Periodic re-verification required",
    "other": "Other (explained in the note)",
}
