"""CrowdStrike alert updates made in CTEM: close, reopen, put in progress, classify (as a ctem_ tag) and comment.

Shared by CTEM (which builds the update) and the shipper (which checks it again before sending it on, never trusting
CTEM's word). Standard library only: the shipper runs this file as is. One update is one PATCH to
/alerts/entities/alerts/v3, which needs the API client's "Alerts: Write" scope. Nothing else in Falcon is ever changed.
"""
import re

PATH = "/alerts/entities/alerts/v3"
STATUSES = ("new", "in_progress", "reopened", "closed")
CLASSES = {"true_positive": "true positive", "false_positive": "false positive", "benign": "benign / expected"}
TAG_PREFIX = "ctem_"
COMMENT_MAX = 1000
MAX_IDS = 100
_CID = re.compile(r"^[A-Za-z0-9:_.-]{1,200}$")
_WHO = re.compile(r"^[^\x00-\x1f<>]{1,256}$")
_NAMES = {"update_status", "append_comment", "add_tag", "remove_tags_by_prefix"}


def clean_comment(v):
    """Up to COMMENT_MAX characters; line breaks and tabs are kept, other control characters are not allowed."""
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError("comment must be text")
    v = v.replace("\r\n", "\n").strip()
    if len(v) > COMMENT_MAX:
        raise ValueError(f"comment is longer than {COMMENT_MAX} characters")
    if any(ord(c) < 32 and c not in "\n\t" for c in v):
        raise ValueError("comment has control characters")
    return v or None


def describe(status=None, classification=None):
    bits = []
    if status:
        bits.append(f"status {status.replace('_', ' ')}")
    if classification:
        bits.append(f"classified {CLASSES[classification]}")
    return ", ".join(bits)


def body(composite_ids, status=None, classification=None, comment=None, who=""):
    """The PATCH body for one update. Raises ValueError on anything outside the allowed set."""
    ids = list(composite_ids or [])
    if not 1 <= len(ids) <= MAX_IDS or not all(isinstance(i, str) and _CID.match(i) for i in ids):
        raise ValueError("bad alert id")
    if status is not None and status not in STATUSES:
        raise ValueError("bad status")
    if classification is not None and classification not in CLASSES:
        raise ValueError("bad classification")
    comment = clean_comment(comment)
    if not (status or classification or comment):
        raise ValueError("nothing to change")
    if not isinstance(who, str) or not _WHO.match(who):
        raise ValueError("bad user name")
    ap = []
    if classification:   # Falcon removes tags before it adds them, so a new classification replaces the old one
        ap += [{"name": "remove_tags_by_prefix", "value": TAG_PREFIX}, {"name": "add_tag", "value": TAG_PREFIX + classification}]
    if status:
        ap.append({"name": "update_status", "value": status})
    what = describe(status, classification)
    note = f"{comment}\n\n-- {who} via open-ctem" + (f" ({what})" if what else "") if comment else f"{who} via open-ctem: {what}"
    ap.append({"name": "append_comment", "value": note[:COMMENT_MAX + 400]})
    return {"composite_ids": ids, "action_parameters": ap}


def check(b):
    """A body received from CTEM, checked again on the box: only the four actions above, with allowed values."""
    if not isinstance(b, dict) or set(b) != {"composite_ids", "action_parameters"}:
        raise ValueError("unexpected update shape")
    ids, ap = b["composite_ids"], b["action_parameters"]
    if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_IDS or not all(isinstance(i, str) and _CID.match(i) for i in ids):
        raise ValueError("bad alert id")
    if not isinstance(ap, list) or not 1 <= len(ap) <= 4:
        raise ValueError("unexpected actions")
    for a in ap:
        if not isinstance(a, dict) or set(a) != {"name", "value"} or a["name"] not in _NAMES or not isinstance(a["value"], str):
            raise ValueError("unexpected action")
        n, v = a["name"], a["value"]
        if (n == "update_status" and v not in STATUSES) or (n == "remove_tags_by_prefix" and v != TAG_PREFIX) \
                or (n == "add_tag" and v[len(TAG_PREFIX):] not in CLASSES) or (n == "add_tag" and not v.startswith(TAG_PREFIX)):
            raise ValueError(f"unexpected {n} value")
        if n == "append_comment" and (len(v) > COMMENT_MAX + 400 or any(ord(c) < 32 and c not in "\n\t" for c in v)):
            raise ValueError("unexpected comment")
    return b


def refused(status):
    """What to tell the person when Falcon says no."""
    if status == 403:
        return "CrowdStrike refused it (HTTP 403): the API client needs the Alerts: Write scope"
    if status == 404:
        return "CrowdStrike doesn't have this alert any more (HTTP 404)"
    if status == 429:
        return "CrowdStrike rate-limited the update (HTTP 429); try again in a minute"
    return f"CrowdStrike refused the update (HTTP {status})"


def run(api, ctem, integration_id, say=print):
    """Shipper side: take the queued updates for this box's CrowdStrike source, send each once, report back."""
    from collector_common import HttpError
    items = (ctem.call("GET", f"/api/v1/collector/alert-actions/{integration_id}") or {}).get("actions") or []
    results = []
    for it in items[:50]:
        aid = it.get("id") if isinstance(it, dict) else None
        if not isinstance(aid, str) or not re.match(r"^[0-9a-f-]{36}$", aid):
            continue
        try:
            api.write("PATCH", PATH, check(it.get("body")))
            results.append({"id": aid, "ok": True})
        except ValueError as e:
            results.append({"id": aid, "ok": False, "error": f"the shipper refused it: {e}"})
        except HttpError as e:
            results.append({"id": aid, "ok": False, "error": refused(e.status)})
        except Exception as e:  # noqa: BLE001 -- a network failure on one update is reported, the rest carry on
            results.append({"id": aid, "ok": False, "error": f"couldn't reach CrowdStrike ({type(e).__name__})"})
    if results:
        ctem.call("POST", f"/api/v1/collector/alert-actions/{integration_id}/results", {"results": results}, retries=3)
        say(f"alert updates: {sum(r['ok'] for r in results)} sent to CrowdStrike, {sum(not r['ok'] for r in results)} failed")
    return results
