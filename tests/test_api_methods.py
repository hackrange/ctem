"""Tenants are read, never changed: AWS runs only allow-listed read actions, Rapid7 only its approved searches."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from api.cloud import aws

_ROOT = Path(__file__).resolve().parents[1]


def _camel(snake: str) -> str:
    return "".join(p.capitalize() for p in snake.split("_"))


def test_every_aws_action_in_the_code_is_on_the_read_only_list():
    src = (_ROOT / "api/cloud/aws.py").read_text()
    used = set(re.findall(r"\.(describe_[a-z_]+|get_caller_identity|assume_role)\(", src))
    used |= set(re.findall(r"_pages\(\w+, \"([a-z_]+)\"", src))
    assert used and {_camel(u) for u in used} <= aws.READ_ONLY
    assert not any(a.startswith(("Create", "Delete", "Modify", "Put", "Terminate", "Stop", "Start", "Update"))
                   for a in aws.READ_ONLY)


def test_aws_refuses_a_write_before_sending_anything():
    s = aws._session({"access_key_id": "AKIAEXAMPLENOTREAL00", "secret_access_key": "example-not-a-secret"})
    ec2 = s.client("ec2", region_name="us-east-1")
    with pytest.raises(PermissionError, match="TerminateInstances"):
        ec2.terminate_instances(InstanceIds=["i-0example"])


def _methods(path: str) -> set[tuple[str, str]]:
    """(method, url-ish) pairs a connector sends, read from its source."""
    src = (_ROOT / path).read_text()
    return {(m.upper(), u) for m, u in re.findall(r"client\.(post|put|patch|delete)\(\s*(f?\"[^\"]*\")", src)}


@pytest.mark.parametrize("path,allowed", [
    ("api/integrations/rapid7_insightvm.py", {("POST", 'f"{self._v4}/assets"'), ("POST", 'f"{self._v4}/vulnerabilities"')}),
    ("api/integrations/rapid7_appsec.py", {("POST", 'f"{self._base}/search"')}),
    ("api/integrations/rapid7_insightvm_console.py", set()),
    ("api/integrations/rapid7_cloudsec.py", set()),
    ("api/cloud/oci.py", set()),
])
def test_rapid7_and_oci_send_only_approved_non_get_calls(path, allowed):
    assert _methods(path) <= allowed, "a new non-GET call to this vendor needs the owner's sign-off first"
    if "self.client.post" in (_ROOT / path).read_text() or "_sign(\"POST\"" in (_ROOT / path).read_text():
        pytest.fail("OCI must stay GET only")
