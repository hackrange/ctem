# Security policy

open-ctem holds sensitive data (vulnerabilities, identities, credentials for the tools it connects to), so security
reports are welcome and taken seriously.

## Reporting a vulnerability

Please report it privately, never in a public issue:

- **GitHub:** use **Report a vulnerability** on the repository's **Security** tab (private vulnerability reporting), or
- **Email:** tim.j.rice@hackrange.com with the subject "open-ctem security".

Include what you found, the version (`app_version` in `api/core/config.py`, or the release you installed), how to reproduce it, and
what an attacker could do with it. If you have a proof of concept, describe it rather than running it against
someone else's installation.

You'll get an acknowledgement, and a fix is released as a new version with the change described in CHANGELOG.md.
Please give us a reasonable time to release the fix before telling anyone else.

## Supported versions

Fixes go into the latest release only. Keep installations current with `upgrade.sh`.

## What's in scope

The application in `api/`, the Docker deployment in `docker/`, the installer and upgrader scripts, and the on-prem
shipper (`api/collector/agent/`). Problems in the products open-ctem connects to (identity providers, EDR, scanners)
belong with those vendors.

## How releases are checked

Every release passes, before it ships: a secrets scan, static analysis (Bandit), a dependency audit (pip-audit), the
SBOM check (both `sbom.cdx.json` and `sbom-collector.cdx.json` match what ships), and the full automated test suite.
Base images are pinned to exact versions.
