#!/usr/bin/env bash
# open-ctem upgrade: fetch the latest code and redeploy a running install. Author: Tim Rice <tim.j.rice@hackrange.com>
#
#   sudo ./upgrade.sh            show what's new, wait for running syncs to finish, then back up, pull, rebuild, restart
#   sudo ./upgrade.sh --check    only say whether an update is available (changes nothing)
#   sudo ./upgrade.sh --now      don't wait for running syncs (they are cut off and run again on schedule)
#   sudo ./upgrade.sh --wait N   wait at most N minutes for running syncs (default 30), then stop without upgrading
#
# The upgrade itself is install.sh --upgrade: an encrypted backup first, a fast-forward pull, a rebuild of the app,
# worker and beat images, a health check, and a rollback to the previous code if the new version doesn't come up.
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/installer/common.sh
source "${INSTALL_DIR}/scripts/installer/common.sh"

CHECK=0 NOW=0 WAIT_MIN=30
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK=1; shift ;;
    --now) NOW=1; shift ;;
    --wait) [[ "${2:-}" =~ ^[0-9]{1,4}$ ]] || die "--wait needs a number of minutes"; WAIT_MIN="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
done
[[ $EUID -eq 0 ]] || die "Run as root: sudo ./upgrade.sh"
cd "$INSTALL_DIR"
[[ -d .git && -f "$ENV_FILE" ]] || die "No open-ctem install at ${INSTALL_DIR}. Run install.sh for a fresh install."

say "Checking for updates..."
BRANCH=$(git rev-parse --abbrev-ref HEAD)
git fetch --quiet origin "$BRANCH" || die "Could not reach origin to check for updates."
HERE=$(git rev-parse HEAD)
THERE=$(git rev-parse "origin/${BRANCH}")
if [[ "$HERE" == "$THERE" ]]; then
  ok "Already up to date (${HERE:0:8})."
  exit 0
fi
git merge-base --is-ancestor "$HERE" "$THERE" || die "This checkout has commits origin doesn't. Merge by hand, then re-run."
NEW=$(git rev-list --count "${HERE}..${THERE}")
ok "${NEW} update(s) available: ${HERE:0:8} -> ${THERE:0:8}"
git log --oneline "${HERE}..${THERE}" | head -30 | sed 's/^/     /'
if git diff --quiet "${HERE}" "${THERE}" -- CHANGELOG.md; then :; else
  hint "What's new: git -C ${INSTALL_DIR} diff ${HERE:0:8} ${THERE:0:8} -- CHANGELOG.md"
fi
[[ $CHECK -eq 1 ]] && exit 0

# Integration syncs hold a lock in Redis while they run; restarting the worker mid-sync would cut one off
running_syncs() {
  local pw
  pw=$(env_get REDIS_PASSWORD)
  _compose exec -T -e REDISCLI_AUTH="$pw" redis redis-cli --no-auth-warning --scan --pattern 'sync_lock:*' 2>/dev/null | grep -c . || true
}
if [[ $NOW -eq 0 ]] && _compose ps --status running --services 2>/dev/null | grep -qx redis; then
  deadline=$(( $(date +%s) + WAIT_MIN * 60 ))
  while :; do
    n=$(running_syncs)
    [[ "${n:-0}" -eq 0 ]] && { ok "No integration syncs running."; break; }
    if [[ $(date +%s) -ge $deadline ]]; then
      die "${n} sync(s) still running after ${WAIT_MIN} minutes. Re-run later, or use --now."
    fi
    say "Waiting for ${n} running sync(s) to finish (up to ${WAIT_MIN} minutes; --now skips this)..."
    sleep 20
  done
fi

exec bash "${INSTALL_DIR}/install.sh" --upgrade
