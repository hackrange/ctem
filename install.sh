#!/usr/bin/env bash
# open-ctem installer, upgrader, backup and restore. Author: Tim Rice <tim.j.rice@hackrange.com>
#
# New server (Ubuntu 22.04 or newer):
#   curl -fsSL https://raw.githubusercontent.com/hackrange/ctem/main/get-ctem.sh | sudo bash
# New server, restored from a backup:
#   curl -fsSL https://raw.githubusercontent.com/hackrange/ctem/main/get-ctem.sh | sudo bash -s -- --restore /root/ctem.ctembak
#
# From a checkout: sudo ./install.sh [--restore FILE | --backup [--password] [--out DIR] | --upgrade | --maintenance-setup]
set -euo pipefail

# Piped in on its own (old one-liner)? Hand over to the bootstrapper, which clones the project first.
if [[ ! -f "${BASH_SOURCE[0]:-}" || ! -f "$(dirname "${BASH_SOURCE[0]}")/scripts/installer/common.sh" ]]; then
  curl -fsSL https://raw.githubusercontent.com/hackrange/ctem/main/get-ctem.sh | bash -s -- "$@"
  exit $?
fi

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/installer/common.sh
source "${INSTALL_DIR}/scripts/installer/common.sh"
# shellcheck source=scripts/installer/backup.sh
source "${INSTALL_DIR}/scripts/installer/backup.sh"
# shellcheck source=scripts/installer/restore.sh
source "${INSTALL_DIR}/scripts/installer/restore.sh"
# shellcheck source=scripts/installer/agent.sh
source "${INSTALL_DIR}/scripts/installer/agent.sh"

MODE=install RESTORE_FILE="" CUSTOM_PW=0 OUT_DIR=""
while (( $# )); do
  case "$1" in
    --upgrade|-u) MODE=upgrade; shift ;;
    --maintenance-setup) MODE=msetup; shift ;;
    --restore)    MODE=restore; [[ -n "${2:-}" ]] || die "--restore needs a backup file"
                  RESTORE_FILE=$(readlink -f -- "$2" 2>/dev/null || true); RESTORE_FILE=${RESTORE_FILE:-$2}; shift 2 ;;
    --backup)     MODE=backup; shift ;;
    --password)   CUSTOM_PW=1; shift ;;
    --out)        [[ -n "${2:-}" ]] || die "--out needs a directory"; OUT_DIR=$(realpath -m -- "$2"); shift 2 ;;
    -h|--help)
      cat <<'USAGE'
open-ctem installer

  install.sh                      Fresh install. Installs Docker and everything else it
                                  needs, generates every credential, starts the stack.
  install.sh --restore FILE       Install from a .ctembak backup (asks for its password).
                                  On a server that already runs open-ctem, replaces it
                                  with the backup after taking a safety backup.
  install.sh --backup             Encrypted full backup into ./backups, locked with
                                  BACKUP_ENCRYPTION_PASSWORD from .env.
  install.sh --backup --password  Same, but asks you for the password to lock it with.
             [--out DIR]          Write the backup somewhere else.
  install.sh --upgrade            Back up, pull the latest code, rebuild, restart.
  install.sh --maintenance-setup  (Re)install the agent behind Admin > Maintenance.

Unattended runs can set CTEM_BACKUP_PASSWORD and CTEM_RESTORE_CONFIRM=RESTORE.
USAGE
      exit 0 ;;
    *) die "Unknown option: $1  (try --help)" ;;
  esac
done
[[ "$MODE" == backup ]] || (( CUSTOM_PW == 0 )) || die "--password goes with --backup"
[[ "$MODE" == backup || -z "$OUT_DIR" ]] || die "--out goes with --backup"

require_root
cd "${INSTALL_DIR}"
[[ "$MODE" == install ]] || ensure_py_crypto

if [[ "$MODE" == msetup ]]; then
  setup_maintenance
  exit 0
fi
maintenance_lock

# ── Backup ────────────────────────────────────────────────────────────────────
if [[ "$MODE" == backup ]]; then
  do_backup "$CUSTOM_PW" "${OUT_DIR:-${INSTALL_DIR}/backups}"
  exit 0
fi

# ── Upgrade ───────────────────────────────────────────────────────────────────
if [[ "$MODE" == upgrade ]]; then
  say "open-ctem upgrade"
  [[ -d .git && -f "$ENV_FILE" ]] || die "No install at ${INSTALL_DIR}. Run without --upgrade for a fresh install."
  if ! git diff --quiet || ! git diff --cached --quiet; then
    warn "Uncommitted local changes found in ${INSTALL_DIR}."
    hint "Stash them first:  git -C ${INSTALL_DIR} stash"
    die "Upgrade aborted -- local changes are protected."
  fi
  missing=""
  while IFS='=' read -r key _rest; do
    [[ -n "$key" && "$key" != \#* && "$key" != BACKUP_ENCRYPTION_PASSWORD ]] || continue
    grep -q "^${key}=" "$ENV_FILE" || missing="${missing} ${key}"
  done < .env.example
  if [[ -n "$missing" ]]; then
    warn "New keys in .env.example are not yet in your .env -- add them manually:"
    for k in $missing; do hint "  $k"; done
  fi
  if [[ -z "$(env_get BACKUP_ENCRYPTION_PASSWORD)" ]]; then
    printf '\n# Locks the automatic backups. Keep a copy off this server.\nBACKUP_ENCRYPTION_PASSWORD=%s\n' "$(gen_backup_pw)" >> "$ENV_FILE"
    warn "Added BACKUP_ENCRYPTION_PASSWORD to .env. Copy it somewhere safe, off this server."
  fi

  BACKUP_FILE=""
  if _compose ps --status running --services 2>/dev/null | grep -qx db; then
    do_backup 0 "${INSTALL_DIR}/backups"   # dies on failure, so nothing gets upgraded without one
  else
    warn "Database container not running -- skipping the pre-upgrade backup."
  fi

  PRE_REV=$(git rev-parse HEAD)
  BRANCH=$(git rev-parse --abbrev-ref HEAD)
  say "Pulling latest code..."
  git fetch --quiet origin "${BRANCH}" || die "Could not fetch from origin."
  git pull --quiet --ff-only origin "${BRANCH}" || die "Could not fast-forward. Merge manually, then re-run."
  POST_REV=$(git rev-parse HEAD)
  [[ "$PRE_REV" != "$POST_REV" ]] || { ok "Already up to date."; exit 0; }
  ok "Code: ${PRE_REV:0:8} -> ${POST_REV:0:8}"
  git log --oneline "${PRE_REV}..${POST_REV}" | sed 's/^/     /'
  # the new code's own setup, so its compose mounts find their folders
  bash "${INSTALL_DIR}/install.sh" --maintenance-setup || warn "Admin > Maintenance agent setup failed; run --maintenance-setup later."

  say "Pulling base images and rebuilding the app..."
  _compose pull --quiet --ignore-buildable
  _compose build --pull || die "Build failed. Still running ${PRE_REV:0:8}; code is at ${POST_REV:0:8}."
  say "Restarting services..."
  _compose up -d --remove-orphans
  # compose doesn't always notice a rebuilt image on worker and beat, so make sure all of them run the new code
  _compose up -d --no-deps --force-recreate app worker beat
  if ! wait_healthy 300; then
    warn "App did not come up healthy. Rolling back code to ${PRE_REV:0:8}..."
    git checkout "${PRE_REV}" -- .
    _compose build && _compose up -d --remove-orphans && _compose up -d --no-deps --force-recreate app worker beat
    die "Upgrade rolled back. Backup: ${BACKUP_FILE:-none}"
  fi
  docker image prune -f &>/dev/null || true
  ok "open-ctem upgraded to ${POST_REV:0:8}"
  hint "Backup:  ${BACKUP_FILE:-none}"
  exit 0
fi

# ── Fresh install, or install from a backup ───────────────────────────────────
require_ubuntu
FRESH=1 RMODE=fresh
if [[ -f "$ENV_FILE" && "$MODE" == restore && -f "${INSTALL_DIR}/.restore-incomplete" ]]; then
  RMODE=resume
  warn "Picking up the restore that stopped partway; this server holds nothing else yet."
elif [[ -f "$ENV_FILE" ]]; then
  [[ "$MODE" == restore ]] || {
    warn "${ENV_FILE} already exists."
    hint "Upgrade:  sudo bash ${INSTALL_DIR}/install.sh --upgrade"
    hint "Restore:  sudo bash ${INSTALL_DIR}/install.sh --restore FILE"
    die "Aborting to protect your existing install."
  }
  FRESH=0 RMODE=inplace
fi

if [[ "$MODE" == restore ]]; then
  [[ -f "$RESTORE_FILE" && -r "$RESTORE_FILE" ]] || die "Backup file not found: ${RESTORE_FILE}"
  say "open-ctem $( (( FRESH )) && echo "install from backup" || echo "restore") --> ${INSTALL_DIR}"
else
  say "open-ctem fresh install --> ${INSTALL_DIR}"
fi

if [[ "$RMODE" != inplace ]]; then
  install_deps
  [[ "$RMODE" == resume ]] || check_ports
fi

if [[ "$MODE" == restore ]]; then
  if [[ "$RMODE" == fresh ]]; then
    need=$(( $(stat -c %s "$RESTORE_FILE") * 5 / 1024 + 4 * 1024 * 1024 ))
    have=$(df -Pk /var/lib/docker 2>/dev/null | awk 'NR == 2 { print $4 }')
    (( ${have:-0} > need )) || die "Not enough disk space: need about $((need / 1024 / 1024)) GB free for Docker."
  fi
  [[ "${CTEM_RESTORE_FROM_UI:-}" == 1 ]] || setup_maintenance
  do_restore "$RESTORE_FILE" "$RMODE"
  echo
  printf '%s  open-ctem is restored and running%s\n\n' "$c_ok" "$c_off"
  printf '  Web UI:   https://%s\n' "$(hostname -f 2>/dev/null || echo localhost)"
  hint "Sign in with the same accounts as the server the backup came from."
  if [[ "$RMODE" == inplace ]]; then
    hint "Settings, integrations and keys came from the backup; this server kept its database and Redis passwords."
  else
    hint "Settings, integrations and keys came from the backup. Database and Redis passwords are new."
  fi
  [[ "$RMODE" != inplace ]] || hint "The previous .env was kept as ${ENV_FILE}.pre-restore-*, and a safety backup is in ${INSTALL_DIR}/backups."
  hint "Logs:     docker compose -f ${COMPOSE_FILE} logs -f"
  echo
  exit 0
fi

say "Generating credentials..."
DB_PASS=$(genpass); REDIS_PASS=$(genpass); ADMIN_PASS=$(genpass); BACKUP_PASS=$(gen_backup_pw)
ADMIN_USER="admin"
umask 077
cat > "$ENV_FILE" <<ENV
# open-ctem -- generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Keep this file secure. Never commit it to version control.

# ── Database ──────────────────────────────────────────────────────────────────
DB_NAME=openctem
DB_USER=openctem
DB_PASSWORD=${DB_PASS}
DATABASE_URL=postgresql+asyncpg://openctem:${DB_PASS}@db:5432/openctem

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_PASSWORD=${REDIS_PASS}
REDIS_URL=redis://:${REDIS_PASS}@redis:6379/0

# ── Secrets ───────────────────────────────────────────────────────────────────
SECRET_KEY=$(genhex)
ENCRYPTION_KEY=$(genhex)
ENCRYPTION_SEARCH_KEY=$(genhex)

# ── Backups ───────────────────────────────────────────────────────────────────
# Locks backups made with install.sh --backup. Keep a copy off this server,
# or a lost server takes the only way into its backups with it.
BACKUP_ENCRYPTION_PASSWORD=${BACKUP_PASS}

# ── First-boot admin user ─────────────────────────────────────────────────────
INITIAL_ADMIN_USER=${ADMIN_USER}
INITIAL_ADMIN_PASS=${ADMIN_PASS}

# ── Authentication ────────────────────────────────────────────────────────────
AUTH_MODE=local_only
MFA_REQUIRED=false

# ── App ───────────────────────────────────────────────────────────────────────
APP_ENV=production
DEBUG=false
ALLOWED_HOSTS=localhost,127.0.0.1

ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# ── TOTP lockout ──────────────────────────────────────────────────────────────
TOTP_LOCKOUT_THRESHOLD_1=5
TOTP_LOCKOUT_MINUTES_1=5
TOTP_LOCKOUT_THRESHOLD_2=10
TOTP_LOCKOUT_MINUTES_2=30
TOTP_LOCKOUT_THRESHOLD_3=15

# ── Email ─────────────────────────────────────────────────────────────────────
EMAIL_MODE=disabled

# ── OIDC (enable later if you need SSO) ──────────────────────────────────────
# AUTH_MODE=both
# OIDC_ISSUER=https://auth.acme.example.com
# OIDC_CLIENT_ID=your-client-id
# OIDC_CLIENT_SECRET=your-client-secret
# OIDC_REDIRECT_URI=https://ctem.acme.example.com/auth/callback
ENV
chmod 600 "$ENV_FILE"
umask 022
ok ".env written and locked down (chmod 600)."

make_self_signed_cert
setup_maintenance

say "Pulling and building the containers (a few minutes)..."
_compose pull --quiet --ignore-buildable </dev/null || die "Could not pull the container images."
_compose build --pull --quiet </dev/null || die "Building the app image failed."
say "Starting open-ctem..."
_compose up -d --remove-orphans </dev/null
wait_healthy 300 || die "App did not respond. Check logs: docker compose -f ${COMPOSE_FILE} logs app"

echo
printf '%s╔══════════════════════════════════════════════════════╗%s\n' "$c_ok" "$c_off"
printf '%s║           open-ctem is ready                         ║%s\n' "$c_ok" "$c_off"
printf '%s╚══════════════════════════════════════════════════════╝%s\n' "$c_ok" "$c_off"
echo
printf '%s  Save these -- you will not see them again%s\n\n' "$c_warn" "$c_off"
printf '  Web UI:           https://%s\n' "$(hostname -f 2>/dev/null || echo localhost)"
printf '  Admin user:       %s\n' "${ADMIN_USER}"
printf '  Admin password:   %s\n' "${ADMIN_PASS}"
printf '  Backup password:  %s\n' "${BACKUP_PASS}"
echo
hint "Keep the backup password off this server; backups cannot be opened without it."
hint "Backups:   Admin > Maintenance, or sudo bash ${INSTALL_DIR}/install.sh --backup"
hint "Upgrade:   sudo bash ${INSTALL_DIR}/install.sh --upgrade"
hint "Logs:      docker compose -f ${COMPOSE_FILE} logs -f"
hint "Creds:     cat ${ENV_FILE}  (chmod 600, root-only)"
echo
