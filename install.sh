#!/usr/bin/env bash
# open-ctem installer / upgrader
#
# First install:
#   curl -fsSL https://raw.githubusercontent.com/hackrange/ctem/main/install.sh | sudo bash
#
# Or on a server you've already SSHd into:
#   sudo bash /data/docker/ctem/install.sh
#
# Upgrade an existing install:
#   sudo bash /data/docker/ctem/install.sh --upgrade
set -euo pipefail

REPO="https://github.com/hackrange/ctem.git"
INSTALL_DIR="/data/docker/ctem"
COMPOSE_FILE="${INSTALL_DIR}/docker/docker-compose.yml"
CERT_DIR="${INSTALL_DIR}/docker/certs"
BACKUP_DIR="${INSTALL_DIR}/.backups"

c_head=$'\033[1;36m'; c_ok=$'\033[32m'; c_warn=$'\033[33m'
c_err=$'\033[31m';    c_dim=$'\033[2m'; c_off=$'\033[0m'
[[ -t 1 ]] || { c_head=; c_ok=; c_warn=; c_err=; c_dim=; c_off=; }

say()  { printf '%s[ctem]%s %s\n' "$c_head" "$c_off" "$*"; }
ok()   { printf '%s  ok%s  %s\n' "$c_ok"   "$c_off" "$*"; }
warn() { printf '%s  !!%s  %s\n' "$c_warn" "$c_off" "$*" >&2; }
die()  { printf '%s  xx%s  %s\n' "$c_err"  "$c_off" "$*" >&2; exit 1; }
hint() { printf '%s     %s%s\n'  "$c_dim"  "$*"     "$c_off"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
UPGRADE=0
while (( $# )); do
  case "$1" in
    --upgrade|-u) UPGRADE=1; shift ;;
    -h|--help)
      cat <<'USAGE'
open-ctem installer / upgrader

  install.sh                Fresh install to /data/docker/ctem.
                            Installs Docker if needed, clones the repo,
                            generates all credentials, starts the stack.
                            No manual steps required -- just run it.

  install.sh --upgrade      Upgrade an existing install. Backs up the
                            database, pulls the latest code, rebuilds
                            images, restarts the stack. Never touches .env.

  install.sh --help         This text.

USAGE
      exit 0 ;;
    *) die "Unknown option: $1  (try --help)" ;;
  esac
done

# ── Must run as root ──────────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || die "Run as root:  sudo bash install.sh"

# ── Compose helper: always pass --env-file so variable substitution works
# even though .env lives in the project root, not beside the compose file.
_compose() { docker compose -f "${COMPOSE_FILE}" --env-file "${INSTALL_DIR}/.env" "$@"; }

# ── Password generator ────────────────────────────────────────────────────────
# Format: XXXXX-XXXXXX-NNNN-XXXXXX  (21 chars + dashes = 23 total)
# Letters: A-Z excluding I, L, O (look-alike letters)
# Digits:  1-9 (no zero)
genpass() {
  python3 - <<'PYEOF'
import secrets, string
letters = [c for c in string.ascii_uppercase if c not in 'ILO']
digits  = [c for c in '123456789']
def seg(chars, n):
    return ''.join(secrets.choice(chars) for _ in range(n))
print(f"{seg(letters,5)}-{seg(letters,6)}-{seg(digits,4)}-{seg(letters,6)}")
PYEOF
}

# ── Upgrade path ──────────────────────────────────────────────────────────────
if (( UPGRADE )); then
  say "open-ctem upgrade"

  [[ -d "${INSTALL_DIR}/.git" ]] || die "No git checkout at ${INSTALL_DIR}. Run without --upgrade for a fresh install."
  [[ -f "${INSTALL_DIR}/.env"  ]] || die "No .env at ${INSTALL_DIR}. Run without --upgrade for a fresh install."

  cd "${INSTALL_DIR}"

  # Guard against local uncommitted changes
  if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
    warn "Uncommitted local changes found in ${INSTALL_DIR}."
    hint "Stash them first:  git -C ${INSTALL_DIR} stash"
    die "Upgrade aborted -- local changes are protected."
  fi

  # Warn about any new required keys from .env.example not yet in .env
  if [[ -f .env.example ]]; then
    missing=""
    while IFS='=' read -r key _rest; do
      [[ -n "$key" && "$key" != \#* ]] || continue
      grep -q "^${key}=" .env 2>/dev/null || missing="${missing} ${key}"
    done < .env.example
    if [[ -n "$missing" ]]; then
      warn "New keys in .env.example are not yet in your .env -- add them manually:"
      for k in $missing; do hint "  $k"; done
      echo
    fi
  fi

  # Pre-upgrade database backup
  mkdir -p "${BACKUP_DIR}"
  STAMP=$(date +%Y%m%d_%H%M%S)
  BACKUP_FILE="${BACKUP_DIR}/db_pre_upgrade_${STAMP}.sql.gz"
  DB_USER=$(grep '^DB_USER=' .env 2>/dev/null | cut -d= -f2 || echo openctem)
  DB_NAME=$(grep '^DB_NAME=' .env 2>/dev/null | cut -d= -f2 || echo openctem)

  say "Backing up database..."
  if _compose ps --services --filter status=running 2>/dev/null | grep -q "^db$"; then
    if _compose exec -T db pg_dump -U "${DB_USER}" "${DB_NAME}" | gzip > "${BACKUP_FILE}"; then
      ok "Backup: ${BACKUP_FILE}"
    else
      warn "Backup failed. Continue without one? (yes/N): "
      read -r REPLY
      [[ "${REPLY}" == "yes" ]] || die "Upgrade aborted. Fix the database connection first."
    fi
  else
    warn "Database container not running -- skipping backup."
  fi

  PRE_REV=$(git rev-parse HEAD)

  say "Pulling latest code..."
  BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)
  git fetch --quiet origin "${BRANCH}" || die "Could not fetch from origin."
  git pull --quiet --ff-only origin "${BRANCH}" \
    || die "Could not fast-forward. Merge manually, then re-run."

  POST_REV=$(git rev-parse HEAD)
  if [[ "${PRE_REV}" == "${POST_REV}" ]]; then
    ok "Already up to date."
    exit 0
  fi
  ok "Code: ${PRE_REV:0:8} -> ${POST_REV:0:8}"
  git log --oneline "${PRE_REV}..${POST_REV}" | sed 's/^/     /'

  say "Pulling updated images..."
  _compose pull --quiet

  say "Restarting services..."
  _compose up -d --remove-orphans

  say "Waiting for healthy response..."
  HEALTHY=0
  for i in $(seq 1 40); do
    if curl -fsk https://localhost/health &>/dev/null; then HEALTHY=1; break; fi
    sleep 3
  done

  if (( ! HEALTHY )); then
    warn "App did not come up healthy. Rolling back code to ${PRE_REV:0:8}..."
    git checkout "${PRE_REV}" -- .
    _compose up -d --remove-orphans
    die "Upgrade rolled back. DB backup is at: ${BACKUP_FILE}"
  fi

  docker image prune -f &>/dev/null || true

  echo
  printf '%s  open-ctem upgraded to %s%s\n' "$c_ok" "${POST_REV:0:8}" "$c_off"
  hint "Backup:  ${BACKUP_FILE}"
  hint "Logs:    docker compose -f ${COMPOSE_FILE} logs -f"
  echo
  exit 0
fi

# ── Fresh install ─────────────────────────────────────────────────────────────
say "open-ctem fresh install  -->  ${INSTALL_DIR}"

# Already installed?
if [[ -f "${INSTALL_DIR}/.env" ]]; then
  warn "${INSTALL_DIR}/.env already exists."
  hint "To upgrade an existing install run:  sudo bash ${INSTALL_DIR}/install.sh --upgrade"
  die "Aborting to protect your existing install."
fi

# ── OS check ──────────────────────────────────────────────────────────────────
if grep -qiE 'ubuntu|debian' /etc/os-release 2>/dev/null; then
  VER=$(grep VERSION_ID /etc/os-release 2>/dev/null | tr -d '"' | cut -d= -f2 | cut -d. -f1)
  [[ "${VER:-0}" -ge 22 ]] || warn "Ubuntu/Debian 22+ recommended (detected ${VER:-unknown})"
else
  warn "Tested on Ubuntu 22.04+. Continuing on this OS..."
fi

# ── Install system packages ───────────────────────────────────────────────────
say "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg lsb-release git openssl python3 2>/dev/null
ok "System packages ready."

# ── Install Docker ────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  say "Installing Docker..."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
  ok "Docker $(docker --version | awk '{print $3}' | tr -d ',') installed."
else
  ok "Docker: $(docker --version | awk '{print $3}' | tr -d ',')"
fi

# ── Install Docker Compose plugin if missing ──────────────────────────────────
if ! docker compose version &>/dev/null; then
  say "Installing Docker Compose plugin..."
  mkdir -p /usr/local/lib/docker/cli-plugins
  COMPOSE_VER="2.24.5"
  curl -fsSL \
    "https://github.com/docker/compose/releases/download/v${COMPOSE_VER}/docker-compose-linux-$(uname -m)" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  ok "Docker Compose $(docker compose version --short) installed."
else
  ok "Docker Compose: $(docker compose version --short)"
fi

# ── Create install directory and clone repo ───────────────────────────────────
mkdir -p "$(dirname "${INSTALL_DIR}")"

if [[ -d "${INSTALL_DIR}/.git" ]]; then
  ok "Repo already cloned at ${INSTALL_DIR}."
else
  say "Cloning open-ctem to ${INSTALL_DIR}..."
  git clone "${REPO}" "${INSTALL_DIR}"
  ok "Cloned."
fi

cd "${INSTALL_DIR}"

# ── Generate all credentials ──────────────────────────────────────────────────
say "Generating credentials..."

DB_PASS=$(genpass)
REDIS_PASS=$(genpass)
ADMIN_PASS=$(genpass)
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
ENC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
ENC_SEARCH_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
ADMIN_USER="admin"

ok "Credentials generated."

# ── Write .env ────────────────────────────────────────────────────────────────
say "Writing .env..."
cat > "${INSTALL_DIR}/.env" <<ENV
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
SECRET_KEY=${SECRET_KEY}
ENCRYPTION_KEY=${ENC_KEY}
ENCRYPTION_SEARCH_KEY=${ENC_SEARCH_KEY}

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

chmod 600 "${INSTALL_DIR}/.env"
ok ".env written and locked down (chmod 600)."

# ── TLS certificate ───────────────────────────────────────────────────────────
if [[ ! -f "${CERT_DIR}/server.crt" ]]; then
  say "Generating self-signed TLS certificate..."
  mkdir -p "${CERT_DIR}"
  FQDN=$(hostname -f 2>/dev/null || echo localhost)
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout "${CERT_DIR}/server.key" \
    -out    "${CERT_DIR}/server.crt" \
    -subj   "/CN=${FQDN}" \
    -addext "subjectAltName=DNS:${FQDN},DNS:localhost,IP:127.0.0.1" \
    &>/dev/null
  chmod 600 "${CERT_DIR}/server.key"
  ok "Self-signed cert (${FQDN}) -- replace with a real cert when ready."
fi

# ── Pull images and start ─────────────────────────────────────────────────────
say "Pulling container images (this takes a minute)..."
_compose pull --quiet
ok "Images pulled."

say "Starting open-ctem..."
_compose up -d --remove-orphans
ok "Containers started."

# ── Health check ──────────────────────────────────────────────────────────────
say "Waiting for the app to become healthy..."
HEALTHY=0
for i in $(seq 1 40); do
  if curl -fsk https://localhost/health &>/dev/null; then HEALTHY=1; break; fi
  printf '.'
  sleep 3
done
echo

(( HEALTHY )) || die "App did not respond after 2 minutes. Check logs: docker compose -f ${COMPOSE_FILE} logs app"
ok "App is healthy."

# ── Print credentials ─────────────────────────────────────────────────────────
echo
printf '%s╔══════════════════════════════════════════════════════╗%s\n' "$c_ok" "$c_off"
printf '%s║           open-ctem is ready                         ║%s\n' "$c_ok" "$c_off"
printf '%s╚══════════════════════════════════════════════════════╝%s\n' "$c_ok" "$c_off"
echo
printf '%s  Save these credentials -- you will not see them again%s\n' "$c_warn" "$c_off"
echo
printf '  Web UI:         https://%s\n'  "$(hostname -f 2>/dev/null || echo localhost)"
printf '  Admin user:     %s\n'          "${ADMIN_USER}"
printf '  Admin password: %s\n'          "${ADMIN_PASS}"
echo
hint "API docs:  https://localhost/api/docs"
hint "Logs:      docker compose -f ${COMPOSE_FILE} logs -f"
hint "Stop:      docker compose -f ${COMPOSE_FILE} down"
hint "Upgrade:   sudo bash ${INSTALL_DIR}/install.sh --upgrade"
hint "Creds:     cat ${INSTALL_DIR}/.env  (chmod 600, root-only)"
echo
