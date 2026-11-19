#!/usr/bin/env bash
# open-ctem installer / upgrader -- Ubuntu 22.04+
#
# First install:   curl -fsSL https://raw.githubusercontent.com/hackrange/ctem/main/install.sh | bash
# Upgrade:         bash /opt/open-ctem/install.sh --upgrade
#
# Everything you configured the first time lives in .env and is left
# completely alone on upgrade -- an upgrade cannot change your database,
# move your data, or alter any setting you made.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo /opt/open-ctem)"
REPO="https://github.com/hackrange/ctem.git"
INSTALL_DIR="${CTEM_DIR:-/opt/open-ctem}"
COMPOSE_FILE="${INSTALL_DIR}/docker/docker-compose.yml"
COMPOSE_VERSION="2.24.5"
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
UPGRADE_NOW=0
while (( $# )); do
  case "$1" in
    --upgrade|-u) UPGRADE=1; shift ;;
    --now)        UPGRADE_NOW=1; shift ;;
    -h|--help)
      cat <<'__USAGE__'
open-ctem install.sh -- installer and upgrader

  install.sh                First time. Installs Docker if needed, clones the
                            repo, generates .env, issues a TLS cert, and starts
                            the stack. Asks for confirmation before launching.

  install.sh --upgrade      Already installed. Backs up the database, pulls the
                            latest code, rebuilds images, and restarts the
                            stack. Asks nothing and never changes your .env.

  install.sh --upgrade --now
                            Same as --upgrade but restarts immediately without
                            waiting for in-progress syncs to settle.

  install.sh --help         This text.

Everything you configured the first time lives in .env and is left alone
on every upgrade, so an upgrade cannot silently change your database
connection, encryption key, or any other setting.

__USAGE__
      exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

# ── Permissions check ─────────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || die "Run as root (or: sudo bash install.sh)"

# ── Upgrade path ──────────────────────────────────────────────────────────────
if (( UPGRADE )); then
  say "open-ctem upgrade"

  [[ -d "${INSTALL_DIR}/.git" ]] || die "No git checkout at ${INSTALL_DIR}. Run without --upgrade for a fresh install."
  [[ -f "${INSTALL_DIR}/.env" ]] || die "No .env at ${INSTALL_DIR}. Run without --upgrade for a fresh install."

  cd "${INSTALL_DIR}"

  # 1. Abort on uncommitted local changes -- protect operator patches
  if ! git diff --quiet || ! git diff --cached --quiet; then
    warn "Uncommitted local changes detected in ${INSTALL_DIR}."
    hint "Stash them first:  git -C ${INSTALL_DIR} stash"
    die "Upgrade aborted to protect your local changes."
  fi

  # 2. Report new .env keys from .env.example (never merge automatically)
  if [[ -f .env.example ]]; then
    missing=""
    while IFS='=' read -r key _; do
      [[ -n "$key" && "$key" != \#* ]] || continue
      grep -q "^${key}=" .env 2>/dev/null || missing="${missing} ${key}"
    done < .env.example
    if [[ -n "$missing" ]]; then
      warn "New keys in .env.example not yet in .env -- add them manually if needed:"
      for k in $missing; do hint "  $k"; done
      echo
    fi
  fi

  # 3. Pre-upgrade database backup
  mkdir -p "${BACKUP_DIR}"
  STAMP=$(date +%Y%m%d_%H%M%S)
  BACKUP_FILE="${BACKUP_DIR}/db_pre_upgrade_${STAMP}.sql.gz"

  say "Backing up database..."
  PGUSER=$(grep '^POSTGRES_USER=' .env | cut -d= -f2)
  PGDB=$(grep '^POSTGRES_DB=' .env   | cut -d= -f2)
  PGUSER="${PGUSER:-ctem}"
  PGDB="${PGDB:-ctem}"

  if docker compose -f "${COMPOSE_FILE}" ps --services --filter status=running 2>/dev/null | grep -q "^db$"; then
    if docker compose -f "${COMPOSE_FILE}" exec -T db pg_dump -U "${PGUSER}" "${PGDB}" | gzip > "${BACKUP_FILE}"; then
      ok "Database backup: ${BACKUP_FILE}"
    else
      warn "Database backup failed."
      hint "Make sure the db container is healthy: docker compose -f ${COMPOSE_FILE} ps"
      printf 'Continue WITHOUT a backup? (yes/N): '
      read -r CONFIRM
      [[ "${CONFIRM}" == "yes" ]] || die "Upgrade aborted. Fix the database connection first."
    fi
  else
    warn "Database container not running -- skipping backup."
  fi

  # 4. Record pre-upgrade rev for rollback
  PRE_REV=$(git rev-parse HEAD)

  # 5. Pull latest code (ff-only -- no surprise merges)
  say "Pulling latest code..."
  BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)
  git fetch --quiet origin "${BRANCH}" || die "Could not fetch from origin."
  git pull --quiet --ff-only origin "${BRANCH}" \
    || die "Could not fast-forward. The branch has diverged; merge manually then re-run."

  POST_REV=$(git rev-parse HEAD)
  if [[ "${PRE_REV}" == "${POST_REV}" ]]; then
    ok "Already up to date -- nothing to deploy."
    exit 0
  fi
  ok "Code: ${PRE_REV:0:8} -> ${POST_REV:0:8}"
  git log --oneline "${PRE_REV}..${POST_REV}" | sed 's/^/     /'

  # 6. Pull new images + rolling restart (--volumes is NEVER passed)
  say "Pulling updated container images..."
  docker compose -f "${COMPOSE_FILE}" pull --quiet

  say "Restarting services..."
  docker compose -f "${COMPOSE_FILE}" up -d --remove-orphans

  # 7. Health check with automatic code rollback on failure
  say "Waiting for app to become healthy..."
  HEALTHY=0
  for i in $(seq 1 40); do
    if curl -fsk https://localhost/health &>/dev/null; then
      HEALTHY=1; break
    fi
    sleep 3
  done

  if (( ! HEALTHY )); then
    warn "App did not become healthy after upgrade."
    say "Rolling back code to ${PRE_REV:0:8}..."
    git checkout "${PRE_REV}" -- .
    docker compose -f "${COMPOSE_FILE}" up -d --remove-orphans
    echo
    die "Upgrade rolled back. DB backup: ${BACKUP_FILE}"
  fi

  docker image prune -f &>/dev/null || true

  echo
  printf '%s╔══════════════════════════════════════════╗%s\n' "$c_ok" "$c_off"
  printf '%s║  open-ctem upgraded successfully         ║%s\n' "$c_ok" "$c_off"
  printf '%s╚══════════════════════════════════════════╝%s\n' "$c_ok" "$c_off"
  echo
  hint "Version:    ${POST_REV:0:8}"
  hint "DB backup:  ${BACKUP_FILE}"
  hint "Logs:       docker compose -f ${COMPOSE_FILE} logs -f"
  echo
  exit 0
fi

# ── Fresh install path ────────────────────────────────────────────────────────
say "open-ctem fresh install"

if ! grep -qE 'Ubuntu' /etc/os-release 2>/dev/null; then
  warn "Tested on Ubuntu 22.04+. Continuing on this OS..."
fi
VER=$(grep VERSION_ID /etc/os-release 2>/dev/null | cut -d'"' -f2 | cut -d'.' -f1)
[[ "${VER:-0}" -ge 22 ]] || warn "Ubuntu 22+ recommended (detected ${VER:-unknown})"

# Docker
if ! command -v docker &>/dev/null; then
  say "Installing Docker..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg lsb-release git openssl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
  ok "Docker installed."
else
  ok "Docker: $(docker --version)"
fi

if ! docker compose version &>/dev/null; then
  say "Installing Docker Compose plugin..."
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  ok "Docker Compose installed."
fi

apt-get install -y -qq git openssl &>/dev/null || true

say "Cloning open-ctem to ${INSTALL_DIR}..."
git clone "${REPO}" "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

# .env
if [[ ! -f .env ]]; then
  say "Generating .env from template..."
  [[ -f .env.example ]] || die ".env.example not found. Is the repo complete?"
  cp .env.example .env

  SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  ENC_KEY=$(python3 -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")
  DB_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
  REDIS_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

  sed -i "s|SECRET_KEY=.*|SECRET_KEY=${SECRET_KEY}|" .env
  sed -i "s|ENCRYPTION_KEY=.*|ENCRYPTION_KEY=${ENC_KEY}|" .env
  sed -i "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${DB_PASS}|" .env
  sed -i "s|REDIS_PASSWORD=.*|REDIS_PASSWORD=${REDIS_PASS}|" .env

  warn "Review .env before proceeding: ${INSTALL_DIR}/.env"
  warn "Set AUTH_MODE, OIDC_*, and any site-specific values."
  echo
  printf 'Press Enter when .env is ready (Ctrl-C to abort and edit first): '
  read -r _
fi

# TLS cert
CERT_DIR="${INSTALL_DIR}/docker/certs"
if [[ ! -f "${CERT_DIR}/server.crt" ]]; then
  say "Generating self-signed TLS certificate..."
  mkdir -p "${CERT_DIR}"
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.crt" \
    -subj "/CN=open-ctem" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    &>/dev/null
  chmod 600 "${CERT_DIR}/server.key"
  ok "Self-signed cert at ${CERT_DIR}/ -- replace with a real cert when ready."
fi

say "Starting open-ctem..."
docker compose -f "${COMPOSE_FILE}" pull --quiet
docker compose -f "${COMPOSE_FILE}" up -d --remove-orphans

say "Waiting for app to become healthy..."
for i in $(seq 1 30); do
  if curl -fsk https://localhost/health &>/dev/null; then break; fi
  sleep 2
  [[ $i -lt 30 ]] || die "App not healthy after 60s. Check: docker compose -f ${COMPOSE_FILE} logs app"
done

echo
printf '%s╔══════════════════════════════════════════╗%s\n' "$c_ok" "$c_off"
printf '%s║  open-ctem is running                    ║%s\n' "$c_ok" "$c_off"
printf '%s╚══════════════════════════════════════════╝%s\n' "$c_ok" "$c_off"
echo
hint "Web UI:   https://localhost  (or your server IP)"
hint "API docs: https://localhost/api/docs"
hint "Logs:     docker compose -f ${COMPOSE_FILE} logs -f"
hint "Stop:     docker compose -f ${COMPOSE_FILE} down"
hint "Upgrade:  bash ${INSTALL_DIR}/install.sh --upgrade"
echo
ok "Done. Create your first admin user via the UI."
