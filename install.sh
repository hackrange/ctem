#!/usr/bin/env bash
# open-ctem installer / upgrader -- Ubuntu 22.04+
# Fresh install:  curl -fsSL https://raw.githubusercontent.com/hackrange/ctem/main/install.sh | bash
# Upgrade:        bash /opt/open-ctem/install.sh  (re-run from an existing install)
#
# UPGRADE SAFETY:
#   - Never overwrites .env on an existing install
#   - Dumps the Postgres DB before pulling new code
#   - Rolls back the git pull if the app fails to become healthy
#   - Never removes Docker volumes (data is never wiped automatically)
set -euo pipefail

REPO="https://github.com/hackrange/ctem.git"
INSTALL_DIR="${CTEM_DIR:-/opt/open-ctem}"
COMPOSE_FILE="${INSTALL_DIR}/docker/docker-compose.yml"
COMPOSE_VERSION="2.24.5"
BACKUP_DIR="${INSTALL_DIR}/.backups"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[ctem]${NC} $*"; }
ok()    { echo -e "${GREEN}[ctem]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ctem]${NC} $*"; }
die()   { echo -e "${RED}[ctem] ERROR:${NC} $*" >&2; exit 1; }

# ── OS + permissions check ────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || die "Run as root (or with sudo bash install.sh)"

if ! grep -qE 'Ubuntu' /etc/os-release 2>/dev/null; then
  warn "Tested on Ubuntu 22.04+. Continuing on this OS..."
fi
VER=$(grep VERSION_ID /etc/os-release 2>/dev/null | cut -d'"' -f2 | cut -d'.' -f1)
[[ "${VER:-0}" -ge 22 ]] || warn "Ubuntu 22+ recommended (detected ${VER:-unknown})"

# ── Detect fresh install vs upgrade ──────────────────────────────────────────
IS_UPGRADE=0
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  IS_UPGRADE=1
  info "Existing installation found at ${INSTALL_DIR} -- running upgrade."
else
  info "Fresh installation to ${INSTALL_DIR}."
fi

# ── Docker ────────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  info "Installing Docker..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg lsb-release git
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
  ok "Docker already installed: $(docker --version)"
fi

if ! docker compose version &>/dev/null; then
  info "Installing Docker Compose plugin..."
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  ok "Docker Compose installed."
fi

# ── UPGRADE path ──────────────────────────────────────────────────────────────
if [[ "${IS_UPGRADE}" -eq 1 ]]; then
  cd "${INSTALL_DIR}"

  # 1. Guard: uncommitted local changes abort the pull (operator may have patched something)
  if ! git diff --quiet || ! git diff --cached --quiet; then
    warn "Uncommitted local changes detected in ${INSTALL_DIR}."
    warn "Stash or commit them before upgrading:"
    warn "  git -C ${INSTALL_DIR} stash"
    die "Aborting upgrade to protect local changes."
  fi

  # 2. Pre-upgrade database backup
  mkdir -p "${BACKUP_DIR}"
  STAMP=$(date +%Y%m%d_%H%M%S)
  BACKUP_FILE="${BACKUP_DIR}/db_pre_upgrade_${STAMP}.sql.gz"

  info "Backing up database to ${BACKUP_FILE}..."
  if docker compose -f "${COMPOSE_FILE}" ps --services --filter status=running | grep -q "^db$"; then
    if docker compose -f "${COMPOSE_FILE}" exec -T db \
        pg_dump -U "$(grep POSTGRES_USER .env | cut -d= -f2)" \
        "$(grep POSTGRES_DB .env | cut -d= -f2)" \
      | gzip > "${BACKUP_FILE}"; then
      ok "Database backup saved: ${BACKUP_FILE}"
    else
      warn "Database backup failed -- check that the db container is running."
      read -rp "Continue WITHOUT a backup? (yes/N): " CONFIRM
      [[ "${CONFIRM}" == "yes" ]] || die "Upgrade aborted. Fix the database connection first."
    fi
  else
    warn "Database container not running -- skipping backup."
    warn "If this is unexpected, start the stack first: docker compose -f ${COMPOSE_FILE} up -d"
  fi

  # 3. Record the current git rev so we can roll back
  PRE_UPGRADE_REV=$(git -C "${INSTALL_DIR}" rev-parse HEAD)

  # 4. Pull latest code
  info "Pulling latest code..."
  git -C "${INSTALL_DIR}" fetch origin
  if ! git -C "${INSTALL_DIR}" merge --ff-only origin/main; then
    die "Could not fast-forward. The branch has diverged. Merge manually then re-run."
  fi
  POST_UPGRADE_REV=$(git -C "${INSTALL_DIR}" rev-parse HEAD)

  if [[ "${PRE_UPGRADE_REV}" == "${POST_UPGRADE_REV}" ]]; then
    ok "Already up to date -- no new code to deploy."
    exit 0
  fi
  ok "Code updated: ${PRE_UPGRADE_REV:0:8} -> ${POST_UPGRADE_REV:0:8}"

  # 5. Pull new images + rolling restart (never down --volumes)
  info "Pulling updated container images..."
  docker compose -f "${COMPOSE_FILE}" pull --quiet

  info "Restarting services (zero data loss -- volumes preserved)..."
  docker compose -f "${COMPOSE_FILE}" up -d --remove-orphans

  # 6. Health check with rollback on failure
  info "Waiting for app to become healthy..."
  HEALTHY=0
  for i in $(seq 1 40); do
    if curl -fsk https://localhost/health &>/dev/null; then
      HEALTHY=1
      break
    fi
    sleep 3
  done

  if [[ "${HEALTHY}" -eq 0 ]]; then
    warn "App did not become healthy after upgrade."
    warn "Rolling back code to ${PRE_UPGRADE_REV:0:8}..."
    git -C "${INSTALL_DIR}" checkout "${PRE_UPGRADE_REV}" -- .
    docker compose -f "${COMPOSE_FILE}" up -d --remove-orphans
    echo
    die "Upgrade rolled back. DB backup is at: ${BACKUP_FILE}"
  fi

  # 7. Prune dangling images to free disk (safe -- only removes untagged)
  docker image prune -f &>/dev/null || true

  echo
  echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║         open-ctem upgraded successfully          ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
  echo
  echo -e "  Version:   ${CYAN}${POST_UPGRADE_REV:0:8}${NC}"
  echo -e "  DB backup: ${CYAN}${BACKUP_FILE}${NC}"
  echo -e "  Logs:      docker compose -f ${COMPOSE_FILE} logs -f"
  echo
  ok "Upgrade complete."
  exit 0
fi

# ── FRESH INSTALL path ────────────────────────────────────────────────────────
apt-get install -y -qq git openssl &>/dev/null || true

info "Cloning open-ctem to ${INSTALL_DIR}..."
git clone "${REPO}" "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

# ── .env setup ────────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  info "Generating .env from template..."
  [[ -f .env.example ]] || die ".env.example not found in ${INSTALL_DIR}. Is the repo complete?"
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
  read -rp "Press Enter when .env is ready (or Ctrl-C to abort and edit first): "
fi

# ── TLS cert (self-signed for first run) ──────────────────────────────────────
CERT_DIR="${INSTALL_DIR}/docker/certs"
if [[ ! -f "${CERT_DIR}/server.crt" ]]; then
  info "Generating self-signed TLS certificate..."
  mkdir -p "${CERT_DIR}"
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.crt" \
    -subj "/CN=open-ctem" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    &>/dev/null
  chmod 600 "${CERT_DIR}/server.key"
  ok "Self-signed cert generated. Replace with a real cert at ${CERT_DIR}/"
fi

# ── Launch ────────────────────────────────────────────────────────────────────
info "Starting open-ctem..."
docker compose -f "${COMPOSE_FILE}" pull --quiet
docker compose -f "${COMPOSE_FILE}" up -d --remove-orphans

info "Waiting for app to become healthy..."
for i in $(seq 1 30); do
  if curl -fsk https://localhost/health &>/dev/null; then
    break
  fi
  sleep 2
  [[ $i -eq 30 ]] && die "App did not become healthy within 60s. Check: docker compose -f ${COMPOSE_FILE} logs app"
done

echo
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         open-ctem is running                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo
echo -e "  Web UI:    ${CYAN}https://localhost${NC}  (or your server IP)"
echo -e "  API docs:  ${CYAN}https://localhost/api/docs${NC}"
echo -e "  Logs:      docker compose -f ${COMPOSE_FILE} logs -f"
echo -e "  Stop:      docker compose -f ${COMPOSE_FILE} down"
echo -e "  Upgrade:   bash ${INSTALL_DIR}/install.sh"
echo
ok "Done. Create your first admin user via the UI after first login."
