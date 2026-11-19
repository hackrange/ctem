#!/usr/bin/env bash
# open-ctem installer -- Ubuntu 22.04+
# Usage: curl -fsSL https://raw.githubusercontent.com/hackrange/ctem/main/install.sh | bash
set -euo pipefail

REPO="https://github.com/hackrange/ctem.git"
INSTALL_DIR="${CTEM_DIR:-/opt/open-ctem}"
COMPOSE_VERSION="2.24.5"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[ctem]${NC} $*"; }
ok()    { echo -e "${GREEN}[ctem]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ctem]${NC} $*"; }
die()   { echo -e "${RED}[ctem] ERROR:${NC} $*" >&2; exit 1; }

# ── OS check ──────────────────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || die "Run as root (or with sudo bash install.sh)"

if ! grep -qE 'Ubuntu' /etc/os-release 2>/dev/null; then
  warn "This installer is tested on Ubuntu 22.04+. Continuing anyway..."
fi
VER=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2 | cut -d'.' -f1)
[[ "${VER:-0}" -ge 22 ]] || warn "Ubuntu 22+ recommended (detected ${VER:-unknown})"

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

# ── Docker Compose ────────────────────────────────────────────────────────────
if ! docker compose version &>/dev/null; then
  info "Installing Docker Compose plugin..."
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  ok "Docker Compose installed."
fi

# ── Clone or update ───────────────────────────────────────────────────────────
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  info "Updating existing installation at ${INSTALL_DIR}..."
  git -C "${INSTALL_DIR}" pull --ff-only
else
  info "Cloning open-ctem to ${INSTALL_DIR}..."
  git clone "${REPO}" "${INSTALL_DIR}"
fi

cd "${INSTALL_DIR}"

# ── .env setup ────────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  info "Generating .env from template..."
  cp .env.example .env

  # Generate cryptographically random values
  SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  ENC_KEY=$(python3 -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")
  DB_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
  REDIS_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

  sed -i "s|SECRET_KEY=.*|SECRET_KEY=${SECRET_KEY}|" .env
  sed -i "s|ENCRYPTION_KEY=.*|ENCRYPTION_KEY=${ENC_KEY}|" .env
  sed -i "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${DB_PASS}|" .env
  sed -i "s|REDIS_PASSWORD=.*|REDIS_PASSWORD=${REDIS_PASS}|" .env

  warn "Review .env before proceeding: ${INSTALL_DIR}/.env"
  warn "Set AUTH_MODE, OIDC_*, and other required values."
  echo
  read -rp "Press Enter when .env is ready (or Ctrl-C to abort and edit manually): "
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
docker compose -f docker/docker-compose.yml pull --quiet
docker compose -f docker/docker-compose.yml up -d --remove-orphans

# ── Wait for health ───────────────────────────────────────────────────────────
info "Waiting for app to become healthy..."
for i in $(seq 1 30); do
  if curl -fsk https://localhost/health &>/dev/null; then
    break
  fi
  sleep 2
  [[ $i -eq 30 ]] && die "App did not become healthy within 60s. Check: docker compose -f docker/docker-compose.yml logs app"
done

echo
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         open-ctem is running                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo
echo -e "  Web UI:    ${CYAN}https://localhost${NC}  (or your server IP)"
echo -e "  API docs:  ${CYAN}https://localhost/api/docs${NC}"
echo -e "  Logs:      docker compose -f ${INSTALL_DIR}/docker/docker-compose.yml logs -f"
echo -e "  Stop:      docker compose -f ${INSTALL_DIR}/docker/docker-compose.yml down"
echo
ok "Done. Create your first user via the admin panel after logging in."
