# shellcheck shell=bash
# Shared bits for install.sh, backup.sh and restore.sh. Author: Tim Rice <tim.j.rice@hackrange.com>

c_head=$'\033[1;36m'; c_ok=$'\033[32m'; c_warn=$'\033[33m'
c_err=$'\033[31m';    c_dim=$'\033[2m'; c_off=$'\033[0m'
[[ -t 1 ]] || { c_head=; c_ok=; c_warn=; c_err=; c_dim=; c_off=; }

say()  { printf '%s[ctem]%s %s\n' "$c_head" "$c_off" "$*"; }
ok()   { printf '%s  ok%s  %s\n' "$c_ok"   "$c_off" "$*"; }
warn() { printf '%s  !!%s  %s\n' "$c_warn" "$c_off" "$*" >&2; }
die()  { printf '%s  xx%s  %s\n' "$c_err"  "$c_off" "$*" >&2; exit 1; }
hint() { printf '%s     %s%s\n'  "$c_dim"  "$*"     "$c_off"; }

COMPOSE_FILE="${INSTALL_DIR}/docker/docker-compose.yml"
ENV_FILE="${INSTALL_DIR}/.env"
ARCHIVE_PY="${INSTALL_DIR}/api/maintenance/backup_archive.py"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1

# Always pass --env-file (the .env sits in the project root) and keep a local override file
_compose() {
  local files=(-f "${COMPOSE_FILE}")
  [[ -f "${INSTALL_DIR}/docker/docker-compose.override.yml" ]] && files+=(-f "${INSTALL_DIR}/docker/docker-compose.override.yml")
  docker compose "${files[@]}" --env-file "${ENV_FILE}" "$@"
}

archive() { python3 -I "${ARCHIVE_PY}" "$@"; }

# XXXXX-XXXXXX-NNNN-XXXXXX, no look-alike letters and no zero
genpass() {
  python3 -I -c 'import secrets, string
L = [c for c in string.ascii_uppercase if c not in "ILO"]
D = "123456789"
s = lambda cs, n: "".join(secrets.choice(cs) for _ in range(n))
print(f"{s(L,5)}-{s(L,6)}-{s(D,4)}-{s(L,6)}")'
}
genhex()        { python3 -I -c 'import secrets; print(secrets.token_hex(32))'; }
gen_backup_pw() { python3 -I -c 'import secrets; print(secrets.token_urlsafe(30))'; }

# Read KEY from an env file without sourcing it (sourcing runs whatever is in there)
env_get() {
  local line
  line=$(grep -E "^${1}=" "${2:-$ENV_FILE}" 2>/dev/null | tail -n1) || true
  line="${line#*=}"; line="${line%\"}"; line="${line#\"}"
  printf '%s' "$line"
}

# Set KEY=VALUE in an env file; values go through ENVIRON so nothing in them gets interpreted
env_set() {
  local f="$3"
  K="$1" V="$2" awk 'BEGIN { k = ENVIRON["K"]; v = ENVIRON["V"] }
    index($0, k "=") == 1 { if (!done) print k "=" v; done = 1; next }
    { print } END { if (!done) print k "=" v }' "$f" > "$f.new"
  chmod 600 "$f.new" && mv "$f.new" "$f"
}

# curl | bash leaves stdin holding the script, so prompts always go to the terminal
ask_tty() {
  local prompt="$1" reply=""
  [[ -r /dev/tty ]] || return 1
  printf '%s  ?? %s%s ' "$c_warn" "$c_off" "$prompt" > /dev/tty
  read -r reply < /dev/tty || true
  printf '%s' "$reply"
}

read_secret() {
  local prompt="$1" reply=""
  [[ -r /dev/tty ]] || die "No terminal to ask for the password on. Set CTEM_BACKUP_PASSWORD for unattended runs."
  printf '%s  ?? %s%s ' "$c_warn" "$c_off" "$prompt" > /dev/tty
  IFS= read -rs reply < /dev/tty || true
  printf '\n' > /dev/tty
  printf '%s' "$reply"
}

require_root() { [[ "$(id -u)" -eq 0 ]] || die "Run as root:  sudo bash install.sh"; }

require_ubuntu() {
  local id="" ver=""
  # shellcheck disable=SC1091
  [[ -r /etc/os-release ]] && { id=$(. /etc/os-release; echo "${ID:-}"); ver=$(. /etc/os-release; echo "${VERSION_ID:-}"); }
  [[ "$id" == "ubuntu" ]] || die "open-ctem installs on Ubuntu 22.04 or newer only (this is ${id:-unknown})."
  dpkg --compare-versions "${ver:-0}" ge 22.04 || die "open-ctem needs Ubuntu 22.04 or newer (this is ${ver:-unknown})."
  [[ "$(dpkg --print-architecture)" =~ ^(amd64|arm64)$ ]] || die "open-ctem needs an amd64 or arm64 machine."
  ok "Ubuntu ${ver} ($(dpkg --print-architecture))"
}

_apt() { apt-get -o DPkg::Lock::Timeout=600 -y -qq "$@"; }

_docker_from_docker_repo() {
  local codename; codename=$(. /etc/os-release; echo "${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}")
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc || return 1
  chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$codename" > /etc/apt/sources.list.d/docker.list
  if ! _apt update >/dev/null 2>&1; then
    rm -f /etc/apt/sources.list.d/docker.list   # a release Docker hasn't published for yet
    _apt update >/dev/null
    return 1
  fi
  _apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
}

install_deps() {
  say "Installing system packages..."
  _apt update >/dev/null || die "apt-get update failed. Check this server's network and apt sources."
  _apt install ca-certificates curl gnupg git openssl python3 python3-cryptography iproute2 >/dev/null \
    || die "Could not install the base packages."
  ok "git, curl, openssl, python3 and python3-cryptography ready."

  if ! command -v docker >/dev/null 2>&1; then
    say "Installing Docker Engine and the compose plugin..."
    if ! _docker_from_docker_repo; then
      warn "Docker's repository has nothing for this release, using Ubuntu's own Docker packages."
      _apt install docker.io docker-compose-v2 >/dev/null || die "Could not install Docker."
      _apt install docker-buildx >/dev/null 2>&1 || true
    fi
  fi
  if ! docker compose version >/dev/null 2>&1; then
    say "Installing the docker compose plugin..."
    if dpkg -s docker-ce >/dev/null 2>&1; then
      _apt install docker-compose-plugin docker-buildx-plugin >/dev/null || die "Could not install docker-compose-plugin."
    else
      _apt install docker-compose-v2 >/dev/null 2>&1 || _docker_from_docker_repo \
        || die "Could not install the docker compose plugin."
    fi
  fi
  systemctl enable --now docker >/dev/null 2>&1 || true
  docker info >/dev/null 2>&1 || die "Docker is installed but not running. Try: systemctl start docker"
  ok "Docker $(docker version --format '{{.Server.Version}}'), compose $(docker compose version --short)"
}

# Backups need python3-cryptography on the host; older installs may not have it yet
ensure_py_crypto() {
  python3 -I -c 'import cryptography' 2>/dev/null && return 0
  say "Installing python3-cryptography for backups..."
  _apt update >/dev/null || die "apt-get update failed."
  _apt install python3 python3-cryptography >/dev/null || die "Could not install python3-cryptography."
}

check_ports() {
  local port busy
  for port in 80 443; do
    busy=$(ss -Hltnp "sport = :${port}" 2>/dev/null | head -n1)
    if [[ -n "$busy" ]]; then
      warn "Port ${port} is already in use on this server:"
      hint "${busy}"
      die "open-ctem serves on ports 80 and 443. Stop whatever is using them, then run this again."
    fi
  done
}

wait_healthy() {
  local secs="${1:-180}" i
  say "Waiting for the app to become healthy (up to $((secs / 60)) minutes)..."
  for ((i = 0; i < secs; i += 3)); do
    if curl -fsk --max-time 5 https://localhost/health >/dev/null 2>&1; then echo; ok "App is healthy."; return 0; fi
    printf '.'; sleep 3
  done
  echo
  return 1
}

wait_db() {
  local user="$1" i
  # Over TCP on purpose: first boot runs a socket-only server for init scripts, then restarts it
  for ((i = 0; i < 90; i++)); do
    _compose exec -T db pg_isready -q -h 127.0.0.1 -U "$user" </dev/null 2>/dev/null && return 0
    sleep 2
  done
  die "The database did not start. Check: docker compose -f ${COMPOSE_FILE} logs db"
}

make_self_signed_cert() {
  local dir="${INSTALL_DIR}/docker/certs" fqdn
  [[ -f "${dir}/server.crt" && -f "${dir}/server.key" ]] && return 0
  say "Generating a self-signed TLS certificate..."
  mkdir -p "$dir"
  fqdn=$(hostname -f 2>/dev/null || echo localhost)
  openssl req -x509 -nodes -newkey rsa:3072 -days 825 -keyout "${dir}/server.key" -out "${dir}/server.crt" \
    -subj "/CN=${fqdn}" -addext "subjectAltName=DNS:${fqdn},DNS:localhost,IP:127.0.0.1" &>/dev/null \
    || die "Could not generate a TLS certificate."
  chmod 600 "${dir}/server.key"
  ok "Self-signed cert for ${fqdn}. Swap in a real one when ready (docker/certs/server.crt and server.key)."
}
