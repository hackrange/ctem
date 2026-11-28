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

port_busy() { [[ -n "$(ss -Hltn "sport = :${1}" 2>/dev/null | head -n1)" ]]; }

free_port() {   # free_port <first>: the first free TCP port from there on
  local p="$1" i
  for ((i = 0; i < 100; i++, p++)); do port_busy "$p" || { echo "$p"; return 0; }; done
  die "No free port found from ${1}."
}

# Ports 80 and 443 taken (another web server or a reverse proxy already there): don't fail. open-ctem takes free
# ports on this server only instead, and the install ends by saying what to point the reverse proxy at.
PROXY_MODE=0 TAKEN=""
check_ports() {
  local port busy taken=()
  for port in 80 443; do
    busy=$(ss -Hltnp "sport = :${port}" 2>/dev/null | head -n1)
    if [[ -n "$busy" ]]; then
      warn "Port ${port} is already in use on this server:"
      hint "${busy}"
      taken+=("$port")
    fi
  done
  (( ${#taken[@]} )) || { port_busy 8085 && die "Port 8085 (the load balancer and reverse proxy listener) is in use; free it, then run this again."; return 0; }
  PROXY_MODE=1
  TAKEN=$( (( ${#taken[@]} == 2 )) && echo "Ports 80 and 443 are" || echo "Port ${taken[0]} is")
  HTTP_PORT=$(free_port 8080); HTTPS_PORT=$(free_port 8443); LB_PORT=$(free_port 8085)
  warn "${TAKEN} already in use, so open-ctem won't take the public ports 80 and 443."
  hint "It listens on this server only instead: HTTP ${HTTP_PORT}, HTTPS ${HTTPS_PORT}, and the reverse proxy port ${LB_PORT}."
}

# Writes the ports chosen above into .env (a fresh install's or a restored one), once.
apply_port_env() {
  (( PROXY_MODE )) || return 0
  grep -q '^HTTPS_PORT=' "$ENV_FILE" && return 0
  {
    echo
    echo "# ── Ports (80 or 443 were in use at install: a reverse proxy in front) ─────────────"
    echo "PUBLIC_BIND=127.0.0.1:"
    echo "HTTP_PORT=${HTTP_PORT}"
    echo "HTTPS_PORT=${HTTPS_PORT}"
    echo "LB_PORT=${LB_PORT}"
  } >> "$ENV_FILE"
}

# A reverse proxy on this server reaches the listener through Docker's network gateway: trust the client address it
# forwards (X-Forwarded-For) from that address only, so CTEM sees real client IPs. Once, after the stack is up.
trust_local_proxy() {
  (( PROXY_MODE )) || return 0
  grep -q '^LB_TRUSTED_IPS=.' "$ENV_FILE" && return 0
  local net gw
  net=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$(_compose ps -q nginx)" 2>/dev/null | awk '{print $1}')
  gw=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' "$net" 2>/dev/null | awk '{print $1}')
  [[ "$gw" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { warn "Couldn't find Docker's gateway: client IPs behind the proxy show as the proxy."; return 0; }
  echo "LB_TRUSTED_IPS=${gw}" >> "$ENV_FILE"
  _compose up -d --no-deps nginx </dev/null >/dev/null 2>&1 || true
}

# What to point the reverse proxy at, for the end of an install or restore
proxy_hints() {
  (( PROXY_MODE )) || return 0
  echo
  warn "$(echo "${TAKEN:-Ports 80 and 443 are}" | sed 's/ are$/ were/; s/ is$/ was/') already in use, so open-ctem did not take the public ports."
  hint "Point your reverse proxy at:   http://127.0.0.1:${LB_PORT}   (TLS ends at your proxy; send Host and X-Forwarded-For)"
  hint "open-ctem's own HTTPS, for checks on this server: https://127.0.0.1:${HTTPS_PORT}"
  hint "Then set PUBLIC_URL to your proxy's https address, and add its host name to ALLOWED_HOSTS, in ${ENV_FILE}."
}

env_port() {   # the HTTPS port open-ctem publishes (443 unless .env moved it)
  local p
  p=$(grep -m1 '^HTTPS_PORT=' "$ENV_FILE" 2>/dev/null | cut -d= -f2)
  [[ "$p" =~ ^[0-9]{1,5}$ ]] && echo "$p" || echo 443
}

wait_healthy() {
  local secs="${1:-180}" i
  say "Waiting for the app to become healthy (up to $((secs / 60)) minutes)..."
  for ((i = 0; i < secs; i += 3)); do
    if curl -fsk --max-time 5 "https://localhost:$(env_port)/health" >/dev/null 2>&1; then echo; ok "App is healthy."; return 0; fi
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
