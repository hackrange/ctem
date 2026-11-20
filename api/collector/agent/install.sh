#!/usr/bin/env bash
# open-ctem shipper installer
# Ships LDAP, Rapid7 console, CrowdStrike and Splunk telemetry from an internal box to CTEM.
# Settings and sealed passwords live in CTEM; this box keeps its own key and approves destinations.
# Author: Tim Rice <tim.j.rice@hackrange.com>
#
#   sudo bash open-ctem-shipper.sh               install (asks local vs Docker)
#   sudo bash open-ctem-shipper.sh --local       local script mode (Python + systemd + cron)
#   sudo bash open-ctem-shipper.sh --docker      self-contained Docker container
#   sudo bash open-ctem-shipper.sh --test-ctem   just check CTEM is reachable
#   sudo bash open-ctem-shipper.sh --uninstall   remove it again (either mode)
set -euo pipefail
umask 077

CTEM_URL_DEFAULT='@@CTEM_URL@@'
ENROLL_CODE='@@ENROLL_CODE@@'
COLLECTOR_NAME='@@COLLECTOR_NAME@@'
LDAP3_VERSION='2.9.1'
CRYPTO_VERSION='50.0.2'

APP=/opt/open-ctem-collector
CONF=/etc/open-ctem-collector
STATE=/var/lib/open-ctem-collector
SVC_USER=octem-collector
UNIT=open-ctem-collector
CRON=/etc/cron.d/open-ctem-collector
HELPER=/usr/local/bin/open-ctem-collector
IMAGE=open-ctem-collector:local
CTR=open-ctem-collector
VOL=octem-collector-data

c_h=$'\033[1;36m'; c_ok=$'\033[32m'; c_w=$'\033[33m'; c_e=$'\033[31m'; c_0=$'\033[0m'
[[ -t 2 ]] || { c_h=; c_ok=; c_w=; c_e=; c_0=; }
say()  { printf '%s[shipper]%s %s\n' "$c_h" "$c_0" "$*" >&2; }
ok()   { printf '%s  ok%s  %s\n' "$c_ok" "$c_0" "$*" >&2; }
warn() { printf '%s  !!%s  %s\n' "$c_w" "$c_0" "$*" >&2; }
die()  { printf '%s  xx%s  %s\n' "$c_e" "$c_0" "$*" >&2; exit 1; }

STAGE=""
cleanup() { [[ -n "$STAGE" && -d "$STAGE" ]] && { find "$STAGE" -type f -exec shred -u {} + 2>/dev/null || true; rm -rf "$STAGE"; }; }
trap cleanup EXIT

unpack() {
  STAGE=$(mktemp -d /tmp/octem-shipper.XXXXXX)
  chmod 700 "$STAGE"
@@EMBEDDED_FILES@@
}

setup_args() {
  printf '%s\0' --url "$CTEM_URL_DEFAULT" --code "$ENROLL_CODE" --name "$COLLECTOR_NAME"
}

pick_python() {
  local py
  for py in python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$py" >/dev/null && "$py" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
      command -v "$py"; return 0
    fi
  done
  return 1
}

proxy_env() {
  local v
  for v in https_proxy HTTPS_PROXY no_proxy NO_PROXY; do
    [[ -n "${!v:-}" ]] && printf '%s=%s\n' "$v" "${!v}"
  done
  return 0
}

# ── uninstall (both modes) ────────────────────────────────────────────────────
uninstall() {
  say "Removing the shipper"
  rm -f "$CRON" "$HELPER"
  if command -v systemctl >/dev/null; then
    systemctl stop "$UNIT.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/$UNIT.service"
    systemctl daemon-reload 2>/dev/null || true
  fi
  if command -v docker >/dev/null; then
    docker rm -f "$CTR" >/dev/null 2>&1 || true
    docker volume rm "$VOL" >/dev/null 2>&1 || true
    docker rmi "$IMAGE" >/dev/null 2>&1 || true
  fi
  [[ -d "$CONF" ]] && find "$CONF" -type f -exec shred -u {} + 2>/dev/null || true
  [[ -d "$STATE" ]] && find "$STATE" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$APP" "$CONF" "$STATE"
  id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" 2>/dev/null || true
  ok "removed. Revoke it in CTEM too: Shippers > Revoke."
}

# ── local script mode: venv + systemd oneshot + cron ─────────────────────────
pip_or_os() {
  # $1 import name, $2 pip spec, $3 distro package
  "$APP/venv/bin/python" -c "import $1" 2>/dev/null && return 0
  "$APP/venv/bin/pip" install --quiet --disable-pip-version-check "$2" 2>/dev/null && return 0
  if command -v apt-get >/dev/null; then apt-get install -y -qq "$3" >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null; then dnf install -y -q "$3" >/dev/null 2>&1 || true
  elif command -v yum >/dev/null; then yum install -y -q "$3" >/dev/null 2>&1 || true
  fi
  "$APP/venv/bin/python" -c "import $1" 2>/dev/null
}

install_deps() {
  say "Installing Python dependencies into $APP/venv"
  pip_or_os cryptography "cryptography==$CRYPTO_VERSION" python3-cryptography \
    || die "couldn't install 'cryptography' (needed for sealed secrets). Offline? $APP/venv/bin/pip install --no-index --find-links DIR cryptography"
  ok "cryptography ready"
  if pip_or_os ldap3 "ldap3==$LDAP3_VERSION" python3-ldap3; then ok "ldap3 ready"
  else warn "ldap3 unavailable; the LDAP source won't work until it's installed into $APP/venv"; fi
}

write_unit() {
  local creds_line="$1" line
  cat > "/etc/systemd/system/$UNIT.service" <<UNIT
[Unit]
Description=open-ctem shipper (checks in with CTEM, ships internal telemetry when due)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=$SVC_USER
Group=$SVC_USER
ExecStart=$APP/venv/bin/python $APP/ctem_collector.py run
$creds_line
StateDirectory=open-ctem-collector
StateDirectoryMode=0700
TimeoutStartSec=3h
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
UNIT
  while IFS= read -r line; do
    [[ -n "$line" ]] && printf 'Environment=%s\n' "$line" >> "/etc/systemd/system/$UNIT.service"
  done < <(proxy_env)
  systemctl daemon-reload
}

store_identity() {
  # The shipper's private key + CTEM token. systemd-creds seals it with the host key (and TPM when present)
  if command -v systemd-creds >/dev/null && systemd-creds encrypt --name=octem-identity \
       "$STAGE/out/identity.json" "$CONF/identity.cred" >/dev/null 2>&1; then
    chmod 600 "$CONF/identity.cred"
    rm -f "$CONF/identity.json"
    ok "shipper key sealed with systemd-creds ($CONF/identity.cred)"
    echo "LoadCredentialEncrypted=octem-identity:$CONF/identity.cred"
  else
    install -m 600 -o "$SVC_USER" -g "$SVC_USER" "$STAGE/out/identity.json" "$CONF/identity.json"
    warn "systemd-creds not available; the shipper key is in $CONF/identity.json (mode 600, $SVC_USER only)"
    echo ""
  fi
}

install_cron() {
  # Every 15 minutes the shipper checks in; it only ships when CTEM's schedule says it's due
  printf '# open-ctem shipper: check in with CTEM, ship when due. The schedule lives in CTEM.\n*/15 * * * * root systemctl start --no-block %s.service\n' \
    "$UNIT" > "$CRON"
  chmod 644 "$CRON"
  ok "cron check-in every 15 minutes ($CRON)"
}

write_local_helper() {
  local props="-p User=$SVC_USER -p StateDirectory=open-ctem-collector"
  [[ -n "$1" ]] && props="$props -p $1"
  cat > "$HELPER" <<HELP
#!/usr/bin/env bash
# Day-two helper for the open-ctem shipper (local script mode)
PY="$APP/venv/bin/python $APP/ctem_collector.py"
case "\${1:-}" in
  run-now)   exec systemd-run --quiet --pipe --wait --collect $props \$PY run --force ;;
  approve)   exec \$PY approve ;;
  secrets)   exec \$PY secrets "\${@:2}" ;;
  test)      exec \$PY test ;;
  test-ctem) exec \$PY test-ctem ;;
  status)    systemctl status $UNIT.service --no-pager; exit 0 ;;
  logs)      exec journalctl -u $UNIT.service -n "\${2:-100}" --no-pager ;;
  *) echo "usage: open-ctem-collector run-now|approve|secrets [--all]|test|test-ctem|status|logs [n]"; exit 2 ;;
esac
HELP
  chmod 755 "$HELPER"
}

install_local() {
  command -v systemctl >/dev/null || die "local script mode needs systemd (or use --docker)"
  local py creds_line a args=()
  py=$(pick_python) || die "need Python 3.9 or newer (apt/dnf install python3)"
  "$py" -c 'import venv, ensurepip' 2>/dev/null || {
    command -v apt-get >/dev/null && apt-get install -y -qq python3-venv >/dev/null 2>&1 || true
    "$py" -c 'import venv, ensurepip' 2>/dev/null || die "Python venv support missing (install python3-venv)"
  }
  ok "using $("$py" -V 2>&1)"
  id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER"
  install -d -m 755 "$APP"
  install -m 644 "$STAGE"/*.py "$APP/"
  [[ -x "$APP/venv/bin/python" ]] || "$py" -m venv --system-site-packages "$APP/venv"
  install_deps

  while IFS= read -r -d '' a; do args+=("$a"); done < <(setup_args)
  install -d -m 700 "$STAGE/out"
  "$APP/venv/bin/python" "$APP/ctem_collector.py" setup "${args[@]}" --out-dir "$STAGE/out" </dev/tty \
    || die "setup didn't finish; nothing was installed as a service"

  say "Installing (local script mode)"
  install -d -m 750 -o root -g "$SVC_USER" "$CONF"
  install -m 640 -o root -g "$SVC_USER" "$STAGE/out/collector.json" "$CONF/collector.json"
  if [[ -f "$STAGE/out/pins.json" ]]; then install -m 640 -o root -g "$SVC_USER" "$STAGE/out/pins.json" "$CONF/pins.json"; fi
  creds_line=$(store_identity)
  write_unit "$creds_line"
  install_cron
  write_local_helper "$creds_line"

  say "First shipment"
  if "$HELPER" run-now; then ok "first run finished"
  else warn "first run reported a problem; see: open-ctem-collector logs"; fi
}

# ── self-contained Docker mode ────────────────────────────────────────────────
host_ca_args() {
  # Hand the host's trust store to the container so a corporate CA keeps working
  local f
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    if [[ -r "$f" ]]; then printf '%s\0' -v "$f:/etc/ssl/host-ca.pem:ro" -e SSL_CERT_FILE=/etc/ssl/host-ca.pem; return; fi
  done
}

write_docker_helper() {
  cat > "$HELPER" <<HELP
#!/usr/bin/env bash
# Day-two helper for the open-ctem shipper (Docker mode)
case "\${1:-}" in
  run-now)   exec docker exec $CTR python /app/ctem_collector.py run --force ;;
  approve)   exec docker exec -it $CTR python /app/ctem_collector.py approve ;;
  secrets)   exec docker exec -it $CTR python /app/ctem_collector.py secrets "\${@:2}" ;;
  test)      exec docker exec $CTR python /app/ctem_collector.py test ;;
  test-ctem) exec docker exec $CTR python /app/ctem_collector.py test-ctem ;;
  status)    exec docker ps -a --filter name=^/$CTR\$ ;;
  logs)      exec docker logs --tail "\${2:-100}" $CTR ;;
  *) echo "usage: open-ctem-collector run-now|approve|secrets [--all]|test|test-ctem|status|logs [n]"; exit 2 ;;
esac
HELP
  chmod 755 "$HELPER"
}

install_docker() {
  command -v docker >/dev/null || die "Docker isn't installed (or use --local)"
  docker info >/dev/null 2>&1 || die "can't talk to the Docker daemon"
  local host line a common=() args=()
  host=$(hostname -f 2>/dev/null || hostname)
  common=(-e "OCTEM_HOST=$host" -v "$VOL:/data")
  while IFS= read -r -d '' line; do common+=("$line"); done < <(host_ca_args)
  while IFS= read -r line; do [[ -n "$line" ]] && common+=(-e "$line"); done < <(proxy_env)

  say "Building the shipper image locally ($IMAGE)"
  docker build -q -t "$IMAGE" "$STAGE" >/dev/null || die "image build failed (the build needs to reach PyPI once)"
  ok "image built"
  docker volume create "$VOL" >/dev/null

  while IFS= read -r -d '' a; do args+=("$a"); done < <(setup_args)
  docker run --rm -it --cap-drop ALL --security-opt no-new-privileges:true "${common[@]}" "$IMAGE" \
    setup "${args[@]}" --out-dir /data/config </dev/tty || die "setup didn't finish; nothing was started"

  say "Starting the shipper container"
  docker rm -f "$CTR" >/dev/null 2>&1 || true
  docker run -d --name "$CTR" --restart unless-stopped \
    --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --cap-drop ALL --security-opt no-new-privileges:true --memory 512m --pids-limit 128 \
    --log-opt max-size=10m --log-opt max-file=3 \
    "${common[@]}" "$IMAGE" daemon >/dev/null
  ok "container $CTR is running; it checks in with CTEM every 15 minutes"
  write_docker_helper
  "$HELPER" run-now || warn "first run reported a problem; see: open-ctem-collector logs"
  warn "Docker mode keeps the shipper key in the $VOL volume (mode 600, container user only); local mode seals it with systemd-creds"
}

choose_mode() {
  local ans
  if ! { command -v docker >/dev/null && docker info >/dev/null 2>&1; }; then echo local; return; fi
  printf '\nHow should the shipper run?\n  1) Local script mode (Python + systemd + cron, key sealed with systemd-creds)\n  2) Self-contained Docker container\n' >/dev/tty
  while true; do
    read -r -p "Pick 1 or 2 [1]: " ans </dev/tty
    case "${ans:-1}" in 1) echo local; return ;; 2) echo docker; return ;; esac
  done
}

main() {
  local mode=""
  case "${1:-}" in
    --uninstall) [[ $EUID -eq 0 ]] || die "run as root"; uninstall; exit 0 ;;
    --test-ctem)
      unpack; PY=$(pick_python) || die "need Python 3.9+"
      "$PY" "$STAGE/ctem_collector.py" test-ctem --url "${2:-$CTEM_URL_DEFAULT}"; exit $? ;;
    --local) mode=local ;;
    --docker) mode=docker ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    "") ;;
    *) die "unknown option $1 (try --help)" ;;
  esac
  [[ $EUID -eq 0 ]] || die "run as root (sudo bash $0)"
  [[ -n "$mode" ]] || mode=$(choose_mode)
  unpack
  if [[ "$mode" == docker ]]; then install_docker; else install_local; fi
  say "Day-two: open-ctem-collector approve | secrets | run-now | test | status | logs"
  say "Passwords rotate in CTEM > Shippers; destination changes need 'open-ctem-collector approve' here."
}

main "$@"
