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
#   sudo bash open-ctem-shipper.sh --upgrade     new shipper code, same key, passwords and approvals
#                                                (plain runs on a box that already has a shipper do this too)
#   sudo bash open-ctem-shipper.sh --reinstall   enroll from scratch even though one is installed
#   sudo bash open-ctem-shipper.sh --uninstall   remove it again (either mode)
set -euo pipefail
umask 077

CTEM_URL_DEFAULT='@@CTEM_URL@@'
ENROLL_CODE='@@ENROLL_CODE@@'
COLLECTOR_NAME='@@COLLECTOR_NAME@@'
AGENT_VERSION='@@AGENT_VERSION@@'
LDAP3_VERSION='2.9.1'
CRYPTO_VERSION='50.0.2'
BOTO3_VERSION='1.43.120'

APP=/opt/open-ctem-collector
SOURCES='ldap rapid7_console crowdstrike splunk netprobe alert_actions'
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
  for py in python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
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
    systemctl stop "$UNIT-source@*.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/$UNIT.service" "/etc/systemd/system/$UNIT-source@.service"
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
  if pip_or_os boto3 "boto3==$BOTO3_VERSION" python3-boto3; then ok "boto3 ready (Falcon Data Replicator)"
  else warn "boto3 unavailable; only Falcon Data Replicator needs it"; fi
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

write_source_unit() {
  # One instance per source (open-ctem-collector-source@<kind>), so sources run side by side: a long console pass
  # never holds up the EDR. Same user, sealed key, sandbox and proxy settings as the main unit.
  [[ -f "/etc/systemd/system/$UNIT.service" ]] || return 0
  sed -e "s|^Description=.*|Description=open-ctem shipper source %i|" \
      -e "s|ctem_collector.py run\$|ctem_collector.py run --only %i|" \
      -e "s|^TimeoutStartSec=.*|TimeoutStartSec=6h|" \
      "/etc/systemd/system/$UNIT.service" > "/etc/systemd/system/$UNIT-source@.service"
  systemctl daemon-reload
}

install_cron() {
  # Every 5 minutes each source's instance is started; one still running from before is left alone (start on an
  # active unit is a no-op), and each ships only when its own schedule in CTEM says so
  write_source_unit
  printf '# open-ctem shipper: each source checks in and ships when due, side by side. Schedules live in CTEM.\n*/5 * * * * root for k in %s; do systemctl start --no-block %s-source@$k.service; done\n' \
    "$SOURCES" "$UNIT" > "$CRON"
  chmod 644 "$CRON"
  ok "cron check-in every 5 minutes, each source in parallel ($CRON)"
}

write_local_helper() {
  local props="-p User=$SVC_USER -p StateDirectory=open-ctem-collector"
  [[ -n "$1" ]] && props="$props -p $1"
  cat > "$HELPER" <<HELP
#!/usr/bin/env bash
# Day-two helper for the open-ctem shipper (local script mode)
PY="$APP/venv/bin/python $APP/ctem_collector.py"
case "\${1:-}" in
  run-now)   exec systemd-run --quiet --pipe --wait --collect $props \$PY run --force "\${@:2}" ;;
  probe)     exec systemd-run --quiet --pipe --wait --collect $props \$PY probe "\${@:2}" ;;
  approve)   exec \$PY approve ;;
  set-url)   exec \$PY set-url "\${@:2}" ;;
  secrets)   exec \$PY secrets "\${@:2}" ;;
  test)      exec \$PY test ;;
  test-ctem) exec \$PY test-ctem ;;
  status)    systemctl status "$UNIT.service" "$UNIT-source@*.service" --no-pager; exit 0 ;;
  logs)      exec journalctl -u "$UNIT.service" -u "$UNIT-source@*.service" -n "\${2:-100}" --no-pager ;;
  *) echo "usage: open-ctem-collector run-now [--only SOURCE]|probe [--dry-run]|approve|secrets [--all]|set-url URL|test|test-ctem|status|logs [n]"; exit 2 ;;
esac
HELP
  chmod 755 "$HELPER"
}

install_code() {
  local py
  py=$(pick_python) || die "need Python 3.9 or newer (apt/dnf install python3)"
  "$py" -c 'import venv, ensurepip' 2>/dev/null || {
    command -v apt-get >/dev/null && apt-get install -y -qq python3-venv >/dev/null 2>&1 || true
    "$py" -c 'import venv, ensurepip' 2>/dev/null || die "Python venv support missing (install python3-venv)"
  }
  ok "using $("$py" -V 2>&1)"
  id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER"
  install -d -m 755 "$APP"
  install -m 644 "$STAGE"/*.py "$APP/"
  # umask 077 is for keys; the service user still has to run this venv
  (
    umask 022
    [[ -x "$APP/venv/bin/python" ]] || "$py" -m venv --system-site-packages "$APP/venv"
    install_deps
  )
  chown -R root:root "$APP"
  chmod -R u=rwX,go=rX "$APP"
  runuser -u "$SVC_USER" -- "$APP/venv/bin/python" -c 'import cryptography' \
    || die "the service user can't run $APP/venv/bin/python (check mount options and SELinux on $APP)"
}

install_local() {
  command -v systemctl >/dev/null || die "local script mode needs systemd (or use --docker)"
  local creds_line a args=()
  install_code

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
  run-now)   exec docker exec $CTR python /app/ctem_collector.py run --force "\${@:2}" ;;
  probe)     exec docker exec $CTR python /app/ctem_collector.py probe "\${@:2}" ;;
  approve)   exec docker exec -it $CTR python /app/ctem_collector.py approve ;;
  set-url)   exec docker exec -it $CTR python /app/ctem_collector.py set-url "\${@:2}" ;;
  secrets)   exec docker exec -it $CTR python /app/ctem_collector.py secrets "\${@:2}" ;;
  test)      exec docker exec $CTR python /app/ctem_collector.py test ;;
  test-ctem) exec docker exec $CTR python /app/ctem_collector.py test-ctem ;;
  status)    exec docker ps -a --filter name=^/$CTR\$ ;;
  logs)      exec docker logs --tail "\${2:-100}" $CTR ;;
  *) echo "usage: open-ctem-collector run-now [--only SOURCE]|probe [--dry-run]|approve|secrets [--all]|set-url URL|test|test-ctem|status|logs [n]"; exit 2 ;;
esac
HELP
  chmod 755 "$HELPER"
}

COMMON=()
docker_prep() {
  command -v docker >/dev/null || die "Docker isn't installed (or use --local)"
  docker info >/dev/null 2>&1 || die "can't talk to the Docker daemon"
  local host line
  host=$(hostname -f 2>/dev/null || hostname)
  COMMON=(-e "OCTEM_HOST=$host" -v "$VOL:/data")
  while IFS= read -r -d '' line; do COMMON+=("$line"); done < <(host_ca_args)
  while IFS= read -r line; do [[ -n "$line" ]] && COMMON+=(-e "$line"); done < <(proxy_env)
  say "Building the shipper image locally ($IMAGE)"
  docker build -q -t "$IMAGE" "$STAGE" >/dev/null || die "image build failed (the build needs to reach PyPI once)"
  ok "image built"
}

start_container() {
  say "Starting the shipper container"
  docker rm -f "$CTR" >/dev/null 2>&1 || true
  docker run -d --name "$CTR" --restart unless-stopped \
    --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --cap-drop ALL --security-opt no-new-privileges:true --memory 512m --pids-limit 128 \
    --log-opt max-size=10m --log-opt max-file=3 \
    "${COMMON[@]}" "$IMAGE" daemon >/dev/null
  ok "container $CTR is running; it checks in with CTEM every 5 minutes"
  write_docker_helper
}

install_docker() {
  local a args=()
  docker_prep
  docker volume create "$VOL" >/dev/null

  while IFS= read -r -d '' a; do args+=("$a"); done < <(setup_args)
  docker run --rm -it --cap-drop ALL --security-opt no-new-privileges:true "${COMMON[@]}" "$IMAGE" \
    setup "${args[@]}" --out-dir /data/config </dev/tty || die "setup didn't finish; nothing was started"

  start_container
  "$HELPER" run-now || warn "first run reported a problem; see: open-ctem-collector logs"
  warn "Docker mode keeps the shipper key in the $VOL volume (mode 600, container user only); local mode seals it with systemd-creds"
}

existing_install() {
  [[ -f "$CONF/collector.json" ]] && return 0
  command -v docker >/dev/null && docker volume inspect "$VOL" >/dev/null 2>&1
}

upgrade() {
  # New code only: the key, passwords, approvals and schedule all stay put
  if [[ -f "$CONF/collector.json" ]]; then
    say "Upgrading the shipper code (local script mode)"
    install_code
    install_cron
    ok "code updated in $APP; key and approvals in $CONF untouched"
    "$HELPER" run-now || warn "run reported a problem; see: open-ctem-collector logs"
  elif command -v docker >/dev/null && docker volume inspect "$VOL" >/dev/null 2>&1; then
    say "Upgrading the shipper image (Docker mode)"
    docker_prep
    start_container
    "$HELPER" run-now || warn "run reported a problem; see: open-ctem-collector logs"
  else
    die "no shipper installed here to upgrade; run without --upgrade to install one"
  fi
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
  say "open-ctem shipper installer, agent version $AGENT_VERSION"
  case "${1:-}" in
    --uninstall) [[ $EUID -eq 0 ]] || die "run as root"; uninstall; exit 0 ;;
    --upgrade) [[ $EUID -eq 0 ]] || die "run as root"; unpack; upgrade; exit 0 ;;
    --test-ctem)
      unpack; PY=$(pick_python) || die "need Python 3.9+"
      "$PY" "$STAGE/ctem_collector.py" test-ctem --url "${2:-$CTEM_URL_DEFAULT}"; exit $? ;;
    --local) mode=local ;;
    --docker) mode=docker ;;
    --reinstall) mode=reinstall ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    "") ;;
    *) die "unknown option $1 (try --help)" ;;
  esac
  [[ $EUID -eq 0 ]] || die "run as root (sudo bash $0)"
  # Already installed? Then this is an update: keep the key, passwords, approvals and sources
  if [[ "$mode" != reinstall ]] && existing_install; then
    say "Found an existing shipper on this box; upgrading it in place (nothing to re-enter)."
    say "To enroll from scratch instead, uninstall first or use --reinstall."
    unpack; upgrade; exit 0
  fi
  if [[ "$mode" == reinstall ]]; then
    warn "--reinstall makes a new key: passwords must be entered again and destinations re-approved"
    mode=""
  fi
  [[ -n "$mode" ]] || mode=$(choose_mode)
  unpack
  if [[ "$mode" == docker ]]; then install_docker; else install_local; fi
  say "Day-two: open-ctem-collector approve | secrets | set-url | run-now | test | status | logs"
  say "Passwords rotate in CTEM > Shippers; destination changes need 'open-ctem-collector approve' here."
}

main "$@"
