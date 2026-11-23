# shellcheck shell=bash
# Admin > Maintenance needs a root-side helper: the app asks, this agent runs install.sh --backup/--restore.
# Author: Tim Rice <tim.j.rice@hackrange.com>

AGENT_PY="${INSTALL_DIR}/api/maintenance/host_agent.py"
UNIT_DIR=/etc/systemd/system

# One backup, restore or upgrade at a time, whether it came from the command line or the web page
maintenance_lock() {
  install -d -m 755 "${INSTALL_DIR}/run"
  exec 9>"${INSTALL_DIR}/run/.maintenance.lock"
  flock -n 9 && return 0
  say "Waiting for another backup, restore or upgrade to finish..."
  flock -w 7200 9 || die "Another backup, restore or upgrade is still running."
}

setup_maintenance() {
  [[ "$INSTALL_DIR" =~ ^/[A-Za-z0-9/_.-]+$ ]] \
    || { warn "Admin > Maintenance needs an install path without spaces or odd characters; skipping its agent."; return 0; }
  python3 -I "$AGENT_PY" setup --root "$INSTALL_DIR" || die "Could not set up the maintenance folders."
  if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then
    warn "No systemd here, so Admin > Maintenance can't run backups. install.sh --backup still works."
    return 0
  fi
  cat > "${UNIT_DIR}/ctem-maintenance.service" <<UNIT
[Unit]
Description=open-ctem maintenance agent (backups and restores for Admin > Maintenance)
After=docker.service
Wants=docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I ${AGENT_PY} run --root ${INSTALL_DIR}
TimeoutStartSec=12h
UMask=0027
UNIT
  cat > "${UNIT_DIR}/ctem-maintenance.path" <<UNIT
[Unit]
Description=Wake the open-ctem maintenance agent when the web page queues a request

[Path]
DirectoryNotEmpty=${INSTALL_DIR}/run/spool/inbox
Unit=ctem-maintenance.service

[Install]
WantedBy=multi-user.target
UNIT
  cat > "${UNIT_DIR}/ctem-maintenance.timer" <<UNIT
[Unit]
Description=Check in and run scheduled open-ctem backups every 5 minutes

[Timer]
OnBootSec=2min
OnUnitInactiveSec=5min
Unit=ctem-maintenance.service

[Install]
WantedBy=timers.target
UNIT
  chmod 644 "${UNIT_DIR}"/ctem-maintenance.{service,path,timer}
  systemctl daemon-reload
  systemctl enable --now ctem-maintenance.path ctem-maintenance.timer >/dev/null 2>&1 \
    || { warn "Could not start the maintenance agent: systemctl status ctem-maintenance.path"; return 0; }
  # check in now so the page shows it as ready right away
  systemctl start --no-block ctem-maintenance.service >/dev/null 2>&1 || true
  ok "Maintenance agent ready (Admin > Maintenance)."
}
