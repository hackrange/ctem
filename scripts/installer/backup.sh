# shellcheck shell=bash
# Encrypted full backup: database, .env (keys included), TLS cert, local overrides and uploads.
# Author: Tim Rice <tim.j.rice@hackrange.com>

# Ask twice for a password the archive tool accepts
prompt_new_password() {
  local a b
  while true; do
    a=$(read_secret "Backup password (16+ characters):")
    b=$(read_secret "Same password again:")
    [[ "$a" == "$b" ]] || { warn "Those did not match."; continue; }
    if CTEM_BACKUP_PASSWORD="$a" archive check-password; then printf '%s' "$a"; return 0; fi
  done
}

# do_backup <custom 0|1> <out dir> ; sets BACKUP_FILE
do_backup() {
  local custom="$1" outdir="${2:-${INSTALL_DIR}/backups}" pw db_user db_name tsv stamp tmp rc
  [[ -f "$ENV_FILE" ]] || die "No open-ctem install at ${INSTALL_DIR} (no .env)."
  _compose ps --status running --services 2>/dev/null | grep -qx db || die "The database container is not running."

  if [[ -n "${CTEM_BACKUP_PASSWORD:-}" ]]; then
    pw="$CTEM_BACKUP_PASSWORD"
  elif (( custom )); then
    pw=$(prompt_new_password)
  else
    pw=$(env_get BACKUP_ENCRYPTION_PASSWORD)
    [[ -n "$pw" ]] || die "No BACKUP_ENCRYPTION_PASSWORD in .env. Add one, or run with --password to type one."
  fi
  CTEM_BACKUP_PASSWORD="$pw" archive check-password || die "Pick a stronger backup password."

  db_user=$(env_get DB_USER); db_user=${db_user:-openctem}
  db_name=$(env_get DB_NAME); db_name=${db_name:-openctem}
  tsv=$(_compose exec -T db psql -X -U "$db_user" -d "$db_name" -Atc \
        "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'" </dev/null | tr -d '\r') \
    || die "Could not read from the database."

  # The app reads ./backups (group root, read-only mount) to list and download them; anywhere else stays root-only
  local dmode=700 fmode=600
  [[ "$(realpath -m -- "$outdir")" != "$(realpath -m -- "${INSTALL_DIR}/backups")" ]] || { dmode=750; fmode=640; }
  mkdir -p "$outdir"; chmod "$dmode" "$outdir"
  stamp=$(date -u +%Y%m%d-%H%M%SZ)
  BACKUP_FILE="${outdir%/}/ctem-$(hostname -s)-${stamp}.ctembak"
  tmp=$(mktemp -d); chmod 700 "$tmp"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  local adds=(--add "env/dotenv=${ENV_FILE}")
  [[ -f "${INSTALL_DIR}/docker/certs/server.crt" ]] && adds+=(--add "host/certs/server.crt=${INSTALL_DIR}/docker/certs/server.crt")
  [[ -f "${INSTALL_DIR}/docker/certs/server.key" ]] && adds+=(--add "host/certs/server.key=${INSTALL_DIR}/docker/certs/server.key")
  [[ -f "${INSTALL_DIR}/docker/docker-compose.override.yml" ]] \
    && adds+=(--add "host/docker-compose.override.yml=${INSTALL_DIR}/docker/docker-compose.override.yml")
  # nginx.conf is tracked, so only a local edit is worth carrying
  git -C "$INSTALL_DIR" diff --quiet HEAD -- docker/nginx.conf 2>/dev/null \
    || adds+=(--add "host/nginx.conf=${INSTALL_DIR}/docker/nginx.conf")

  say "Backing up to ${BACKUP_FILE}"
  # Streams go straight into the encrypted file; exit codes land in files because <() hides them
  CTEM_BACKUP_PASSWORD="$pw" archive pack --out "$BACKUP_FILE" "${adds[@]}" \
    --add "volumes/app_uploads.tar=/dev/fd/3" \
    --add "db/openctem.dump=/dev/fd/4" \
    --meta "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" --meta "host=$(hostname -f 2>/dev/null || hostname)" \
    --meta "git_commit=$(git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null || echo unknown)" \
    --meta "app_version=$(app_version)" --meta "timescaledb=${tsv}" --meta "db_name=${db_name}" \
    3< <(_compose run --rm --no-deps -T --user 0 --entrypoint tar app -C /app/uploads -cf - . </dev/null; echo $? > "$tmp/tar.rc") \
    4< <(_compose exec -T db pg_dump -U "$db_user" -d "$db_name" -Fc </dev/null 2>"$tmp/dump.err"; echo $? > "$tmp/dump.rc") \
    && rc=0 || rc=$?
  local i
  for ((i = 0; i < 60; i++)); do [[ -s "$tmp/dump.rc" && -s "$tmp/tar.rc" ]] && break; sleep 1; done
  if (( rc != 0 )) || [[ "$(cat "$tmp/dump.rc" 2>/dev/null)" != 0 || "$(cat "$tmp/tar.rc" 2>/dev/null)" != 0 ]]; then
    rm -f "$BACKUP_FILE"
    grep -v '^pg_dump: \(warning\|detail\|hint\)' "$tmp/dump.err" 2>/dev/null | head -n5 >&2 || true
    die "Backup failed; nothing was kept."
  fi

  say "Checking the backup opens and every file inside matches its checksum..."
  CTEM_BACKUP_PASSWORD="$pw" archive verify --in "$BACKUP_FILE" >/dev/null || { rm -f "$BACKUP_FILE"; die "The new backup did not verify; nothing was kept."; }
  chown 0:0 "$BACKUP_FILE"; chmod "$fmode" "$BACKUP_FILE"
  ok "Backup ready: ${BACKUP_FILE} ($(du -h "$BACKUP_FILE" | cut -f1))"
  if (( custom )); then
    hint "It opens only with the password you just typed. Keep it in a password manager."
  else
    hint "It opens with BACKUP_ENCRYPTION_PASSWORD from ${ENV_FILE}. Keep a copy of that password off this server."
  fi
}

app_version() {
  grep -oE 'app_version: str = "[^"]+"' "${INSTALL_DIR}/api/core/config.py" 2>/dev/null | cut -d'"' -f2
}
