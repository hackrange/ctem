# shellcheck shell=bash
# Rebuild a server from a .ctembak: settings, keys, cert, database and uploads.
# Author: Tim Rice <tim.j.rice@hackrange.com>

_manifest() {
  python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$RESTORE_TMP/manifest.json" "$1"
}

# Ask for the backup password until it opens the file; checks every byte of it on the way
_open_backup() {
  local file="$1" tries=0 pw rc
  while true; do
    if [[ -n "${CTEM_BACKUP_PASSWORD:-}" ]]; then pw="$CTEM_BACKUP_PASSWORD"; else pw=$(read_secret "Password for $(basename "$file"):"); fi
    rm -rf "${RESTORE_TMP:?}"/*
    say "Opening the backup and checking every byte of it..."
    CTEM_BACKUP_PASSWORD="$pw" archive extract --in "$file" --dest "$RESTORE_TMP" \
      --skip db/openctem.dump --skip volumes/app_uploads.tar && rc=0 || rc=$?
    if (( rc == 0 )); then RESTORE_PW="$pw"; return 0; fi
    tries=$((tries + 1))
    [[ -z "${CTEM_BACKUP_PASSWORD:-}" && $tries -lt 3 ]] || die "Could not open the backup."
  done
}

# Refuse a backup taken on newer code than this checkout; schema only ever moves forward
_check_version() {
  local commit ver here
  commit=$(_manifest git_commit); ver=$(_manifest app_version); here=$(app_version)
  if [[ "$commit" =~ ^[0-9a-f]{40}$ ]] && git -C "$INSTALL_DIR" cat-file -e "${commit}^{commit}" 2>/dev/null; then
    git -C "$INSTALL_DIR" merge-base --is-ancestor "$commit" HEAD \
      || die "This backup was taken on newer open-ctem code (${commit:0:8}) than this checkout. Update the code first."
    ok "Backup code version ${commit:0:8} is at or behind this checkout."
  elif [[ -n "$ver" && "$(printf '%s\n%s\n' "$ver" "$here" | sort -V | tail -n1)" != "$here" ]]; then
    die "This backup came from open-ctem ${ver}, newer than this checkout (${here})."
  else
    warn "Backup commit ${commit:0:8} is not in this checkout; it says version ${ver:-unknown}, this is ${here}."
  fi
}

# The backup's .env, with this server's own database and Redis passwords (new ones on a bare server)
_build_env() {
  local src="$RESTORE_TMP/env/dotenv" out="$1" mode="$2" k db_user db_name db_pw redis_pw lb
  [[ -f "$src" ]] || die "The backup has no .env inside it."
  for k in ENCRYPTION_KEY ENCRYPTION_SEARCH_KEY SECRET_KEY; do
    [[ "$(env_get "$k" "$src")" =~ ^[0-9a-fA-F]{64}$ ]] || die "The backup's ${k} is missing or malformed."
  done
  install -m 600 "$src" "$out"
  if [[ "$mode" == fresh ]]; then
    db_user=$(env_get DB_USER "$src"); db_name=$(env_get DB_NAME "$src"); db_pw=$(genpass); redis_pw=$(genpass)
  else
    db_user=$(env_get DB_USER); db_name=$(env_get DB_NAME); db_pw=$(env_get DB_PASSWORD); redis_pw=$(env_get REDIS_PASSWORD)
  fi
  db_user=${db_user:-openctem}; db_name=${db_name:-openctem}
  [[ "$db_user" =~ ^[a-z_][a-z0-9_]{0,62}$ && "$db_name" =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "Unexpected DB_USER or DB_NAME."
  env_set DB_USER "$db_user" "$out"; env_set DB_NAME "$db_name" "$out"; env_set DB_PASSWORD "$db_pw" "$out"
  env_set DATABASE_URL "postgresql+asyncpg://${db_user}:${db_pw}@db:5432/${db_name}" "$out"
  env_set REDIS_PASSWORD "$redis_pw" "$out"
  env_set REDIS_URL "redis://:${redis_pw}@redis:6379/0" "$out"
  [[ -n "$(env_get BACKUP_ENCRYPTION_PASSWORD "$out")" ]] || env_set BACKUP_ENCRYPTION_PASSWORD "$(gen_backup_pw)" "$out"
  # The load balancer address belongs to the old box; binding to an address we don't have stops nginx cold
  lb=$(env_get LB_BIND_IP "$out")
  if [[ -n "$lb" ]] && ! ip -o addr show 2>/dev/null | grep -qw "inet ${lb}/[0-9]*"; then
    sed -i "s/^LB_BIND_IP=/#LB_BIND_IP=/" "$out"
    warn "LB_BIND_IP ${lb} is not on this server, so it was commented out in .env. Set it if you use a load balancer."
  fi
}

_put_host_files() {
  local d="$RESTORE_TMP/host"
  if [[ -f "$d/certs/server.crt" && -f "$d/certs/server.key" ]]; then
    install -d -m 755 "${INSTALL_DIR}/docker/certs"
    install -m 644 "$d/certs/server.crt" "${INSTALL_DIR}/docker/certs/server.crt"
    install -m 600 "$d/certs/server.key" "${INSTALL_DIR}/docker/certs/server.key"
    ok "TLS certificate restored."
  fi
  if [[ -f "$d/docker-compose.override.yml" ]]; then
    install -m 644 "$d/docker-compose.override.yml" "${INSTALL_DIR}/docker/docker-compose.override.yml"
    ok "docker-compose.override.yml restored."
  fi
  if [[ -f "$d/nginx.conf" ]]; then
    install -m 644 "$d/nginx.conf" "${INSTALL_DIR}/docker/nginx.conf"
    warn "Restored a locally edited docker/nginx.conf. Commit or stash it before the next --upgrade."
  fi
  make_self_signed_cert
}

_load_database() {
  local file="$1" db_user db_name tsv have
  db_user=$(env_get DB_USER); db_name=$(env_get DB_NAME); tsv=$(_manifest timescaledb)
  [[ "$tsv" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]] || die "The backup does not say which TimescaleDB version it used."
  psql_db() { _compose exec -T db psql -X -q -v ON_ERROR_STOP=1 -U "$db_user" "$@" </dev/null; }
  have=$(psql_db -d postgres -Atc "SELECT 1 FROM pg_available_extension_versions WHERE name = 'timescaledb' AND version = '${tsv}'" | tr -d '\r')
  [[ "$have" == 1 ]] || die "The backup uses TimescaleDB ${tsv}, which this database image does not have. Update open-ctem first."

  say "Recreating database ${db_name}..."
  psql_db -d postgres -c "DROP DATABASE IF EXISTS \"${db_name}\" WITH (FORCE)" \
    -c "CREATE DATABASE \"${db_name}\" TEMPLATE template0 ENCODING 'UTF8'" || die "Could not recreate the database."
  psql_db -d "$db_name" -c "CREATE EXTENSION timescaledb VERSION '${tsv}'" -c "SELECT timescaledb_pre_restore()" >/dev/null \
    || die "Could not prepare TimescaleDB."

  say "Loading the database (a large one takes a while)..."
  CTEM_BACKUP_PASSWORD="$RESTORE_PW" archive cat --in "$file" --name db/openctem.dump \
    | _compose exec -T db pg_restore -U "$db_user" -d "$db_name" --no-owner --no-acl --exit-on-error \
    || die "Loading the database failed. Nothing else was changed; fix the cause and run the restore again."
  psql_db -d "$db_name" -c "SELECT timescaledb_post_restore()" >/dev/null
  _compose exec -T db psql -X -q -U "$db_user" -d "$db_name" -c "ALTER EXTENSION timescaledb UPDATE" </dev/null >/dev/null 2>&1 || true
  psql_db -d "$db_name" -c "ANALYZE" || warn "ANALYZE did not finish; the first few pages may be slow."
  ok "Database loaded."
}

_load_uploads() {
  local file="$1"
  CTEM_BACKUP_PASSWORD="$RESTORE_PW" archive cat --in "$file" --name volumes/app_uploads.tar \
    | _compose run --rm --no-deps -T --user 0 --entrypoint tar app -C /app/uploads -xpf - \
    || die "Restoring uploaded files failed."
  ok "Uploaded files restored."
}

_restore_cleanup() {
  rm -rf "${RESTORE_TMP:?}"
  if [[ -f "$RESTORE_MARK" ]]; then
    hint "Fix the cause above, then run the same command again; it picks up where it stopped."
    [[ -z "${SAFETY_FILE:-}" ]] || hint "To go back instead: sudo bash ${INSTALL_DIR}/install.sh --restore ${SAFETY_FILE}"
  fi
  return 0
}

# do_restore <file> <fresh|inplace|resume>; resume picks up a bare-server restore that stopped partway
RESTORE_MARK="${INSTALL_DIR}/.restore-incomplete"
do_restore() {
  local file="$1" mode="$2" stamp newenv
  stamp=$(date -u +%Y%m%d-%H%M%SZ)
  RESTORE_TMP=$(mktemp -d); chmod 700 "$RESTORE_TMP"
  trap _restore_cleanup EXIT

  _open_backup "$file"
  [[ "$(_manifest format)" == open-ctem-backup ]] || die "This is not an open-ctem backup."
  ok "Backup from $(_manifest host), taken $(_manifest created_utc)."
  _check_version

  if [[ "$mode" == inplace ]]; then
    warn "This replaces EVERYTHING on this server (data, users, settings, keys) with the backup."
    if [[ "${CTEM_RESTORE_CONFIRM:-}" != RESTORE ]]; then
      [[ "$(ask_tty "Type RESTORE to continue:")" == RESTORE ]] || die "Restore cancelled. Nothing was changed."
    fi
    say "Taking a safety backup of this server first..."
    local keep="${CTEM_BACKUP_PASSWORD-}"
    unset CTEM_BACKUP_PASSWORD
    do_backup 0 "${INSTALL_DIR}/backups"   # dies on failure, before anything has changed
    SAFETY_FILE="$BACKUP_FILE"
    [[ -z "$keep" ]] || export CTEM_BACKUP_PASSWORD="$keep"
  fi

  newenv=$(mktemp -p "$INSTALL_DIR" .env.restore.XXXXXX)
  _build_env "$newenv" "$mode"

  if [[ "$mode" != inplace ]]; then
    : > "$RESTORE_MARK"
    mv "$newenv" "$ENV_FILE"
    _put_host_files
    say "Pulling and building the containers (a few minutes)..."
    _compose pull --quiet --ignore-buildable </dev/null || die "Could not pull the container images."
    _compose build --pull --quiet </dev/null || die "Building the app image failed."
    # A resumed run may find the app up from last time; nothing may write while the database reloads
    _compose stop app worker beat nginx </dev/null 2>/dev/null || true
  else
    : > "$RESTORE_MARK"
    say "Stopping the app..."
    _compose stop app worker beat nginx </dev/null
    cp -p "$ENV_FILE" "${ENV_FILE}.pre-restore-${stamp}"
    mv "$newenv" "$ENV_FILE"
    _put_host_files
  fi

  _compose up -d db redis </dev/null || die "Could not start the database."
  wait_db "$(env_get DB_USER)"
  _load_database "$file"
  if grep -q '"volumes/app_uploads.tar"' "$RESTORE_TMP/manifest.json"; then
    _load_uploads "$file"
  fi
  if [[ "$mode" != fresh ]]; then
    # by name only, so the password never shows up in ps
    REDISCLI_AUTH="$(env_get REDIS_PASSWORD)" _compose exec -T -e REDISCLI_AUTH redis redis-cli FLUSHALL </dev/null >/dev/null \
      || warn "Could not clear the Redis cache."
  fi

  say "Starting open-ctem..."
  _compose up -d --remove-orphans </dev/null || die "Could not start the stack."
  # Containers keep the environment they were created with; every one must pick up the restored keys
  _compose up -d --no-deps --force-recreate app worker beat nginx </dev/null || die "Could not restart the app."
  wait_healthy 600 || die "The app did not come up. Check: docker compose -f ${COMPOSE_FILE} logs app"
  _compose exec -T app python -m api.maintenance.restore_check </dev/null \
    || die "The restored data does not open with the restored keys. Do not use this server; check the backup."
  ok "Encryption keys open the restored data."
  rm -f "$RESTORE_MARK"
}
