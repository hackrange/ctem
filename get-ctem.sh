#!/usr/bin/env bash
# open-ctem, one line install. Author: Tim Rice <tim.j.rice@hackrange.com>
#
#   curl -fsSL https://raw.githubusercontent.com/hackrange/ctem/main/get-ctem.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/hackrange/ctem/main/get-ctem.sh | sudo bash -s -- --restore /root/ctem.ctembak
#
# Ubuntu 22.04 or newer. Installs git and Docker when missing, clones the project and runs install.sh.
#   CTEM_DIR=/data/docker/ctem   where the checkout goes
#   CTEM_REPO / CTEM_BRANCH      install from a copy somewhere else
set -euo pipefail

# Everything lives in main so a half-downloaded script runs nothing at all
main() {
  local repo="${CTEM_REPO:-https://github.com/hackrange/ctem.git}" dest="${CTEM_DIR:-/data/docker/ctem}"
  local branch="${CTEM_BRANCH:-main}" id="" ver="" args=() a
  local c_head=$'\033[1;36m' c_ok=$'\033[32m' c_err=$'\033[31m' c_off=$'\033[0m'
  [[ -t 1 ]] || { c_head=; c_ok=; c_err=; c_off=; }
  say() { printf '%s[ctem]%s %s\n' "$c_head" "$c_off" "$*"; }
  ok()  { printf '%s  ok%s  %s\n' "$c_ok" "$c_off" "$*"; }
  die() { printf '%s  xx%s  %s\n' "$c_err" "$c_off" "$*" >&2; exit 1; }

  [[ "$(id -u)" -eq 0 ]] || die "Run it with sudo:  curl -fsSL <url>/get-ctem.sh | sudo bash"
  # shellcheck disable=SC1091
  [[ -r /etc/os-release ]] && { id=$(. /etc/os-release; echo "${ID:-}"); ver=$(. /etc/os-release; echo "${VERSION_ID:-}"); }
  [[ "$id" == ubuntu ]] || die "open-ctem installs on Ubuntu 22.04 or newer only (this is ${id:-unknown})."
  dpkg --compare-versions "${ver:-0}" ge 22.04 || die "open-ctem needs Ubuntu 22.04 or newer (this is ${ver:-unknown})."

  # The backup path is relative to where you ran this, so pin it down before we cd anywhere
  while (( $# )); do
    a="$1"; shift
    if [[ "$a" == --restore && $# -gt 0 ]]; then
      args+=("$a" "$(readlink -f -- "$1" 2>/dev/null || echo "$1")"); shift
    else
      args+=("$a")
    fi
  done

  if ! command -v git >/dev/null 2>&1; then
    say "Installing git..."
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq git ca-certificates >/dev/null \
      || die "Could not install git."
  fi

  if [[ -d "$dest/.git" ]]; then
    ok "Using the existing checkout at $dest"
  else
    [[ -z "$(ls -A "$dest" 2>/dev/null)" ]] || die "$dest exists and is not empty. Move it, or set CTEM_DIR."
    say "Cloning open-ctem into $dest..."
    mkdir -p "$(dirname "$dest")"
    git clone --quiet --branch "$branch" "$repo" "$dest" || die "Could not clone $repo"
    ok "Cloned $(git -C "$dest" rev-parse --short HEAD)."
  fi
  [[ -f "$dest/install.sh" ]] || die "install.sh is missing from $dest"

  say "Handing over to install.sh"
  # stdin is still this script; prompts read the terminal directly
  exec bash "$dest/install.sh" "${args[@]}" </dev/null
}

main "$@"
