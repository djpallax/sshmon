#!/usr/bin/env bash
set -euo pipefail

if (( EUID == 0 )); then
  echo 'Run as your desktop user, without sudo.' >&2
  exit 1
fi
systemctl --user disable --now sshmon.service 2>/dev/null || true
rm -f -- "$HOME/.config/systemd/user/sshmon.service" "$HOME/.local/bin/sshmon"
systemctl --user daemon-reload
systemctl --user reset-failed sshmon.service 2>/dev/null || true
echo 'SSHmon C++ service and binary removed.'
echo 'The source repository and build directory were left untouched.'
