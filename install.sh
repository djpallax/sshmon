#!/usr/bin/env bash
set -euo pipefail

if (( EUID == 0 )); then
  echo 'Run as your desktop user, without sudo.' >&2
  exit 1
fi

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v cmake >/dev/null || ! command -v c++ >/dev/null; then
  echo 'Missing C++ compiler or CMake. On Arch: sudo pacman -S --needed base-devel cmake qt6-base' >&2
  exit 1
fi

cmake -S "$root" -B "$root/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$root/build" --parallel 2
ctest --test-dir "$root/build" --output-on-failure

# Stop existing instance before replacing its executable.
systemctl --user stop sshmon.service 2>/dev/null || true

mkdir -p "$HOME/.local/bin" "$HOME/.config/systemd/user"
install -m 755 "$root/build/sshmon" "$HOME/.local/bin/sshmon"
install -m 644 "$root/systemd/sshmon.service" "$HOME/.config/systemd/user/sshmon.service"

systemctl --user daemon-reload
systemctl --user enable --now sshmon.service

echo
echo 'Installed SSHmon C++ and enabled its user service.'
echo 'Status: systemctl --user status sshmon.service'
echo 'Logs:   journalctl --user -u sshmon.service -f'
