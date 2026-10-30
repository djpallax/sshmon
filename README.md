# SSHmon

A small, compiled **C++ / Qt 6** system-tray application for monitoring **incoming authenticated SSH sessions** on a Linux desktop. Designed for **KDE Plasma 6 on Wayland**, without an applet, browser, server process, or root daemon.

The notifier remains D-Bus registered but switches to **Passive** (normally hidden in the expandable tray area) when no SSH sessions exist. It appears automatically when somebody logs in over SSH. The tray icon uses the active icon theme's `link` icon, with an active-session count and upload/download activity indicators. The tray uses KDE Frameworks 6 `KStatusNotifierItem` directly, avoiding repeated D-Bus unregistration during SSH disconnect/reconnect.

## Reconnection reliability

The application keeps its StatusNotifierItem **registered** for its entire lifetime. Instead of calling `QSystemTrayIcon::hide()` and `show()` (which unregister/re-register the icon), it changes the notifier status:

- `Passive`: zero SSH sessions, usually hidden in the expanded tray.
- `Active`: one or more authenticated SSH sessions, automatically visible.
- `NeedsAttention`: session discovery failed; never silently report zero sessions.

The displayed SSH session count is based on `loginctl`, not only open TCP sockets. KDE's tray visibility settings can override where a passive/active item appears. If you see a TCP connection but no icon, verify an authenticated session with `loginctl list-sessions` and check the user service logs.

## Features

- Shows a StatusNotifierItem with **Passive** status without sessions, **Active** status with sessions, and **NeedsAttention** on monitoring errors. The item stays registered across reconnects.
- Displays authenticated session count, usernames, remote IPs, and traffic rates in its tooltip.
- Displays a submenu for each SSH session: session ID, user, remote host, state, TTY, login time, and traffic rate.
- Updates traffic rates **every two seconds while the menu is open** without deleting or recreating its actions.
- Disconnects a selected session after a confirmation and a Polkit authorization prompt.
- Stops `sshd.service` after confirmation and Polkit authorization.
- Runs as a **systemd user service** bound to the graphical desktop session; automatically starts when Plasma starts.
- Does not require elevated privileges for monitoring, eBPF, an HTTP server, or any custom root service.

### Icon activity

- **Up arrow**: bytes sent by the monitored machine to the remote SSH client.
- **Down arrow**: bytes received by the monitored machine from the remote SSH client.
- **Number badge**: authenticated SSH sessions (9+ if greater than nine).

## Requirements

- Linux with `systemd-logind` and a working SSH server (`sshd` with PAM session registration).
- KDE Plasma 6 / Wayland or another desktop with a StatusNotifierItem-compatible system tray.
- Qt 6 Core and Widgets; KDE Frameworks 6 `kstatusnotifieritem`; `iproute2` (for `ss`); `polkit` plus a graphical authentication agent (for administrative menu actions).
- C++17 compiler and CMake to build.

**Arch Linux:**

```bash
sudo pacman -S --needed base-devel cmake qt6-base kstatusnotifieritem iproute2 polkit openssh
```

`qt6-base` is also used at runtime (and is normally installed already on Plasma 6). `openssh` must be configured separately; this program does not enable or expose an SSH server.

## Installation

From the repository root, as your **normal desktop user (no `sudo`)**:

```bash
bash install.sh
```

The installer:

1. Builds the C++ executable with CMake in `build/` and executes the bundled monitoring tests.
2. Installs the binary at `~/.local/bin/sshmon`.
3. Installs a user unit at `~/.config/systemd/user/sshmon.service`.
4. Enables and starts it using `systemctl --user enable --now sshmon.service`.

The unit starts automatically on subsequent Plasma graphical logins. No terminal needs to remain open. **Do not enable system-wide lingering or run this GUI service as root**: it needs the user's active graphical session and D-Bus session bus.

## Service management

```bash
systemctl --user status sshmon.service
systemctl --user restart sshmon.service
systemctl --user stop sshmon.service
systemctl --user start sshmon.service
journalctl --user -u sshmon.service -f
```

To disable automatic startup without uninstalling:

```bash
systemctl --user disable --now sshmon.service
```

To enable it again:

```bash
systemctl --user enable --now sshmon.service
```

The service uses `WantedBy=graphical-session.target`, `After=graphical-session.target`, and `PartOf=graphical-session.target`: it is intended to run **only while the desktop session exists**, not at the system login screen.

## Configuration

The default service starts the monitor with:

```bash
~/.local/bin/sshmon --port 22 --interval 2
```

`--port` accepts TCP port 1–65535, and `--interval` accepts 1–60 seconds.

For custom values, use a systemd override:

```bash
systemctl --user edit sshmon.service
```

Example override for SSH port 2222 and a 3-second update interval:

```ini
[Service]
ExecStart=
ExecStart=%h/.local/bin/sshmon --port 2222 --interval 3
```

Apply changes:

```bash
systemctl --user daemon-reload
systemctl --user restart sshmon.service
```

## Building and testing manually

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
./build/sshmon --help
```

The tests use **synthetic `loginctl` and `ss` outputs only**, with fictional usernames and IP ranges reserved for documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`). They do not connect to SSH, inspect your real network, or require root. The tests cover session filtering, TCP counter parsing, IP normalization, traffic-rate aggregation, and rate formatting.

Run in an active graphical session if you are testing the icon. Do not manually run a second instance while the user service is active: the app uses a per-user lock file to prevent duplicates.

## Uninstallation

From the repository root, as a normal user:

```bash
bash uninstall.sh
```

This **stops and disables** the systemd user service, removes its unit and installed executable, and reloads the user manager. It leaves the source checkout, build directory and SSH server configuration intact. It never stops or uninstalls OpenSSH.

## How it works

- Every two seconds, a worker thread queries `loginctl list-sessions` and `loginctl show-session`, selecting entries where `Service=sshd` and `Remote=yes`.
- It queries `ss -Htin state established '( sport = :22 )'` to read per-socket TCP `bytes_sent` and `bytes_received` counters.
- Adjacent samples are converted to bytes/second, grouped by **remote IP address**.
- Qt's GUI thread updates existing menu action text in place, retaining stable submenus and hover state during normal traffic updates.
- System operations run through `pkexec` with standard `loginctl` / `systemctl` commands only after explicit confirmation. The application itself never runs as root.

## Security, behavior, and limitations

**Session coverage.** Only authenticated remote sessions registered with `systemd-logind` are counted. Pre-authentication connections, some non-PAM SSH connections, certain `ssh -N` tunnels, and some transfers that do not create a logind session may be absent. This is an informative desktop indicator, **not an intrusion-detection system or comprehensive SSH audit**.

**Traffic attribution.** TCP counters are aggregated by remote **IP**, not per SSH login. Multiple sessions originating from the same IP show a **shared-IP** label and the same aggregate traffic. Other established TCP connections from the same peer IP to the configured SSH port can affect the totals. The rates describe SSH TCP transport bytes, not decrypted application payload. The first sample is `N/A` until a prior counter sample exists. Counter availability depends on the kernel/iproute2 version and permissions.

**Closing sessions.** "Disconnect this session" invokes `loginctl terminate-session ID`. It can terminate processes belonging to that logind session. The application rechecks the session's user, host and service immediately before starting the privileged operation; concurrent session turnover cannot be completely eliminated.

**Stopping SSH.** "Stop SSH server" invokes `systemctl stop sshd.service`. This does not disable future startup and may leave existing sessions alive. If socket activation is in use, `sshd.socket` may continue listening; manage that unit separately if you use it. Stopping the server can interrupt remote management: use local or RDP access as a fallback.

**Permissions.** Polkit may ask for an administrator password; ensure a Polkit authentication agent is available in your session. Do not add passwordless Polkit rules for this utility. The program runs unprivileged at all other times.

**Tray environment.** Wayland doesn't reliably support manually positioned Qt popup menus, so this app uses `KStatusNotifierItem::setContextMenu()` and does not force a popup on primary click. Depending on the desktop, open the menu with right-click or the tray's native interaction. KDE may put the icon in its hidden tray section unless you configure its visibility.

**Error handling.** The monitor switches to `NeedsAttention` and shows a warning rather than falsely claiming zero SSH connections if the session query fails. A per-user single-instance lock prevents duplicate native monitors.

## Project structure

```text
sshmon/
├── CMakeLists.txt
├── LICENSE
├── README.md
├── .gitignore
├── install.sh
├── uninstall.sh
├── src/
│   ├── monitor.h
│   ├── monitor.cpp
│   └── tray.cpp
├── systemd/
│   └── sshmon.service
└── tests/
    └── monitor_tests.cpp
```

## Contributing

Bug reports and pull requests are welcome. Please include the Qt/Plasma versions, distribution, SSH port, relevant user-service logs, and steps to reproduce. Avoid including public IP addresses, usernames, or authentication secrets in shared logs.

## Troubleshooting

```bash
systemctl --user status sshmon.service --no-pager
journalctl --user -u sshmon.service -n 80 --no-pager
loginctl list-sessions
ss -Htn state established '( sport = :22 )'
```

Service logs include the detected authenticated-session count on changes, without logging IP addresses. An SSH socket without a `systemd-logind` authenticated session does not trigger the indicator. This includes some forwarding-only and PAM-less configurations.

## License

GNU General Public License v3.0 or later (`GPL-3.0-or-later`). See [LICENSE](LICENSE).

The repository includes a GitHub Actions workflow that compiles the code and runs parser/throughput tests on Linux. The graphical tray and Polkit dialogs still require manual testing in a real desktop session.
