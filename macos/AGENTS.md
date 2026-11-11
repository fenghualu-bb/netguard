# NetGuard macOS — instructions for coding agents (Codex, Claude Code) on the user's Mac

Read `macos/README.md` first. This file is the operating contract. The user previously had to
factory-reset this Mac after an agent left it "connected to Wi-Fi but with no working network".
Nothing in this file may be relaxed to make a step look successful.

## Absolute rules

1. Never edit `/etc/pf.conf`, never run `pfctl -d`, `pfctl -F all`, `pfctl -f /etc/pf.conf`, or flush
   anything except NetGuard's own anchor `com.apple/zz.NetGuard`.
2. Never change DNS, routes, network services (`networksetup`), `/etc/hosts`, proxies, VPN profiles,
   system extensions, SIP or Gatekeeper. Never disable FlClash TUN or ClaudeGuard to "fix" something.
3. You cannot type the user's password. Every `sudo` command is run **by the user in Terminal**. Give the
   exact command, say what it changes, and ask them to paste the output back.
4. Before any step that can interrupt networking — `netguard enable`, restarting FlClash or its TUN,
   reloading FlClash profiles/subscriptions, installing/uninstalling ClaudeGuard's network helper —
   stop and explain: during the gap new connections may use the real IP (ClaudeGuard only protects the
   two Claude programs and reacts after about 3 seconds). Ask the user to close browsers, Claude and other
   networked apps, and wait for an explicit "done/confirmed" before continuing.
5. Your own network may disappear while the kill switch blocks traffic. Before step 5 of the install,
   tell the user the offline recovery: double-click "NetGuard 紧急恢复" in Applications, or
   `sudo /Library/NetGuard/bin/netguard-recover`. Never suggest a factory reset or reboot for this.
6. Never use `disable`, `guard-off`, `recover`, DIRECT mode, a wider whitelist or a longer grace period to
   make a failure disappear. Diagnose read-only first (`netguard status`, `netguard events -n 50`,
   `sudo tail -n 100 /Library/NetGuard/netguard.log`). Lift a lockdown only with `netguard release`.
7. Never run `macos/ci/integration.sh` on the user's Mac (it is for disposable CI VMs only).
8. Do not commit runtime files (`/Library/NetGuard/*.json`, logs), node/subscription data, tokens or the
   user's real IPs. Test fixtures use 203.0.113.0/24 documentation addresses.

## Install checklist (stop at the first failed checkpoint and report it)

| Step | Who runs it | Checkpoint |
|---|---|---|
| 0. `xcode-select -p` | agent | prints a path; else ask the user to run `xcode-select --install` |
| 1. FlClash: TUN on and core authorized, global mode, launch at login | user (GUI) | `ps -axo uid,rgid,comm \| grep FlClashCore` shows uid `0`; `ifconfig \| grep 198.18.` shows `inet 198.18.0.1`; the Cloudflare trace `ip=` is the node IP |
| 2. ClaudeGuard at commit `61b61e1` (README step 2), whitelist added | user | `claudeguard status` shows a whitelisted IP and protection on |
| 3. `sudo bash macos/install.sh` | user | ends with "安装完成"; `netguard status` prints a fresh status; the shield appears in the menu bar |
| 4. `sudo /Library/NetGuard/bin/netguard whitelist list` (import or add if empty) | user | at least one entry, equal to the FlClash exit IP |
| 5. Rule 4 warning, then `sudo /Library/NetGuard/bin/netguard enable` | user | "断网保护已开启"; if it says "自检未通过，已自动恢复", nothing is broken — report the listed reason |
| 6. `sudo /Library/NetGuard/bin/netguard verify` | user | every line ✅ |

If `enable` is refused, the message says exactly what is missing (FlClash core not root, no TUN,
exit not whitelisted, empty whitelist). Fix that cause; do not edit the code to skip the check.

## Repairs and updates

- Update: `git pull`, then the user runs `sudo bash macos/install.sh` (keeps config/state; never changes
  pf rules; backs up the previous version to `/Library/NetGuard/backup-*`).
- Changing NetGuard's code: keep Python 3.9-compatible (stdlib only), keep shell scripts POSIX/bash 3.2,
  run `cd macos && python3 -m unittest discover -s tests -p 'test_*.py'`, and keep the safety static tests
  green. pf behaviour changes must be validated by the GitHub Actions `macOS NetGuard` workflow before
  the user installs them.
- Real-machine acceptance rows are in `macos/ACCEPTANCE.md`. Mark a row only with evidence collected on
  this Mac; CI results are not Mac results.
