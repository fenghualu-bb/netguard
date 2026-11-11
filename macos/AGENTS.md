# NetGuard macOS — instructions for coding agents (Codex, Claude Code) on the user's Mac

Read `macos/README.md` first. This file is the operating contract. The user previously had to
factory-reset this Mac after an agent left it "connected to Wi-Fi but with no working network".
Nothing in this file may be relaxed to make a step look successful.

The user wants the installation **fully automated**: do every step yourself, report results, and
stop only at the few points listed under "When to involve the user".

## Absolute rules (what YOU, the agent, may do by hand)

1. Never edit `/etc/pf.conf`, never run `pfctl -d`, `pfctl -F all`, `pfctl -f /etc/pf.conf`, and never
   flush or load any pf anchor yourself. NetGuard's own scripts manage `com.apple/zz.NetGuard`.
2. Never change DNS, routes, network services (`networksetup`), `/etc/hosts`, proxies, VPN profiles,
   system extensions, SIP or Gatekeeper by hand. Never disable FlClash TUN or ClaudeGuard to "fix" something.
3. **Third-party components chosen by the user are not "by hand".** Running ClaudeGuard's official
   `install.sh` at commit `61b61e1` is allowed although its root helper maintains its own marked section
   in `/etc/hosts` and its own pf anchor `com.claudeguard` (it never reloads the main ruleset or edits
   `/etc/pf.conf`; see its README "Coexisting with other PF users"). FlClash managing its TUN/DNS is likewise
   allowed. Verify afterwards: `/etc/pf.conf` hash unchanged, `/etc/hosts` changed only inside the
   ClaudeGuard markers, `pfctl -sr` only gained ClaudeGuard's anchor call. Do not edit their code.
4. Never use `disable`, `guard-off`, `recover`, DIRECT mode, a wider whitelist or a longer grace period to
   make a failure disappear. Diagnose read-only first (`netguard status`, `netguard events -n 50`,
   `/Library/NetGuard/netguard.log`). Lift a lockdown only with `netguard release`.
5. Never run `macos/ci/integration.sh` on the user's Mac (it is for disposable CI VMs only).
6. Do not commit runtime files, node/subscription data, tokens or the user's IPs.

## Privileged commands without making the user type commands

You cannot know the password and must not ask for it in chat. Run root commands through the macOS
administrator dialog; the user only types the password into the system dialog:

```bash
osascript -e 'do shell script "bash /Users/<user>/netguard/macos/install.sh 2>&1" with administrator privileges'
osascript -e 'do shell script "/Library/NetGuard/bin/netguard enable 2>&1" with administrator privileges'
```

- Batch several root steps into one dialog when they belong together (macOS caches the authorization
  for a few minutes). Exit status non-zero = failure; read the output.
- NetGuard's `install.sh`/`uninstall.sh` detect the console user when started this way (no SUDO_USER).
- For an interactive third-party installer that calls `sudo` itself (ClaudeGuard `install.sh`): read the
  script first. Answer its y/n questions yourself via stdin. Decline "whitelist current IP" inside the
  installer and add the IP afterwards with `claudeguard add-ip <ip>` only after confirming the current
  exit is the FlClash node IP (never the real IP). If its `sudo` needs a TTY, open it in Terminal with
  `osascript -e 'tell application "Terminal" to do script "cd ~/ClaudeGuard && ./install.sh"'` and tell
  the user that one password prompt in that window is expected.

## Before anything that can drop networking

`netguard enable`, rebooting, restarting FlClash/TUN: first quit Claude and web browsers yourself
(`osascript -e 'quit app "Claude"'`, same for Safari/Google Chrome/Arc/Firefox if running), say so in one
line, then continue. The user authorized this so they are not asked each time. Also remind them once of
the offline recovery: double-click "NetGuard 紧急恢复" in Applications, or
`sudo /Library/NetGuard/bin/netguard-recover`. Never suggest a factory reset.

## When to involve the user (only these)

- The macOS password dialog (and at most one Terminal password prompt for ClaudeGuard).
- A reboot: you cannot survive it. Write progress to `~/netguard-install-progress.md` first, ask the user
  to restart and to say "继续" after logging in, then resume from that file.
- A checkpoint fails and the fix needs a GUI action you cannot perform (FlClash settings), or a rule above
  would have to be broken. Report the exact output and the one action needed.

## Install checklist (resume from the first unchecked step; stop at a failed checkpoint)

| Step | Checkpoint |
|---|---|
| 0. `xcode-select -p` | prints a path (else run `xcode-select --install` and wait) |
| 1. FlClash: TUN on, core authorized, global mode, launch at login, auto-connect | `ps -axo uid,rgid,comm \| grep FlClashCore` uid `0`; `ifconfig \| grep 198.18.` has `inet 198.18.0.1` (a /30 netmask is normal: NetGuard matches the whole 198.18.0.0/16); Cloudflare trace `ip=` is the node IP |
| 2. ClaudeGuard at `61b61e1`, whitelist = node IP | `claudeguard status` shows the IP allowed and protection on; rule 3 verification passes |
| 3. Reboot drill (kill switch still OFF) | after login, without touching anything: FlClash running, TUN up, node exit, ClaudeGuard running. If not, fix autostart before step 5 |
| 4. NetGuard `install.sh` (admin dialog) | ends with "安装完成"; `/Library/NetGuard/bin/netguard status` fresh; menu bar shield |
| 5. Whitelist: `netguard whitelist list`, else `whitelist import-claudeguard` | contains the node exit IP |
| 6. Quit Claude/browsers, then `netguard enable` (admin dialog) | "断网保护已开启". "自检未通过，已自动恢复" means nothing broke: report the reason, do not retry another way |
| 7. `netguard verify` (admin dialog) | every line ✅ |
| 8. Final reboot | within 3 min of login: network works, status "已开启且完整", lockdown 否, verify all ✅ |

If after a reboot there is no network: FlClash/TUN did not start (the kill switch is doing its job).
Open FlClash first; the network returns immediately. Only if that fails, run the recovery.

## Repairs and updates

- Update: `git pull`, then rerun `install.sh` via the admin dialog (keeps config/state; never changes pf
  rules; backs up to `/Library/NetGuard/backup-*`).
- Changing NetGuard's code: Python 3.9 stdlib only, bash 3.2 compatible, run
  `cd macos && python3 -m unittest discover -s tests -p 'test_*.py'`; pf changes must pass the GitHub
  Actions `macOS NetGuard` workflow before installation.
- Real-machine acceptance rows are in `macos/ACCEPTANCE.md`; mark a row only with evidence from this Mac.
