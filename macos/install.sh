#!/bin/bash
# NetGuard for macOS installer.
#   sudo bash macos/install.sh            install or update (keeps config/state)
#   sudo bash macos/install.sh --no-app   skip building the menu bar app
#   sudo bash macos/install.sh --ci       CI only: build the app but do not register it for a GUI session
#
# What it does: copies root-owned files to /Library/NetGuard, registers the
# com.netguard.daemon LaunchDaemon, builds /Applications/NetGuard.app on this Mac
# and puts "NetGuard 紧急恢复.command" into /Applications.
# What it never does: turn on the kill switch, touch /etc/pf.conf, /etc/hosts, DNS,
# routes, network services, system extensions or VPN profiles. Updating never changes
# pf rules; an already enabled kill switch stays enabled.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
ROOT=/Library/NetGuard
LABEL=com.netguard.daemon
PLIST=/Library/LaunchDaemons/$LABEL.plist
APP=/Applications/NetGuard.app
AGENT_LABEL=com.netguard.menu
RECOVER_CMD="/Applications/NetGuard 紧急恢复.command"
BUILD_APP=1
CI_MODE=0
for arg in "$@"; do
    case "$arg" in
        --no-app) BUILD_APP=0 ;;
        --ci) CI_MODE=1 ;;
        *) echo "未知参数：$arg"; exit 2 ;;
    esac
done

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33m警告：%s\033[0m\n' "$*"; }
die() { printf '\033[31m失败：%s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 sudo 运行：sudo bash macos/install.sh"
# sudo sets SUDO_USER; the macOS admin dialog (osascript "with administrator privileges")
# does not, so fall back to the user logged in at the console.
USER_NAME="${SUDO_USER:-}"
if [ -z "$USER_NAME" ] || [ "$USER_NAME" = "root" ]; then
    USER_NAME="$(stat -f %Su /dev/console)"
fi
[ -n "$USER_NAME" ] && [ "$USER_NAME" != "root" ] || die "找不到桌面用户：请登录后在自己的账户里运行"
USER_UID="$(id -u "$USER_NAME")"
USER_HOME="$(dscl . -read "/Users/$USER_NAME" NFSHomeDirectory | awk '{print $2}')"
[ -d "$USER_HOME" ] || die "找不到用户目录 $USER_HOME"

say "检查系统"
MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
[ "$MAJOR" -ge 13 ] || die "需要 macOS 13 或更新（当前 $(sw_vers -productVersion)）"
xcode-select -p >/dev/null 2>&1 || die "缺少 Xcode Command Line Tools。先运行：xcode-select --install ，装完再重试。"
PY="$(/usr/bin/python3 -c 'import sys; print(sys.executable)' 2>/dev/null)" || die "/usr/bin/python3 不可用（Command Line Tools 未装好）"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "需要 Python 3.9+（当前 $("$PY" -V 2>&1)）"
[ -x /sbin/pfctl ] || die "找不到 /sbin/pfctl"
grep -q 'anchor "com.apple/\*"' /etc/pf.conf 2>/dev/null || warn "/etc/pf.conf 中没有 anchor \"com.apple/*\"：断网保护将无法生效（NetGuard 不会修改 pf.conf）。"
[ -d /Applications/FlClash.app ] || warn "没有找到 /Applications/FlClash.app。断网保护需要 FlClash 开启 TUN 才能开启。"
if [ ! -d /Applications/ClaudeGuard.app ] && [ ! -d "$USER_HOME/.local/share/ClaudeGuard" ]; then
    warn "没有找到 ClaudeGuard（上游 macOS 版）。NetGuard 默认要求它在运行，否则会报“ClaudeGuard 未运行”并锁定 Claude。见 macos/README.md 第 2 步。"
fi

say "停止旧的 NetGuard 后台（不改动 pf 规则）"
launchctl bootout "system/$LABEL" 2>/dev/null || true

STAMP="$(date +%Y%m%d-%H%M%S)"
if [ -d "$ROOT/lib" ]; then
    install -d -o root -g wheel -m 755 "$ROOT/backup-$STAMP"
    cp -R "$ROOT/lib" "$ROOT/bin" "$ROOT/backup-$STAMP/" 2>/dev/null || true
    for f in config.json state.json; do
        if [ -f "$ROOT/$f" ]; then cp -p "$ROOT/$f" "$ROOT/backup-$STAMP/$f"; fi
    done
    say "旧版本已备份到 $ROOT/backup-$STAMP"
fi

say "安装文件到 ${ROOT}（root 所有，普通用户只读）"
install -d -o root -g wheel -m 755 "$ROOT" "$ROOT/lib" "$ROOT/bin"
rm -rf "$ROOT/lib/netguard"
cp -R "$SRC/netguard" "$ROOT/lib/netguard"
cp "$SRC/netguard_main.py" "$ROOT/lib/netguard_main.py"
find "$ROOT/lib" -name '__pycache__' -type d -prune -exec rm -rf {} +
chown -R root:wheel "$ROOT/lib"
chmod -R u=rwX,go=rX "$ROOT/lib"
for f in netguard netguard-boot netguard-recover; do
    install -o root -g wheel -m 755 "$SRC/bin/$f" "$ROOT/bin/$f"
done
install -o root -g wheel -m 755 "$SRC/uninstall.sh" "$ROOT/uninstall.sh"
printf '%s\n' "$PY" > "$ROOT/python-path"
chown root:wheel "$ROOT/python-path"; chmod 644 "$ROOT/python-path"
touch "$ROOT/events.jsonl" "$ROOT/netguard.log"
chown root:wheel "$ROOT/events.jsonl" "$ROOT/netguard.log"; chmod 644 "$ROOT/events.jsonl" "$ROOT/netguard.log"

NETGUARD_INSTALL_USER="$USER_NAME" "$ROOT/bin/netguard" init-config

# Where this copy came from, so the app's "update" button can pull and reinstall it.
REPO="$(cd "$SRC/.." && pwd)"
COMMIT="$(sudo -u "$USER_NAME" git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
"$PY" -c 'import json, sys; json.dump({"repo": sys.argv[1], "commit": sys.argv[2], "user": sys.argv[3], "installed_at": sys.argv[4]}, open(sys.argv[5], "w"))' \
    "$REPO" "$COMMIT" "$USER_NAME" "$(date '+%Y-%m-%d %H:%M')" "$ROOT/source.json"
chown root:wheel "$ROOT/source.json"; chmod 644 "$ROOT/source.json"

say "注册后台 ${LABEL}（开机自启，每 10 秒检查一次）"
install -o root -g wheel -m 644 "$SRC/launchd/$LABEL.plist" "$PLIST"
plutil -lint "$PLIST" >/dev/null
launchctl bootstrap system "$PLIST"

say "安装紧急恢复入口：$RECOVER_CMD"
install -o root -g wheel -m 755 "$SRC/scripts/recover.command" "$RECOVER_CMD"

if [ "$BUILD_APP" -eq 1 ]; then
    say "在本机编译菜单栏/工作台 NetGuard.app（本地编译无需签名，Gatekeeper 不拦截）"
    BUILD="$(mktemp -d /tmp/netguard-build.XXXXXX)"
    if xcrun swiftc -O -swift-version 5 -parse-as-library -target "$(uname -m)-apple-macos13.0" \
            -o "$BUILD/NetGuard" "$SRC/app/NetGuardApp.swift" \
            -framework AppKit -framework SwiftUI 2>"$BUILD/swiftc.log"; then
        rm -rf "$APP"
        install -d -o root -g wheel -m 755 "$APP/Contents/MacOS" "$APP/Contents/Resources"
        install -o root -g wheel -m 755 "$BUILD/NetGuard" "$APP/Contents/MacOS/NetGuard"
        install -o root -g wheel -m 644 "$SRC/app/Info.plist" "$APP/Contents/Info.plist"
        codesign --force --sign - "$APP" >/dev/null 2>&1 || warn "ad-hoc 签名失败（通常不影响本机运行）"
        AGENT="$USER_HOME/Library/LaunchAgents/$AGENT_LABEL.plist"
        install -d -o "$USER_NAME" -m 755 "$USER_HOME/Library/LaunchAgents"
        install -o "$USER_NAME" -m 644 "$SRC/launchd/$AGENT_LABEL.plist" "$AGENT"
        if [ "$CI_MODE" -eq 0 ]; then
            launchctl bootout "gui/$USER_UID/$AGENT_LABEL" 2>/dev/null || true
            launchctl bootstrap "gui/$USER_UID" "$AGENT" 2>/dev/null || \
                warn "菜单栏程序未能自动启动；可以在“应用程序”里打开 NetGuard。"
        fi
        rm -rf "$BUILD"
    else
        warn "NetGuard.app 编译失败（命令行和后台不受影响）。日志：$BUILD/swiftc.log"
        tail -n 20 "$BUILD/swiftc.log" || true
        if [ "$CI_MODE" -eq 1 ]; then exit 1; fi
    fi
fi

say "等待后台写出第一份状态"
for _ in $(seq 1 40); do
    if [ -f "$ROOT/status.json" ] && [ "$(( $(date +%s) - $(stat -f %m "$ROOT/status.json") ))" -lt 30 ]; then
        break
    fi
    sleep 1
done
if [ -f "$ROOT/status.json" ]; then
    "$ROOT/bin/netguard" status || true
else
    warn "后台 40 秒内没有写出状态。查看：sudo tail -n 50 $ROOT/daemon.err.log"
fi

cat <<EOF

安装完成。断网保护尚未开启（与 Windows 版一致，安装不会自动开启）。
下一步（每条都在“终端”里由你本人运行，会要求输入登录密码）：
  1) 确认白名单：   sudo $ROOT/bin/netguard whitelist list
     为空就导入/添加：sudo $ROOT/bin/netguard whitelist import-claudeguard
                     sudo $ROOT/bin/netguard whitelist add <你的节点出口 IP>
  2) 开启断网保护： sudo $ROOT/bin/netguard enable
     （先预检；加载规则后自检 DNS、代理出口和直连拦截，任何一项失败都会自动恢复）
  3) 完整自检：     sudo $ROOT/bin/netguard verify
断网急救（不需要网络）：双击“应用程序”里的“NetGuard 紧急恢复”，
或运行 sudo $ROOT/bin/netguard-recover
EOF
