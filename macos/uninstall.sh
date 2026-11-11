#!/bin/bash
# NetGuard for macOS uninstaller.
#   sudo bash /Library/NetGuard/uninstall.sh          remove everything, keep config/records copy
#   sudo bash /Library/NetGuard/uninstall.sh --purge  also delete the kept copy
set -uo pipefail
ROOT=/Library/NetGuard
LABEL=com.netguard.daemon
PLIST=/Library/LaunchDaemons/$LABEL.plist
AGENT_LABEL=com.netguard.menu
ANCHOR='com.apple/zz.NetGuard'
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" -eq 0 ] || { echo "请用 sudo 运行"; exit 2; }
USER_NAME="${SUDO_USER:-}"

echo "==> 移除断网规则并停止后台"
if [ -x "$ROOT/bin/netguard-recover" ]; then
    "$ROOT/bin/netguard-recover" --stop
else
    launchctl bootout "system/$LABEL" 2>/dev/null || true
    /sbin/pfctl -a "$ANCHOR" -F rules 2>/dev/null || true
fi
rm -f "$PLIST"

echo "==> 移除菜单栏程序"
if [ -n "$USER_NAME" ] && [ "$USER_NAME" != "root" ]; then
    USER_UID="$(id -u "$USER_NAME")"
    USER_HOME="$(dscl . -read "/Users/$USER_NAME" NFSHomeDirectory | awk '{print $2}')"
    launchctl bootout "gui/$USER_UID/$AGENT_LABEL" 2>/dev/null || true
    rm -f "$USER_HOME/Library/LaunchAgents/$AGENT_LABEL.plist"
fi
pkill -x NetGuard 2>/dev/null || true
rm -rf /Applications/NetGuard.app "/Applications/NetGuard 紧急恢复.command"

if [ -d "$ROOT" ]; then
    KEEP="/Library/NetGuard.removed-$(date +%Y%m%d-%H%M%S)"
    if [ "$PURGE" -eq 0 ]; then
        mkdir -p "$KEEP"
        for f in config.json events.jsonl netguard.log; do
            if [ -f "$ROOT/$f" ]; then cp -p "$ROOT/$f" "$KEEP/"; fi
        done
        echo "==> 配置和保护记录已保留在 $KEEP"
    fi
    rm -rf "$ROOT"
fi

left=$(/sbin/pfctl -a "$ANCHOR" -sr 2>/dev/null | wc -l | tr -d ' ')
if [ "$left" = "0" ]; then
    echo "NetGuard 已卸载，pf 中不再有 NetGuard 规则。"
else
    echo "警告：锚点 $ANCHOR 中仍有 $left 条规则。"
    exit 1
fi
