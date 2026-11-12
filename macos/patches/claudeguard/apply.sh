#!/bin/bash
# ClaudeGuard (ivblz/ClaudeGuard @ 61b61e1, MIT) compatibility patch, applied by NetGuard.
#
# Problem: the official native Claude Code installer (2.1.x) stores each version as a flat
# executable file ~/.local/share/claude/versions/<version>. ClaudeGuard 61b61e1 only looks for
# versions/*/claude, so `claudeguard doctor` reports "Hands off to: NOT FOUND" and the claude
# shim cannot start Claude Code. The patch adds exactly one search pattern.
#
#   bash macos/patches/claudeguard/apply.sh            apply (idempotent), then run `claudeguard doctor`
#   bash macos/patches/claudeguard/apply.sh --check    report: original / patched / unknown
#   bash macos/patches/claudeguard/apply.sh --revert   restore the original file
#
# Run as the desktop user (not root). It edits only ~/.local/share/ClaudeGuard/src/integrity.py,
# and only when that file is byte-identical to the 61b61e1 original or to the patched result.
set -euo pipefail

TARGET="$HOME/.local/share/ClaudeGuard/src/integrity.py"
ORIGINAL_SHA=165a1ea4d857e3da7f0e539573396153c2ae962486ea7315de216e5da130f1f9
PATCHED_SHA=75ab8749ea6bf3f1ccd37471da98b6d5b46d9754a2dd6c4f9fd7aeed79cca70c
MODE="${1:-apply}"

die() { echo "失败：$*" >&2; exit 1; }
sha() { /usr/bin/shasum -a 256 "$1" | /usr/bin/cut -d' ' -f1; }

[ "$(id -u)" -ne 0 ] || die "请以桌面用户身份运行（不要用 sudo）"
[ -f "$TARGET" ] || die "没有找到 $TARGET（ClaudeGuard 未安装？）"
CURRENT="$(sha "$TARGET")"

case "$MODE" in
    --check)
        if [ "$CURRENT" = "$PATCHED_SHA" ]; then echo "patched"
        elif [ "$CURRENT" = "$ORIGINAL_SHA" ]; then echo "original"
        else echo "unknown"; fi
        exit 0 ;;
    --revert)
        [ "$CURRENT" = "$PATCHED_SHA" ] || die "当前文件不是本补丁的结果，不做还原"
        BACKUP="$(ls -t "$TARGET".bak-netguard-* 2>/dev/null | head -n 1 || true)"
        [ -n "$BACKUP" ] && [ "$(sha "$BACKUP")" = "$ORIGINAL_SHA" ] || die "找不到原始备份"
        cp -p "$BACKUP" "$TARGET"
        echo "已还原为 ClaudeGuard 原版。"
        exit 0 ;;
    apply) ;;
    *) die "未知参数：$MODE" ;;
esac

if [ "$CURRENT" = "$PATCHED_SHA" ]; then
    echo "ClaudeGuard 补丁已在位，无需重复应用。"
elif [ "$CURRENT" = "$ORIGINAL_SHA" ]; then
    BACKUP="$TARGET.bak-netguard-$(date +%Y%m%d-%H%M%S)"
    cp -p "$TARGET" "$BACKUP"
    /usr/bin/python3 - "$TARGET" <<'PY'
import sys
path = sys.argv[1]
with open(path, "rb") as stream:
    data = stream.read()
old = b'        os.path.join(HOME, ".local", "share", "claude", "versions", "*", "claude"),\n'
new = old + (b'        # NetGuard patch: native installer >= 2.1 stores each version as a flat executable file.\n'
             b'        os.path.join(HOME, ".local", "share", "claude", "versions", "*"),\n')
if data.count(old) != 1:
    sys.exit("anchor line not found exactly once")
with open(path, "wb") as stream:
    stream.write(data.replace(old, new))
PY
    if [ "$(sha "$TARGET")" != "$PATCHED_SHA" ]; then
        cp -p "$BACKUP" "$TARGET"
        die "补丁结果校验不符，已还原原文件"
    fi
    echo "已应用 ClaudeGuard 补丁（原文件备份：$BACKUP）。"
else
    die "integrity.py 既不是 61b61e1 原版也不是补丁版（sha256 $CURRENT），拒绝修改。ClaudeGuard 可能已升级，请交给维护者。"
fi

CG="$HOME/.local/bin/claudeguard"
if [ -x "$CG" ]; then
    echo "运行 claudeguard doctor 让 ClaudeGuard 重新识别真实的 Claude Code："
    "$CG" doctor || true
fi
