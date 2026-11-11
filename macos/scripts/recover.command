#!/bin/sh
# 双击运行：NetGuard 紧急恢复。不需要网络，不需要 Codex。
# 安装后位于 /Applications/NetGuard 紧急恢复.command
clear
echo "================ NetGuard 紧急恢复 ================"
echo "将移除 NetGuard 的 pf 断网规则并关闭断网保护。"
echo "不会改动 FlClash、ClaudeGuard、DNS、系统防火墙配置文件。"
echo
echo "请输入本机登录密码后回车（输入时屏幕不显示，这是正常的）："
if [ -x /Library/NetGuard/bin/netguard-recover ]; then
    /usr/bin/sudo /Library/NetGuard/bin/netguard-recover
else
    # NetGuard files are gone but rules might remain: remove only NetGuard's anchor.
    /usr/bin/sudo /sbin/pfctl -a 'com.apple/zz.NetGuard' -F rules
fi
echo
echo "完成。按回车关闭此窗口。"
read -r _
