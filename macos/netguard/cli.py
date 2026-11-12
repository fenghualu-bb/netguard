"""`netguard` command line. Mutating commands need root (sudo or the app's admin prompt)."""
import argparse
import json
import os
import sys
import time

from . import VERSION, config, events, paths, util
from .service import Service, UserError

ROOT_COMMANDS = {"enable", "disable", "release", "guard-on", "guard-off", "isolate", "unisolate",
                 "recover", "watch", "verify", "refresh", "whitelist", "drill"}


def _is_root():
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def _fmt_time(ts):
    if not ts:
        return "—"
    return time.strftime("%m-%d %H:%M:%S", time.localtime(ts))


def print_status(status, out=print):
    if not status:
        out("还没有状态文件：NetGuard 后台可能没有运行（sudo launchctl print system/com.netguard.daemon）。")
        return 1
    age = int(time.time() - status.get("updated_at", 0))
    guard = status.get("guard") or {}
    obs = status.get("observations") or {}
    core = obs.get("core") or {}
    cg = obs.get("claudeguard") or {}
    integ = status.get("integrity") or {}
    if status.get("wanted_killswitch"):
        ks = "已开启且完整" if status.get("killswitch_complete") else "已开启但不完整！"
    else:
        ks = "未开启"
    out("NetGuard %s（状态 %d 秒前更新%s）" % (status.get("version"), age, "，可能已停止" if age > 60 else ""))
    out("  断网保护：%s   pf=%s 锚点引用=%s 规则 %s 条 token=%s" % (
        ks, integ.get("pf_enabled"), integ.get("main_anchor_ref"), integ.get("rule_count"), integ.get("token_live")))
    out("  自动防护：%s   锁定：%s%s" % ("开" if guard.get("enabled") else "关",
                                        "是（%s 起）" % _fmt_time(guard.get("since")) if guard.get("lockdown") else "否",
                                        "   Claude 已隔离" if status.get("claude_block") else ""))
    if guard.get("lockdown"):
        out("    锁定原因：" + "；".join(guard.get("reasons") or []))
    out("  普通出口：%s %s   claude.ai 出口：%s %s" % (
        obs.get("egress"), "✓" if obs.get("egress_ok") else "✗",
        obs.get("claude_egress"), "✓" if obs.get("claude_egress_ok") else "✗"))
    fl = obs.get("flclash") or {}
    out("  FlClash：界面%s 内核%s   TUN：%s（路由 %s）   模式：%s" % (
        "✓" if obs.get("flclash_ui") else "✗",
        ("✓ root 授权" if core.get("privileged") else "✓ 未授权") if core.get("running") else "✗",
        obs.get("tun") or "未连接", obs.get("route") or "?",
        {"global": "全局", "rule": "规则", "direct": "直连"}.get(fl.get("mode"), "待核实")))
    out("  局域网 DNS：%s   真实 IP 模式：%s" % ("拦截" if status.get("dns_block") else "放行",
                                            "是" if status.get("realip") else "否"))
    if status.get("require_claudeguard"):
        out("  ClaudeGuard：%s  保护%s  网络助手%s  claude 钩子%s" % (
            ("运行中（%s）" % cg.get("state")) if cg.get("fresh") else "未运行或状态过期",
            "关" if cg.get("protection_enabled") is False else "开",
            "✓" if cg.get("helper_loaded") else "✗", "✓" if cg.get("cli_hooked") else "✗"))
    if obs.get("exempt_others"):
        out("  注意：%s 与 FlClash 内核共用放行身份联网" % "、".join(obs["exempt_others"]))
    if guard.get("grace_until") and guard["grace_until"] > time.time():
        out("  开机/登录/唤醒宽限期至 %s（期间中危异常不锁定）" % _fmt_time(guard["grace_until"]))
    findings = guard.get("last_findings") or []
    out("  当前异常：" + ("；".join(findings) if findings else "无"))
    out("  白名单：%d 项   上次检查：%s" % (len(status.get("whitelist") or []), _fmt_time(guard.get("last_check"))))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="netguard", description="NetGuard for macOS %s" % VERSION)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("status", help="显示状态").add_argument("--json", action="store_true")
    sub.add_parser("enable", help="开启断网保护（先预检，失败自动回滚）")
    sub.add_parser("disable", help="关闭断网保护（同时解除锁定与隔离）")
    sub.add_parser("release", help="解除自动防护锁定（先完整检查）")
    sub.add_parser("guard-on", help="开启自动防护")
    sub.add_parser("guard-off", help="关闭自动防护")
    sub.add_parser("isolate", help="真实 IP 模式：隔离 Claude")
    sub.add_parser("unisolate", help="退出真实 IP 模式（出口需回到白名单）")
    sub.add_parser("verify", help="完整自检，包括直连拦截测试")
    sub.add_parser("refresh", help="立即执行一次检查并写状态")
    sub.add_parser("recover", help="紧急恢复：移除 NetGuard 的全部 pf 规则并关闭断网保护")
    sub.add_parser("drill", help="自动断线演练：退出 FlClash→验证直连被拦与锁定→重新打开；3 分钟未恢复自动急救")
    sub.add_parser("watch", help="（后台）常驻检查循环")
    ev = sub.add_parser("events", help="显示保护记录")
    ev.add_argument("-n", type=int, default=30)
    wl = sub.add_parser("whitelist", help="白名单")
    wl.add_argument("op", choices=["list", "add", "remove", "import-claudeguard"])
    wl.add_argument("value", nargs="?")
    sub.add_parser("version")
    sub.add_parser("init-config", help="（安装用）没有配置时写入默认配置，并尝试导入 ClaudeGuard 白名单")
    args = parser.parse_args(argv)
    command = args.command or "status"

    if command == "version":
        print(VERSION)
        return 0
    if command == "init-config":
        if not _is_root():
            print("需要 sudo", file=sys.stderr)
            return 2
        if os.path.exists(paths.CONFIG):
            raw = util.read_json(paths.CONFIG, None)
            migrated, changes = config.migrate(raw)
            if changes:
                util.write_text(paths.CONFIG + ".bak-v1", json.dumps(raw, ensure_ascii=False, indent=2) + "\n")
                config.save(migrated)
                print("已升级配置（旧文件备份为 config.json.bak-v1）：" + "；".join(changes))
            else:
                config.load()  # validates the kept configuration
                print("保留现有配置 %s" % paths.CONFIG)
            return 0
        cfg = config.validate({})
        user = os.environ.get("NETGUARD_INSTALL_USER") or ""
        cfg["whitelist"] = config.claudeguard_whitelist(user) if user else []
        config.save(cfg)
        print("已写入默认配置，从 ClaudeGuard 导入白名单 %d 项。" % len(cfg["whitelist"]))
        return 0
    if command == "events":
        for e in events.read(args.n):
            print("%s [%s/%s] %s" % (_fmt_time(e.get("ts")), e.get("type"), e.get("severity"), e.get("summary")))
            for r in e.get("reasons") or []:
                print("      - %s（%s）" % (r.get("text"), r.get("level")))
        return 0
    if command == "status":
        status = util.read_json(paths.STATUS, None)
        if args.json:
            print(json.dumps(status, ensure_ascii=False, indent=2))
            return 0 if status else 1
        return print_status(status)
    if command == "whitelist" and args.op == "list":
        try:
            for entry in config.load()["whitelist"] or ["（白名单为空）"]:
                print(entry)
        except config.ConfigError as exc:
            print("配置错误：%s" % exc, file=sys.stderr)
            return 2
        return 0
    if command in ROOT_COMMANDS and not _is_root():
        print("此操作需要管理员权限：sudo /Library/NetGuard/bin/netguard %s" % " ".join(sys.argv[1:] or [command]),
              file=sys.stderr)
        return 2

    try:
        svc = Service()
        if command == "enable":
            svc.enable()
        elif command == "disable":
            svc.disable()
        elif command == "release":
            svc.release()
        elif command == "guard-on":
            svc.set_guard(True)
        elif command == "guard-off":
            svc.set_guard(False)
        elif command == "isolate":
            svc.isolate()
        elif command == "unisolate":
            svc.unisolate()
        elif command == "recover":
            svc.recover()
        elif command == "verify":
            return 0 if svc.verify() else 1
        elif command == "refresh":
            svc.tick()
            return print_status(svc.write_status())
        elif command == "whitelist":
            if args.op in ("add", "remove") and not args.value:
                raise UserError("请给出 IP 或网段")
            svc.whitelist(args.op, args.value)
        elif command == "drill":
            from .drill import Drill
            result = Drill(svc).run()
            print("—— 断线演练结果 ——")
            print("断开期间采样 %d 次；公网请求成功 %d 次（其中非白名单出口 %d 次）"
                  % (result["down_samples"], result["public_succeeded_while_down"], result["real_ip_leaks"]))
            print("断开期间局域网网关可达 %d/%d 次" % (result["gateway_ok_while_down"], result["gateway_samples"]))
            print("TUN 消失后 %s 秒触发锁定" % result["lockdown_after_seconds"])
            print("重新打开 FlClash 后 %s 秒恢复网络%s" % (result["network_back_after_seconds"],
                                                      "；已自动执行紧急恢复（断网保护已关闭，需重新 enable）" if result["rescued"] else ""))
            print("记录文件：%s" % result["log"])
            print("结论：%s" % ("通过" if result["passed"] else "未通过"))
            if not result["rescued"]:
                print("Claude 现在处于锁定（这是演练的预期结果），确认无误后运行 release 解除。")
            return 0 if result["passed"] else 1
        elif command == "watch":
            util.log("watch 启动", "watch")
            svc.watch()
        try:
            if command not in ("watch",):
                svc.write_status()
        except Exception:
            pass
        return 0
    except Exception as exc:
        from .drill import DrillAbort
        if isinstance(exc, (UserError, config.ConfigError, util.CommandError, DrillAbort)):
            util.log("拒绝/失败：%s" % exc, command)
            print("失败：%s" % exc, file=sys.stderr)
            return 1
        util.log("错误：%r" % exc, command)  # unexpected
        print("错误：%r" % exc, file=sys.stderr)
        return 1
