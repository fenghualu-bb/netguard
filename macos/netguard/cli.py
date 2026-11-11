"""`netguard` command line. Mutating commands need root (sudo or the app's admin prompt)."""
import argparse
import json
import os
import sys
import time

from . import VERSION, config, events, paths, util
from .service import Service, UserError

ROOT_COMMANDS = {"enable", "disable", "release", "guard-on", "guard-off", "isolate", "unisolate",
                 "recover", "watch", "verify", "refresh", "whitelist"}


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
    out("  FlClash 内核：%s   TUN：%s" % (
        ("运行中（root 授权）" if core.get("privileged") else "运行中但未授权") if core.get("running") else "未运行",
        obs.get("tun") or "未连接"))
    if status.get("require_claudeguard"):
        out("  ClaudeGuard：%s" % (("运行中（%s）" % cg.get("state")) if cg.get("fresh") else "未运行或状态过期"))
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
        elif command == "watch":
            util.log("watch 启动", "watch")
            svc.watch()
        try:
            if command not in ("watch",):
                svc.write_status()
        except Exception:
            pass
        return 0
    except (UserError, config.ConfigError, util.CommandError) as exc:
        util.log("拒绝/失败：%s" % exc, command)
        print("失败：%s" % exc, file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - unexpected
        util.log("错误：%r" % exc, command)
        print("错误：%r" % exc, file=sys.stderr)
        return 1
