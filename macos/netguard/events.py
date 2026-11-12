"""Protection records: one JSON object per line, same shape as the Windows version."""
import json
import os
import time

from . import paths

# key -> (level, why). Same codes and wording as Windows where they mean the same thing.
RISK = {
    "egress": ("高", "普通流量出口不在白名单：代理节点或模式变了，经此出口的连接（包括 Claude 网页里的请求）用的不是白名单 IP。"),
    "egress_claude": ("高", "claude.ai 出口不在白名单：Claude 继续联网时对方看到的是非白名单 IP，账号有风控风险。"),
    "killswitch": ("高", "断网保护规则不完整或 pf 未生效：代理一旦断开，流量可能直接用真实 IP 发出。"),
    "core": ("中", "FlClash 内核未运行或未获授权：代理中断。断网保护会拦住直连，真实 IP 不会泄露，但保护链出现缺口。"),
    "tun": ("中", "TUN 虚拟网卡未连接：代理中断。断网保护会拦住直连，真实 IP 不会泄露，但保护链出现缺口。"),
    "guard_daemon": ("中", "ClaudeGuard 未运行或状态过期：少了它的 3 秒一次出口检查和 Claude 域名拦截，只剩 NetGuard 每 10 秒一次的检查。"),
    "guard_helper": ("中", "ClaudeGuard 报告执行错误：出口不对时，它可能无法拦截 Claude 域名。"),
    "claude_path": ("高", "Claude 已更新或重装，ClaudeGuard 的钩子没有跟上：直接运行 claude 或打开 Claude 时可能绕过 ClaudeGuard 的出口检查。"),
    "mode": ("中", "FlClash 不是全局模式：规则模式下 Claude 的部分流量可能被分流为直连（Anthropic 官方网段仍会被拦截，claude.ai 走 Cloudflare 的部分只能靠出口检查发现）。"),
    "guard_off": ("中", "ClaudeGuard 的保护被关闭：出口不对时它不会拦截 Claude，只剩 NetGuard 每 10 秒一次的检查。"),
    "user": ("低", "用户主动操作，不是异常。"),
    "error": ("中", "检查过程出错，无法确认当前是否安全。"),
}
LEVEL_ORDER = {"低": 1, "中": 2, "高": 3}


def finding(key, text):
    return {"key": key, "text": text}


def format_reasons(items):
    out = []
    for item in items or []:
        if isinstance(item, str):
            code, text = "error", item
        else:
            code, text = str(item.get("key", "error")), str(item.get("text", ""))
        level, why = RISK.get(code, RISK["error"])
        out.append({"code": code, "text": text, "level": level, "why": why})
    return out


def add(kind, summary, reasons=None, detail=None, path=None):
    items = format_reasons(reasons)
    severity = max((i["level"] for i in items), key=LEVEL_ORDER.get) if items else "—"
    line = json.dumps({"ts": int(time.time()), "source": "NetGuard", "type": kind, "severity": severity,
                       "summary": summary, "reasons": items, "detail": detail}, ensure_ascii=False)
    target = path or paths.EVENTS
    try:
        with open(target, "a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        os.chmod(target, 0o644)
        if os.path.getsize(target) > 1_500_000:
            with open(target, "r", encoding="utf-8") as stream:
                keep = stream.read().splitlines()[-2000:]
            with open(target, "w", encoding="utf-8") as stream:
                stream.write("\n".join(keep) + "\n")
    except OSError:
        pass


def read(limit=200, path=None):
    out = []
    try:
        with open(path or paths.EVENTS, "r", encoding="utf-8") as stream:
            lines = stream.read().splitlines()[-limit:]
    except OSError:
        return out
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
