import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import psutil

from portable.config import atomic_json
from portable.platforms import enforce, normalized, spawn, stop_tree
from src.ip_checker import perform_ip_check
from src import policy
from src.proxy_config import cli_environment
from portable.config import default_path
from portable import network


def check(data, policy_dir=None):
    if policy.advanced(data):
        return policy.check(data, policy_dir or default_path().parent)
    if not data["protection_enabled"]:
        return {"state": "disabled", "ip": None, "error": None}
    ip, allowed, error = perform_ip_check(data["allowed_ips"], mode=data["ip_check_mode"], proxy=data["http_proxy"] or None)
    return {"state": "allowed" if allowed else ("blocked" if ip else "offline"), "ip": ip, "error": error}


class InstanceLock:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.file = open(path, "a+b")

    def __enter__(self):
        self.file.seek(0)
        if os.name == "nt":
            import msvcrt
            self.file.write(b"0")
            self.file.flush()
            self.file.seek(0)
            msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return self

    def __exit__(self, *args):
        self.file.close()


# ---------------------------------------------------------------- 保护记录与分级处置（本地补丁，2026-10-31）
# 原版：任何一次未通过（含测不到 IP、网络助手心跳超过 4 秒）都立即结束 Claude，且不留记录，导致 Claude 频繁被误杀。
# 现在：网络拦截照旧立即生效（由网络助手执行）；结束进程按危险程度分级：
#   高（IP 已确认不在白名单 / 程序路径变化）→ 立即结束；中、低（暂时无法确认）→ 持续 SOFT_KILL_AFTER 秒仍未恢复才结束。
# 每一次断网、结束进程、恢复都写入 data/protection-events.jsonl（含原因、危险程度、危险说明），NetGuard 工作台合并显示。
SOFT_KILL_AFTER = 10
EVENTS_NAME = "protection-events.jsonl"
RISKS = {
    "ip_not_allowed": ("高", "出口 IP 已确认不在白名单：Claude 继续联网时，对方看到的是非白名单 IP，账号有风控风险。"),
    "path_changed": ("高", "Claude 程序路径已变化（多为自动更新），新版本不在网络助手的拦截范围内，可能绕过保护。"),
    "helper": ("中", "负责执行断网的网络助手暂时失联或状态过期，Claude 的网络拦截可能没有生效；NetGuard 断网保护仍可防止真实 IP 泄露。"),
    "error": ("中", "出口检查过程出错，无法确认当前是否安全，按未通过处理。"),
    "offline": ("低", "暂时测不到出口 IP（多为代理节点短暂卡顿）。此时 Claude 的网络已被切断，不会泄露。"),
}
LEVEL_ORDER = {"低": 1, "中": 2, "高": 3}


def classify_error(text):
    if "程序路径已变化" in text:
        return "path_changed"
    if "网络助手" in text or "WinError 5" in text or "Errno 13" in text or "无法创建该文件" in text:
        return "helper"
    return "error"


def record_event(settings, kind, summary, reasons, detail=None):
    """reasons: [(code, text)]。写入一行 JSON；最多保留 2000 条。记录失败不影响保护本身。"""
    try:
        items = [{"code": code, "text": text, "level": RISKS[code][0], "why": RISKS[code][1]} for code, text in reasons]
        severity = max((i["level"] for i in items), key=LEVEL_ORDER.get, default="低")
        line = json.dumps({"ts": time.time(), "source": "ClaudeGuard", "type": kind, "severity": severity,
                           "summary": summary, "reasons": items, "detail": detail}, ensure_ascii=False)
        path = settings.path.with_name(EVENTS_NAME)
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        if path.stat().st_size > 1_500_000:
            lines = path.read_text(encoding="utf-8").splitlines()[-2000:]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        logging.exception("写保护记录失败")


def running_targets(paths):
    paths = {normalized(p) for p in paths if p}
    me = psutil.Process().username()
    found = 0
    for process in psutil.process_iter(["exe", "username"]):
        try:
            if process.info["username"] == me and process.info.get("exe") and normalized(process.info["exe"]) in paths:
                found += 1
        except (psutil.Error, OSError):
            continue
    return found


def kill_claude(settings, data, code, text, waited=None):
    paths = [data["cli_path"], data["desktop_path"]]
    count = running_targets(paths)
    errors = enforce(paths)
    if count or errors:
        how = "立即结束" if waited is None else f"持续 {waited:.0f} 秒未恢复后结束"
        summary = f"{how} {count} 个 Claude 进程" + (f"（{len(errors)} 个失败）" if errors else "")
        record_event(settings, "kill", summary, [(code, text)], {"killed": count, "errors": errors[:5]})
        logging.warning("%s：%s", summary, text)
    return errors


def daemon(settings):
    state_path = settings.path.with_name("portable-state.json")
    settings.path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(handlers=[RotatingFileHandler(settings.path.with_name("portable.log"), maxBytes=1048576, backupCount=2, encoding="utf-8")],
                        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with InstanceLock(settings.path.with_name("portable.lock")):
        previous = None
        last_data = None
        net_blocked_since = None   # 当前是否处于“已切断 Claude 网络”状态（用于记录断开 / 恢复）
        soft_since = None          # 中、低危险持续开始时间
        while True:
            verdict = None
            try:
                data = settings.load()
                if data != last_data and data.get('network_guard_enabled'):
                    network.publish(settings, data, {'state': 'blocked'})
                last_data = data
                verdict = check(data, settings.path.parent)
                state, ip = verdict["state"], verdict.get("ip")
                if state in ("allowed", "disabled"):
                    reason = None
                elif state == "blocked" and ip:
                    reason = ("ip_not_allowed", f"出口 {ip} 不在白名单")
                elif state == "offline":
                    reason = ("offline", "测不到出口 IP")
                else:
                    reason = ("error", verdict.get("reason") or verdict.get("error") or f"检查结果 {state}")
                verdict['network'] = network.publish(settings, data, verdict)
                errors = []
                now = time.time()
                if reason is None:
                    if net_blocked_since is not None:
                        record_event(settings, "net_restore", f"出口恢复正常（{ip}），已恢复 Claude 网络；此前断开 {now - net_blocked_since:.0f} 秒", [])
                    net_blocked_since = soft_since = None
                else:
                    if net_blocked_since is None:
                        net_blocked_since = now
                        record_event(settings, "net_block", "已切断 Claude 网络（网络助手执行）", [reason])
                    if RISKS[reason[0]][0] == "高":
                        errors = kill_claude(settings, data, *reason)
                    else:
                        soft_since = soft_since or now
                        if now - soft_since >= SOFT_KILL_AFTER:
                            errors = kill_claude(settings, data, *reason, waited=now - soft_since)
                verdict.update({"pid": os.getpid(), "process_created": psutil.Process().create_time(),
                                "checked_at": time.time(), "mode": data["ip_check_mode"], "enforcement_errors": errors})
                atomic_json(state_path, verdict)
                event = (verdict["state"], verdict["ip"], tuple(errors))
                if event != previous:
                    logging.info("state=%s ip=%s errors=%s", *event)
                    previous = event
                interval = data["check_interval"]
            except Exception as exc:
                # Keep guarding the last known targets, never reuse an allowed verdict.
                errors = []
                if last_data:
                    try:
                        network.publish(settings, last_data, {'state': 'blocked'})
                    except Exception:
                        pass
                now = time.time()
                text = str(exc) or type(exc).__name__
                # 出错前若已确认 IP 不在白名单，仍按高危立即处理
                if verdict and verdict.get("state") == "blocked" and verdict.get("ip"):
                    code, text = "ip_not_allowed", f"出口 {verdict['ip']} 不在白名单（随后检查出错：{text}）"
                else:
                    code = classify_error(text)
                if net_blocked_since is None:
                    net_blocked_since = now
                    record_event(settings, "net_block", "已请求切断 Claude 网络（检查出错）", [(code, text)])
                if last_data and last_data["protection_enabled"]:
                    if RISKS[code][0] == "高":
                        errors = kill_claude(settings, last_data, code, text)
                    else:
                        soft_since = soft_since or now
                        if now - soft_since >= SOFT_KILL_AFTER:
                            errors = kill_claude(settings, last_data, code, text, waited=now - soft_since)
                atomic_json(state_path, {"state": "error", "checked_at": time.time(),
                                        "pid": os.getpid(), "process_created": psutil.Process().create_time(),
                                        "enforcement_errors": errors})
                logging.exception("配置或出口检测失败，等待下一轮重试")
                interval = 3
            time.sleep(interval)


def daemon_process(settings):
    try:
        state = json.loads(settings.path.with_name("portable-state.json").read_text(encoding="utf-8"))
        process = psutil.Process(state["pid"])
        if abs(process.create_time() - state["process_created"]) < 0.001 and process.is_running():
            return process
    except (OSError, ValueError, KeyError, psutil.Error):
        pass
    return None


def start_daemon(settings):
    if daemon_process(settings):
        return
    python = Path(sys.executable)
    if os.name == "nt" and python.with_name("pythonw.exe").exists():
        python = python.with_name("pythonw.exe")
    settings.path.parent.mkdir(parents=True, exist_ok=True)
    with open(settings.path.with_name("portable-console.log"), "ab") as output:
        return subprocess.Popen([str(python), str(Path(__file__).with_name("main.py")), "--config", str(settings.path), "daemon"],
                         stdout=output, stderr=output, start_new_session=(os.name != "nt"))


def launch(settings, target, args):
    data = settings.load()
    verdict = check(data, settings.path.parent)  # Never trust a cached verdict at launch.
    if verdict["state"] not in ("allowed", "disabled"):
        raise ValueError(f"已阻止启动：{verdict['ip'] or verdict['error'] or '出口未通过检查'}")
    env = cli_environment(data, os.environ) if target == "cli" else os.environ.copy()
    if data.get('network_guard_enabled'):
        if not network.paths(data) or not data.get(target + '_path'):
            raise ValueError('请先设置要保护的程序路径，并安装网络助手')
        start_daemon(settings)
        process = network.guarded_spawn(settings, data, data[target + '_path'], args, env)
    elif target == "cli":
        process = spawn(data[target + "_path"], args, env=env)
    else:
        process = spawn(data[target + "_path"], args)
    tracked = psutil.Process(process.pid)
    try:
        while process.poll() is None:
            data = settings.load()
            if check(data, settings.path.parent)["state"] not in ("allowed", "disabled"):
                stop_tree(tracked)
                return 1
            time.sleep(data["check_interval"])
        return process.returncode
    finally:
        # Closing the launcher also stops the session it owns.
        if process.poll() is None:
            stop_tree(tracked)
