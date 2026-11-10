"""NetGuard 工作台：监测 ClaudeGuard / FlClash / 全局断网保护，并提供一键操作与真实 IP 模式向导。

用 ClaudeGuard 自带的 venv 运行（已带 psutil 和 tkinter）。本程序以普通用户权限运行，
需要管理员的操作一律通过 UAC 调用 C:\\ProgramData\\NetGuard 下受保护的脚本。
"""
import ctypes
import concurrent.futures
import hashlib
import ipaddress
import queue
import ctypes.wintypes as wt
import json
import os
import re
import subprocess
import threading
import time
import tkinter as tk
import urllib.request
from pathlib import Path
from tkinter import messagebox, ttk

import psutil

LOCAL = Path(os.environ["LOCALAPPDATA"])
PROGRAMDATA = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
GUARD = LOCAL / "Programs" / "ClaudeGuard"
GUARD_CONFIG = GUARD / "data" / "config.json"
GUARD_LNK = Path(os.environ["USERPROFILE"]) / "Desktop" / "ClaudeGuard.lnk"
FLCLASH_EXE = LOCAL / "Programs" / "FlClash" / "FlClash.exe"
FLCLASH_CONFIG = Path(os.environ["APPDATA"]) / "com.follow" / "clash" / "config.yaml"
NETGUARD = PROGRAMDATA / "NetGuard"
HERE = Path(__file__).resolve().parent
REALIP_FLAG = HERE / "realip-mode.json"
POWERSHELL = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
NO_WINDOW = 0x08000000
CHECK_URL = "https://www.cloudflare.com/cdn-cgi/trace"
CLAUDE_URL = "https://claude.ai/cdn-cgi/trace"

VERSION = "1.3.4"
LOADED_SOURCE_HASH = hashlib.sha256(Path(__file__).read_bytes()).digest()

# 深色监控台配色
BG, SIDEBAR, PANEL, PANEL2, HOVER, BORDER, SELECT = "#1e1f22", "#16171a", "#2b2d31", "#383a40", "#43464d", "#3a3c42", "#3d4a63"
TEXT, MUTED, DISABLED = "#e6e7e9", "#9aa0a8", "#6b7079"
ACCENT, ACCENT_HOVER = "#3b82f6", "#2f6fd6"
GOOD, BAD, WARN, INFO = "#3fb950", "#f85149", "#d29922", "#9aa0a8"
UI_FONT, MONO_FONT = "Microsoft YaHei UI", "Consolas"


# ---------------------------------------------------------------- data collection
def run(cmd, timeout=20):
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        return out.returncode, out.stdout.decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - shown in the UI
        return -1, type(exc).__name__


def trace_ip(url):
    # 不使用任何代理设置：走系统路由（TUN），和普通程序看到的出口一致
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "NetGuard"}), timeout=8) as r:
            m = re.search(r"^ip=(.+)$", r.read(65536).decode("utf-8", "replace"), re.M)
            return str(ipaddress.ip_address(m.group(1).strip())) if m else None
    except Exception:
        return None


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def fresh_status(status, max_age=180):
    try:
        age = time.time() - float(status.get("updated_at", 0))
        return -5 <= age <= max_age
    except (TypeError, ValueError, AttributeError):
        return False


def tail_line(path):
    try:
        with Path(path).open("rb") as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 8192))
            lines = stream.read().decode("utf-8-sig", "replace").strip().splitlines()
        return lines[-1] if lines else ""
    except OSError:
        return ""


def locate_flclash_config():
    """按正在运行的 FlClash.exe 自己的 APPDATA 定位配置，而不是本进程的 %APPDATA%。

    2026-10-29 教训：沙盒或其他账户的 %APPDATA% 会指向另一个目录，读到 0 字节旧文件后被误判为配置异常。
    FlClash 未运行时才退回本进程的 %APPDATA%，并在结果里标明来源。"""
    for p in psutil.process_iter(["name"]):
        if (p.info.get("name") or "").lower() != "flclash.exe":
            continue
        try:
            appdata = p.environ().get("APPDATA")
        except (psutil.Error, OSError):
            appdata = None
        if appdata:
            return Path(appdata) / "com.follow" / "clash" / "config.yaml", "FlClash 进程"
    return FLCLASH_CONFIG, "本进程 %APPDATA%（FlClash 未运行）"


def prefs_strict_route(directory):
    # FlClash 的界面设置：tun-override 中是否覆写并开启 strict-route。只读这两个字段。
    try:
        raw = json.loads((Path(directory) / "shared_preferences.json").read_text(encoding="utf-8-sig"))
        patch_cfg = json.loads(raw["flutter.config"])["patchClashConfig"]
        if "strict-route" not in (patch_cfg.get("tun-override-keys") or []):
            return None
        return bool((patch_cfg.get("tun-override") or {}).get("strict-route"))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def flclash_config(path=None, source="本进程 %APPDATA%"):
    # Only these scalar fields are read. Never load or display node credentials.
    path = Path(path or FLCLASH_CONFIG)
    result = {"flclash_mode": "?", "strict_route": None, "fl_config_note": "运行配置待核实",
              "fl_config_path": str(path), "fl_config_source": source, "fl_config_size": None,
              "fl_config_mtime": None, "prefs_strict": prefs_strict_route(path.parent)}
    try:
        st = path.stat()
        result["fl_config_size"], result["fl_config_mtime"] = st.st_size, st.st_mtime
    except OSError:
        pass
    try:
        text = path.read_text(encoding="utf-8-sig")
        if not text.strip():
            result["fl_config_note"] = "配置文件为空；不能据此判断运行模式或严格路由"
            return result
        mode = re.search(r'^mode:\s*["\']?(global|rule|direct)["\']?\s*(?:#.*)?$', text, re.M)
        tun_section = re.search(r'^tun:\s*\n((?:[ \t]+[^\n]*\n?|[ \t]*\n)*)', text, re.M)
        strict = re.search(r'^\s+strict-route:\s*(true|false)\s*(?:#.*)?$', tun_section.group(1), re.M) if tun_section else None
        result["flclash_mode"] = mode.group(1) if mode else "?"
        result["strict_route"] = strict.group(1) == "true" if strict else None
        result["fl_config_note"] = "来自 FlClash 生成的配置；未做断线测试"
    except (OSError, UnicodeError):
        result["fl_config_note"] = "无法读取配置；未将未知状态当作关闭或正常"
    return result


def config_source_text(s):
    size, mtime = s.get("fl_config_size"), s.get("fl_config_mtime")
    when = time.strftime("%m-%d %H:%M", time.localtime(mtime)) if mtime else "?"
    return f"{s.get('fl_config_path', '?')}（{s.get('fl_config_source', '?')}；{size if size is not None else '?'} 字节，{when}）"


def strict_route_view(s):
    """严格路由分三档证据，返回 (显示文字, 颜色, 总状态警告或 None)。

    1. 运行时证据：SYSTEM 核对任务在 WFP 中看到 FlClash 内核（sing-tun）的 "block ipv4/ipv6 dns" 规则。
       这是唯一能证明“内核正在执行严格路由”的证据，不依赖任何配置文件或读取者账户。
    2. 运行时已检查但没看到规则：内核在运行却没有加载 → 判定未生效。
    3. 没有新鲜的运行时数据（旧版管理脚本 / 核对任务停了）：只能看配置，如实标注待证实。"""
    cfg, prefs = s.get("strict_route"), s.get("prefs_strict")
    cfg_text = {True: "开启", False: "关闭", None: "未知"}[cfg]
    rt = (s.get("ng_status") or {}).get("strict_route_runtime")
    core_running = bool(s.get("flclash_core") and s.get("tun_up"))
    if isinstance(rt, dict) and not rt.get("error") and fresh_status({"updated_at": rt.get("checked_at")}):
        if rt.get("detected"):
            note = "" if cfg is True else f"；注意配置文件显示「{cfg_text}」，以运行时为准"
            return f"开启（运行时已证实：内核 {rt.get('total', '?')} 条 WFP 规则在执行，所有者 {rt.get('owner') or '?'}{note}）", GOOD, None
        if core_running:
            return f"未生效：内核在运行，但 WFP 中没有严格路由规则（配置显示「{cfg_text}」）", BAD, "严格路由未在内核生效"
        return "无法证实：FlClash 内核或 TUN 未运行", WARN, "严格路由无法证实（内核未运行）"
    if cfg is True and prefs is not False:
        return "配置为开启；运行时证据需先「更新管理脚本」（需 UAC）", WARN, "严格路由运行时待证实（需更新管理脚本）"
    if cfg is False or prefs is False:
        return f"关闭（配置「{cfg_text}」，界面设置「{ {True: '开启', False: '关闭', None: '未覆写'}[prefs] }」）", WARN, "严格路由未开启"
    return "待核实：读不到配置，也没有运行时证据", WARN, "严格路由待核实"


def isolation_targets_covered(cfg=None, expected=None):
    # Re-run immediately before/after isolation; cached coverage is not authorization.
    try:
        cfg = read_json(GUARD_CONFIG) if cfg is None else cfg
        if not isinstance(cfg, dict): return False
        if expected is None:
            code, location = run([str(POWERSHELL), "-NoProfile", "-Command",
                                  "(Get-AppxPackage -Name Claude | Sort-Object Version -Descending | Select-Object -First 1).InstallLocation"], timeout=5)
            if code or not location.strip(): return False
            expected = str(Path(location.strip()) / "app/claude.exe")
        desktop, cli = cfg.get("desktop_path"), cfg.get("cli_path")
        if not desktop or not cli or os.path.normcase(desktop) != os.path.normcase(expected): return False
        if not Path(desktop).is_file() or not Path(cli).is_file(): return False
        targets = {os.path.normcase(desktop), os.path.normcase(cli)}
        manifest_targets = set()
        for path in (PROGRAMDATA / "ClaudeGuardNetwork").glob("*/manifest.json"):
            manifest = read_json(path) or {}
            manifest_targets.update(os.path.normcase(str(item)) for item in manifest.get("programs", []) if item)
        return len(targets) == 2 and targets <= manifest_targets
    except (OSError, TypeError, ValueError):
        return False


def collect():
    started = time.monotonic()
    s = {"time": time.strftime("%H:%M:%S"), "collected_at": time.time()}
    cfg = read_json(GUARD_CONFIG) or {}
    s["whitelist"] = cfg.get("allowed_ips") or []
    s["guard_protection_enabled"] = cfg.get("protection_enabled") is True
    s["guard_network_enabled"] = cfg.get("network_guard_enabled") is True
    s["claude_configured"] = cfg.get("desktop_path")
    s["claude_path_exists"] = bool(cfg.get("desktop_path") and Path(cfg["desktop_path"]).is_file())
    s["cli_path_exists"] = bool(cfg.get("cli_path") and Path(cfg["cli_path"]).is_file())
    # Independent I/O shares one background collection, rather than serial timeouts.
    ps_command = (
        "$p=(Get-AppxPackage -Name Claude | Sort-Object Version -Descending | Select-Object -First 1).InstallLocation; "
        "$task=Get-ScheduledTask ClaudeGuard-HealthCheck -EA SilentlyContinue; $t=$task | Get-ScheduledTaskInfo; "
        "[pscustomobject]@{location=$p;health=if($t){'{0}|{1}' -f $t.LastTaskResult,$t.NextRunTime}else{''};"
        "health_enabled=($task -and $task.State -ne 'Disabled');health_last_run=if($t){([DateTimeOffset]$t.LastRunTime).ToUnixTimeSeconds()}else{0};"
        "health_next_run=if($t -and $t.NextRunTime.Year -gt 2000){([DateTimeOffset]$t.NextRunTime).ToUnixTimeSeconds()}else{0}} | ConvertTo-Json -Compress"
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        guard_job = pool.submit(run, [str(GUARD / "venv/Scripts/python.exe"), str(GUARD / "portable/main.py"),
                                     "--config", str(GUARD_CONFIG), "status"])
        system_job = pool.submit(run, [str(POWERSHELL), "-NoProfile", "-Command", ps_command])
        egress_job = pool.submit(trace_ip, CHECK_URL)
        claude_job = pool.submit(trace_ip, CLAUDE_URL)
        code, out = guard_job.result()
        try:
            s["guard"] = json.loads(out)
            if not isinstance(s["guard"], dict): raise ValueError("invalid status")
        except (ValueError, TypeError):
            s["guard"] = {"error": "状态命令失败，请查看 ClaudeGuard 日志", "daemon_running": False}
        _, out = system_job.result()
        try:
            system = json.loads(out)
        except (ValueError, TypeError):
            system = {}
        loc = system.get("location")
        s["claude_expected"] = str(Path(loc) / "app/claude.exe") if loc else None
        s["health_task"] = system.get("health") or ""
        s["health_task_enabled"] = bool(system.get("health_enabled"))
        s["health_last_run"] = system.get("health_last_run", 0)
        s["health_next_run"] = system.get("health_next_run", 0)
        s["egress"], s["egress_claude"] = egress_job.result(), claude_job.result()
    names = {p.info["name"].lower() for p in psutil.process_iter(["name"]) if p.info["name"]}
    s["flclash_ui"], s["flclash_core"] = "flclash.exe" in names, "flclashcore.exe" in names
    tun = psutil.net_if_stats().get("FlClash")
    s["tun_up"] = bool(tun and tun.isup)
    s.update(flclash_config(*locate_flclash_config()))
    s["ng_installed"] = (NETGUARD / "netguard.ps1").is_file()
    s["ng_outdated"] = s["ng_installed"] and any(
        not (NETGUARD / name).is_file() or (HERE / "admin" / name).read_bytes() != (NETGUARD / name).read_bytes()
        for name in ("netguard.ps1", "netguard_wfp.cs"))
    s["ng_status"] = read_json(NETGUARD / "status.json")
    s["ng_log"] = tail_line(NETGUARD / "netguard.log")
    health_log = GUARD / "monitor/check.log"
    s["health_last"] = tail_line(health_log)
    s["health_log_updated_at"] = health_log.stat().st_mtime if health_log.exists() else 0
    s["isolation_targets_ok"] = isolation_targets_covered(cfg, s["claude_expected"]) if s["claude_expected"] else False
    lockdown = bool(((s["ng_status"] or {}).get("guard") or {}).get("lockdown"))
    # 自动防护锁定也会让 Claude 处于隔离，但那不是真实 IP 模式
    s["realip"] = REALIP_FLAG.exists() or (bool((s["ng_status"] or {}).get("active_claude_block")) and not lockdown)
    s["events"] = read_events()
    # ClaudeGuard 本地补丁（分级处置 + 保护记录）；重装 / 升级 ClaudeGuard 会把它覆盖掉
    try:
        s["guard_patch_ok"] = "SOFT_KILL_AFTER" in (GUARD / "portable" / "runtime.py").read_text(encoding="utf-8")
    except OSError:
        s["guard_patch_ok"] = False
    s["ui_source_changed"] = hashlib.sha256(Path(__file__).read_bytes()).digest() != LOADED_SOURCE_HASH
    s["duration"] = round(time.monotonic() - started, 1)
    s["time"], s["collected_at"] = time.strftime("%H:%M:%S"), time.time()
    return s


# ---------------------------------------------------------------- elevation
class SHELLEXECUTEINFO(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wt.HWND), ("lpVerb", wt.LPCWSTR),
                ("lpFile", wt.LPCWSTR), ("lpParameters", wt.LPCWSTR), ("lpDirectory", wt.LPCWSTR), ("nShow", ctypes.c_int),
                ("hInstApp", wt.HINSTANCE), ("lpIDList", ctypes.c_void_p), ("lpClass", wt.LPCWSTR), ("hkeyClass", wt.HKEY),
                ("dwHotKey", wt.DWORD), ("hIcon", wt.HANDLE), ("hProcess", wt.HANDLE)]


def run_elevated(args):
    """以管理员运行 PowerShell 脚本并等待；返回退出码，用户在 UAC 点“否”时返回 None。"""
    info = SHELLEXECUTEINFO(cbSize=ctypes.sizeof(SHELLEXECUTEINFO), fMask=0x40, lpVerb="runas",
                            lpFile=str(POWERSHELL), lpParameters=subprocess.list2cmdline(args), nShow=0)
    ctypes.windll.shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFO)]
    ctypes.windll.shell32.ShellExecuteExW.restype = wt.BOOL
    ctypes.windll.kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    ctypes.windll.kernel32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
    ctypes.windll.kernel32.CloseHandle.argtypes = [wt.HANDLE]
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        return None
    ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
    code = wt.DWORD()
    ctypes.windll.kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    ctypes.windll.kernel32.CloseHandle(info.hProcess)
    return code.value


def netguard(action):
    return run_elevated(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(NETGUARD / "netguard.ps1"), "-Action", action])


def last_netguard_log():
    try:
        return (NETGUARD / "netguard.log").read_text(encoding="utf-8").strip().splitlines()[-1]
    except Exception:
        return "（没有日志）"


# ---------------------------------------------------------------- UI
EVENT_TYPES = {
    "isolation_sync": ("隔离已同步", WARN), "isolation_sync_failed": ("隔离同步失败", BAD),
    "trigger": ("锁定隔离", BAD), "release": ("解除锁定", GOOD), "release_refused": ("解除被拒", WARN),
    "suspect": ("发现异常", WARN), "recovered": ("自行恢复", INFO), "info": ("信息", INFO),
    "config": ("设置变更", ACCENT), "guard_error": ("检查出错", BAD),
    "kill": ("结束 Claude", BAD), "net_block": ("切断网络", WARN), "net_restore": ("恢复网络", GOOD),
    "isolate": ("隔离 Claude", WARN), "unisolate": ("解除隔离", GOOD),
}
# 「保护动作」：任何一次切断网络、结束进程、隔离、锁定 / 解除都算；默认只看这些
KEY_EVENTS = {"isolation_sync", "isolation_sync_failed", "trigger", "release", "release_refused", "guard_error", "config", "kill", "net_block", "isolate", "unisolate"}
SEVERITY_COLOR = {"高": BAD, "中": WARN, "低": INFO}
GUARD_EVENTS = GUARD / "data" / "protection-events.jsonl"


def _read_jsonl(path, limit, source):
    try:
        with Path(path).open("rb") as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 400_000))
            lines = stream.read().decode("utf-8-sig", "replace").splitlines()
    except OSError:
        return []
    events = []
    for line in lines[-limit:]:
        try:
            item = json.loads(line.lstrip("\ufeff"))
            if isinstance(item, dict) and "ts" in item:
                item.setdefault("source", source)
                events.append(item)
        except ValueError:
            continue
    return events


def read_events(limit=500):
    """合并两处保护记录：NetGuard 自动防护（SYSTEM 写在 ProgramData）+ ClaudeGuard 守护进程（写在其 data 目录）。"""
    merged = _read_jsonl(NETGUARD / "events.jsonl", limit, "NetGuard") + _read_jsonl(GUARD_EVENTS, limit, "ClaudeGuard")
    merged.sort(key=lambda e: float(e.get("ts", 0)))
    return merged[-limit:]


def event_severity(e):
    sev = e.get("severity")
    if sev in SEVERITY_COLOR: return sev
    levels = [r.get("level") for r in e.get("reasons") or [] if isinstance(r, dict)]
    for level in ("高", "中", "低"):
        if level in levels: return level
    return "—"


def reason_lines(e):
    out = []
    for r in e.get("reasons") or []:
        if isinstance(r, dict):
            out.append(f"【{r.get('level', '—')}】{r.get('text', '')}\n      危险说明：{r.get('why', '—')}")
        else:
            out.append(f"【—】{r}")
    return out


def guard_view(s):
    """自动防护卡片：返回 {key: (文字, 颜色)}、问题列表、警告列表。"""
    st = s.get("ng_status") or {}
    g = st.get("guard")
    rows, problems, warnings = {}, [], []
    if not isinstance(g, dict):
        rows["ag_state"] = ("后台未提供（请更新管理脚本）", WARN)
        rows["ag_check"] = rows["ag_reason"] = rows["ag_count"] = ("—", INFO)
        warnings.append("自动防护待安装（更新管理脚本）")
        return rows, problems, warnings
    last = g.get("last_check") or 0
    stale = not fresh_status({"updated_at": last}, 90)
    if g.get("lockdown"):
        since = time.strftime("%m-%d %H:%M:%S", time.localtime(g.get("since") or 0))
        isolated = st.get("active_claude_block") and st.get("claude_block_complete") and fresh_status(st)
        label = "清单内程序已隔离，等待手动解除" if isolated else "隔离规则待同步，保持锁定"
        rows["ag_state"] = (f"已锁定：{label}（{since} 触发）", BAD)
        if g.get("last_findings"):
            detail = "仍有异常，修复后再手动解除锁定"
        elif stale:
            detail = "最近检查待刷新，保持锁定"
        elif isolated:
            detail = "当前未发现异常，解除前将重新检查"
        else:
            detail = "隔离范围尚未完整核实"
        problems.append("自动防护已触发；" + detail)
    elif not g.get("enabled"):
        rows["ag_state"] = ("已关闭（不会自动隔离 Claude）", WARN)
        warnings.append("自动防护已关闭")
    elif stale:
        rows["ag_state"] = ("检查停滞（超过 90 秒没有新结果）", BAD)
        problems.append("自动防护检查停滞")
    elif g.get("bad_streak"):
        rows["ag_state"] = (f"发现异常，确认中 {g.get('bad_streak')}/{g.get('confirm', 2)}", WARN)
    else:
        rows["ag_state"] = (f"待命：每 {g.get('interval', 10)} 秒检查，连续 {g.get('confirm', 2)} 次异常即隔离 Claude", GOOD)
    rows["ag_check"] = (time.strftime("%H:%M:%S", time.localtime(last)) if last else "尚未检查", BAD if stale else INFO)
    reasons = g.get("last_findings") or []
    if g.get("lockdown"):
        history = "；".join(g.get("reasons") or []) or "未记录"
        current = "；".join(reasons) if reasons else "检查已恢复，等待手动解除"
        rows["ag_reason"] = (f"触发时：{history}\n当前：{current}", BAD if reasons else WARN)
    else:
        rows["ag_reason"] = ("；".join(reasons) if reasons else "无", WARN if reasons else INFO)
    rows["ag_count"] = (f"{g.get('triggers', 0)} 次", INFO)
    return rows, problems, warnings


class Workbench(tk.Tk):
    PAGES = (("overview", "总览"), ("records", "保护记录"), ("maintenance", "维护"))

    def __init__(self):
        super().__init__()
        self.title("NetGuard 工作台")
        self.configure(bg=BG)
        self.events = queue.Queue()
        self.action_buttons = []
        self._refreshing = False
        self.state_data = {}
        self.busy = False
        self.record_filter = "key"
        self.event_list = []
        self.px = lambda inches: int(self.winfo_fpixels(f"{inches}i"))
        self._style()

        # 左侧导航
        side = tk.Frame(self, bg=SIDEBAR, width=self.px(1.9))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Label(side, text="NETGUARD", bg=SIDEBAR, fg=TEXT, font=(UI_FONT, 15, "bold"), anchor="w").pack(fill="x", padx=16, pady=(18, 0))
        tk.Label(side, text="Claude 网络防护工作台", bg=SIDEBAR, fg=MUTED, font=(UI_FONT, 9), anchor="w").pack(fill="x", padx=16, pady=(0, 18))
        self.nav = {}
        for key, label in self.PAGES:
            b = ttk.Button(side, text=label, style="Nav.TButton", command=lambda k=key: self.show_page(k))
            b.pack(fill="x", padx=8, pady=2)
            self.nav[key] = b
        self.side_status = tk.Label(side, text="", bg=SIDEBAR, fg=MUTED, font=(UI_FONT, 8), anchor="w", justify="left", wraplength=self.px(1.7))
        self.side_status.pack(side="bottom", fill="x", padx=16, pady=14)

        main = tk.Frame(self, bg=BG)
        main.pack(side="left", fill="both", expand=True)

        # 顶部状态横幅
        banner = tk.Frame(main, bg=PANEL)
        banner.pack(fill="x", padx=16, pady=(16, 8))
        self.banner_bar = tk.Frame(banner, bg=MUTED, width=6)
        self.banner_bar.pack(side="left", fill="y")
        text_box = tk.Frame(banner, bg=PANEL)
        text_box.pack(side="left", fill="both", expand=True, padx=14, pady=10)
        self.verdict = tk.Label(text_box, text="正在检测…", bg=PANEL, fg=TEXT, font=(UI_FONT, 14, "bold"), anchor="w", justify="left")
        self.verdict.pack(fill="x")
        self.updated = tk.Label(text_box, text="", bg=PANEL, fg=MUTED, font=(UI_FONT, 9), anchor="w", justify="left")
        self.updated.pack(fill="x", pady=(2, 0))
        ip_box = tk.Frame(banner, bg=PANEL)
        ip_box.pack(side="right", padx=16, pady=8)
        tk.Label(ip_box, text="当前出口", bg=PANEL, fg=MUTED, font=(UI_FONT, 8), anchor="e").pack(fill="x")
        self.banner_ip = tk.Label(ip_box, text="—", bg=PANEL, fg=TEXT, font=(MONO_FONT, 15, "bold"), anchor="e")
        self.banner_ip.pack(fill="x")
        banner.bind("<Configure>", lambda e: self.verdict.configure(wraplength=max(200, e.width - ip_box.winfo_reqwidth() - self.px(0.7))))

        self.page_host = tk.Frame(main, bg=BG)
        self.page_host.pack(fill="both", expand=True)
        self.pages = {key: tk.Frame(self.page_host, bg=BG) for key, _ in self.PAGES}
        self.rows = {}
        self._build_overview(self.pages["overview"])
        self._build_records(self.pages["records"])
        self._build_maintenance(self.pages["maintenance"])
        self.show_page("overview")

        self.update_idletasks()
        width = min(max(self.px(9.5), self.winfo_reqwidth()), self.winfo_screenwidth() - 40)
        height = min(max(self.px(6.4), self.winfo_reqheight()), self.winfo_screenheight() - 100)
        self.geometry(f"{width}x{height}")
        self.minsize(min(width, self.px(7.5)), min(height, self.px(4)))
        self.after(80, self.drain_events)
        self.refresh()
        self.after(15000, self.auto_refresh)

    # -------- 外观
    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        base = (UI_FONT, 10)
        style.configure(".", background=BG, foreground=TEXT, fieldbackground=PANEL, bordercolor=BORDER,
                        lightcolor=BORDER, darkcolor=BORDER, troughcolor=BG, font=base, focuscolor=ACCENT)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Big.TLabel", font=(UI_FONT, 14, "bold"))
        pad = (self.px(0.14), self.px(0.07))
        for name, bg, hover in (("TButton", PANEL2, HOVER), ("Accent.TButton", ACCENT, ACCENT_HOVER), ("Danger.TButton", "#8b2c2c", "#a33a3a")):
            style.configure(name, background=bg, foreground=TEXT, borderwidth=0, padding=pad, relief="flat", anchor="center")
            style.map(name, background=[("disabled", PANEL), ("active", hover)], foreground=[("disabled", DISABLED)])
        style.configure("Nav.TButton", background=SIDEBAR, foreground=MUTED, anchor="w", padding=(self.px(0.12), self.px(0.08)), borderwidth=0)
        style.map("Nav.TButton", background=[("active", PANEL)], foreground=[("active", TEXT)])
        style.configure("NavOn.TButton", background=PANEL, foreground=TEXT, anchor="w", padding=(self.px(0.12), self.px(0.08)), borderwidth=0)
        style.map("NavOn.TButton", background=[("active", PANEL)])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=self.px(0.26), borderwidth=0)
        style.map("Treeview", background=[("selected", SELECT)], foreground=[("selected", TEXT)])
        style.configure("Treeview.Heading", background=PANEL2, foreground=MUTED, relief="flat", font=(UI_FONT, 9, "bold"))
        style.map("Treeview.Heading", background=[("active", HOVER)])
        style.configure("Vertical.TScrollbar", background=PANEL2, troughcolor=BG, arrowcolor=MUTED, borderwidth=0,
                        bordercolor=BG, lightcolor=PANEL2, darkcolor=PANEL2, gripcount=0)
        style.map("Vertical.TScrollbar", background=[("active", HOVER), ("disabled", BG)],
                  lightcolor=[("active", HOVER)], darkcolor=[("active", HOVER)], arrowcolor=[("disabled", BG)])

    def _scroll_area(self, parent):
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        bar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        body = tk.Frame(canvas, bg=BG)
        window = canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
        canvas.bind("<Enter>", lambda e: self.bind_all("<MouseWheel>", lambda ev: canvas.yview_scroll(int(-ev.delta / 120), "units")))
        canvas.bind("<Leave>", lambda e: self.unbind_all("<MouseWheel>"))
        return body

    def _card(self, parent, title, rows, row, column, columnspan=1):
        card = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        card.grid(row=row, column=column, columnspan=columnspan, sticky="nsew", padx=6, pady=6)
        tk.Label(card, text=title, bg=PANEL, fg=TEXT, font=(UI_FONT, 11, "bold"), anchor="w").pack(fill="x", padx=14, pady=(10, 6))
        grid = tk.Frame(card, bg=PANEL)
        grid.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        grid.columnconfigure(1, weight=1)
        for i, (key, label, mono) in enumerate(rows):
            tk.Label(grid, text=label, bg=PANEL, fg=MUTED, font=(UI_FONT, 9), anchor="nw").grid(row=i, column=0, sticky="nw", padx=(0, 12), pady=2)
            value = tk.Label(grid, text="…", bg=PANEL, fg=TEXT, font=(MONO_FONT, 10) if mono else (UI_FONT, 10), anchor="w", justify="left")
            value.grid(row=i, column=1, sticky="w", pady=2)
            self.rows[key] = value
        grid.bind("<Configure>", lambda e, g=grid: [w.configure(wraplength=max(120, e.width - self.px(1.1))) for w in g.grid_slaves(column=1)])
        return card

    # -------- 页面：总览
    def _build_overview(self, page):
        actions = tk.Frame(page, bg=BG)
        actions.pack(side="bottom", fill="x", padx=16, pady=(4, 14))
        for c in range(4): actions.columnconfigure(c, weight=1, uniform="a")
        def button(text, command, column, style="TButton", action=True):
            w = ttk.Button(actions, text=text, command=command, style=style)
            w.grid(row=0, column=column, sticky="ew", padx=4)
            if action: self.action_buttons.append(w)
            return w
        self.btn_kill = button("开启断网保护", self.toggle_killswitch, 0)
        self.btn_realip = button("进入真实 IP 模式", self.realip_wizard, 1)
        self.btn_release = button("解除锁定", self.release_lockdown, 2, "Danger.TButton")
        self.btn_refresh = button("刷新检测", self.refresh, 3, "Accent.TButton", action=False)

        body = self._scroll_area(page)
        holder = tk.Frame(body, bg=BG)
        holder.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        holder.columnconfigure(0, weight=1, uniform="c")
        holder.columnconfigure(1, weight=1, uniform="c")
        self._card(holder, "出口 IP", [("egress", "普通流量", True), ("egress_claude", "claude.ai", True), ("whitelist", "白名单", True)], 0, 0)
        self._card(holder, "自动防护", [("ag_state", "状态", False), ("ag_check", "最近检查", True), ("ag_reason", "异常 / 原因", False), ("ag_count", "累计触发", False)], 0, 1)
        self._card(holder, "ClaudeGuard", [("guard_daemon", "守护进程", False), ("guard_state", "出口判定", False), ("guard_net", "网络助手", False),
                                           ("guard_path", "桌面版路径", False), ("health", "健康检查", False)], 1, 0)
        self._card(holder, "FlClash", [("fl_proc", "进程", False), ("fl_tun", "TUN 网卡", False), ("fl_mode", "代理模式", False), ("fl_strict", "严格路由", False)], 1, 1)
        self._card(holder, "断网保护（NetGuard）", [("ng_state", "规则", False), ("ng_claude", "Claude 隔离", False), ("ng_mode", "真实 IP 模式", False),
                                               ("ng_log", "最近操作", False), ("fl_source", "FlClash 配置", False)], 2, 0, columnspan=2)

    # -------- 页面：保护记录
    def _build_records(self, page):
        head = tk.Frame(page, bg=BG)
        head.pack(fill="x", padx=16, pady=(0, 6))
        self.btn_filter = ttk.Button(head, text="显示全部记录", command=self.toggle_record_filter)
        self.btn_filter.pack(side="right", padx=(6, 0))
        ttk.Button(head, text="打开记录文件", command=lambda: os.startfile(NETGUARD / "events.jsonl") if (NETGUARD / "events.jsonl").exists() else None).pack(side="right")
        self.records_summary = tk.Label(head, text="", bg=BG, fg=MUTED, font=(UI_FONT, 10), anchor="w", justify="left")
        self.records_summary.pack(side="left", fill="x", expand=True)
        head.bind("<Configure>", lambda e: self.records_summary.configure(wraplength=max(150, e.width - self.px(3.4))))

        detail = tk.Text(page, height=8, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief="flat", font=(UI_FONT, 10),
                         wrap="word", padx=12, pady=8, highlightthickness=1, highlightbackground=BORDER)
        detail.pack(side="bottom", fill="x", padx=16, pady=(6, 14))
        detail.insert("1.0", "选中一条记录查看详情。")
        detail.configure(state="disabled")
        self.record_detail = detail

        frame = tk.Frame(page, bg=BG)
        frame.pack(fill="both", expand=True, padx=16)
        tree = ttk.Treeview(frame, columns=("time", "source", "level", "type", "summary"), show="headings", selectmode="browse")
        for col, title, width, stretch in (("time", "时间", 1.5, False), ("source", "来源", 1.0, False), ("level", "危险", 0.55, False),
                                           ("type", "类型", 1.0, False), ("summary", "内容", 4.5, True)):
            tree.heading(col, text=title, anchor="w")
            tree.column(col, width=self.px(width), stretch=stretch, anchor="w")
        for level, color in SEVERITY_COLOR.items():
            tree.tag_configure("sev" + level, foreground=color)
        tree.tag_configure("sev—", foreground=TEXT)
        bar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        tree.bind("<<TreeviewSelect>>", self.show_record_detail)
        self.records_tree = tree

    def toggle_record_filter(self):
        self.record_filter = "all" if self.record_filter == "key" else "key"
        self.btn_filter.config(text="只看关键记录" if self.record_filter == "all" else "显示全部记录")
        self.update_records(self.event_list)

    def update_records(self, events):
        self.event_list = events or []
        actions = [e for e in self.event_list if e.get("type") in KEY_EVENTS]
        kills = [e for e in self.event_list if e.get("type") in ("kill", "trigger")]
        high = [e for e in actions if event_severity(e) == "高"]
        last = time.strftime("%m-%d %H:%M:%S", time.localtime(float(kills[-1]["ts"]))) if kills else "从未"
        self.records_summary.config(text=f"保护动作 {len(actions)} 次（高危 {len(high)}）· 结束 / 锁定 Claude {len(kills)} 次，最近：{last}"
                                         + ("（只显示保护动作）" if self.record_filter == "key" else "（显示全部记录）"))
        tree = self.records_tree
        tree.delete(*tree.get_children())
        shown = [e for e in reversed(self.event_list) if self.record_filter == "all" or e.get("type") in KEY_EVENTS]
        for i, e in enumerate(shown[:500]):
            label = EVENT_TYPES.get(e.get("type"), (e.get("type", "?"), INFO))[0]
            level = event_severity(e)
            tree.insert("", "end", iid=str(i), values=(time.strftime("%m-%d %H:%M:%S", time.localtime(float(e.get("ts", 0)))), e.get("source", "?"),
                                                       level, label, e.get("summary", "")), tags=("sev" + level,))
        self._shown_events = shown
        if not shown:
            tree.insert("", "end", values=("", "", "", "", "暂无记录。任何一次切断网络、结束 Claude、锁定 / 解除都会记录在这里。"))

    def show_record_detail(self, _event=None):
        sel = self.records_tree.selection()
        if not sel or not getattr(self, "_shown_events", None): return
        try: e = self._shown_events[int(sel[0])]
        except (ValueError, IndexError): return
        lines = [f"时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(e.get('ts', 0))))}    来源：{e.get('source', '?')}    "
                 f"危险程度：{event_severity(e)}",
                 f"类型：{EVENT_TYPES.get(e.get('type'), (e.get('type'),))[0]}", f"内容：{e.get('summary', '')}"]
        reasons = reason_lines(e)
        lines += (["原因："] + ["  " + r for r in reasons]) if reasons else ["原因：—（恢复 / 设置类记录）"]
        detail = e.get("detail")
        if isinstance(detail, dict):
            if "killed" in detail:
                extra = f"；WFP 隔离：{'成功' if detail.get('isolated') else '失败'}" if "isolated" in detail else ""
                lines.append(f"结束 Claude 进程：{detail.get('killed')} 个{extra}")
            if detail.get("error"): lines.append(f"错误：{detail['error']}")
            if detail.get("errors"): lines.append("未能结束：" + "；".join(map(str, detail["errors"])))
        self.record_detail.configure(state="normal")
        self.record_detail.delete("1.0", "end")
        self.record_detail.insert("1.0", "\n".join(lines))
        self.record_detail.configure(state="disabled")

    # -------- 页面：维护
    def _build_maintenance(self, page):
        body = self._scroll_area(page)
        holder = tk.Frame(body, bg=BG)
        holder.pack(fill="both", expand=True, padx=16, pady=(0, 14))
        holder.columnconfigure(0, weight=1)
        items = [
            ("install", "更新 / 重新安装管理脚本", "安装新版后台（需 UAC）。保留现有保护；锁定期间只补缺失的隔离规则，仍须手动解锁。", self.install),
            ("guard", "自动防护开关", "关闭后不再自动隔离 Claude；断网保护规则和已有锁定不受影响（需 UAC）。", self.toggle_guard),
            ("fix", "修复 ClaudeGuard", "Claude 更新后路径过期时使用：更新路径并重装网络助手（需 UAC，期间有泄露风险，先关联网程序）。", self.fix_guard),
            ("flclash", "打开 FlClash", "切换节点、模式，或查看代理状态。", lambda: os.startfile(FLCLASH_EXE)),
            ("guardui", "ClaudeGuard 设置", "打开 ClaudeGuard 自带的设置界面。", lambda: os.startfile(GUARD_LNK)),
            ("diag", "复制诊断摘要", "复制当前状态摘要（不含节点、订阅、代理地址），用于排障或交给 Codex。", self.copy_diagnostics),
            ("logs", "打开日志目录", "C:\\ProgramData\\NetGuard：状态、日志、保护记录。", self.open_logs),
            ("uninstall", "卸载 NetGuard", "移除断网保护和自动防护（需 UAC）。卸载后代理断开时可能经真实 IP 联网。", self.uninstall),
        ]
        self.maint_buttons = {}
        for i, (key, title, desc, command) in enumerate(items):
            card = tk.Frame(holder, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
            card.grid(row=i, column=0, sticky="ew", pady=5)
            card.columnconfigure(0, weight=1)
            tk.Label(card, text=title, bg=PANEL, fg=TEXT, font=(UI_FONT, 11, "bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=14, pady=(10, 0))
            d = tk.Label(card, text=desc, bg=PANEL, fg=MUTED, font=(UI_FONT, 9), anchor="w", justify="left")
            d.grid(row=1, column=0, sticky="w", padx=14, pady=(2, 10))
            card.bind("<Configure>", lambda e, lbl=d: lbl.configure(wraplength=max(150, e.width - self.px(2.4))))
            style = "Danger.TButton" if key == "uninstall" else ("Accent.TButton" if key == "install" else "TButton")
            b = ttk.Button(card, text={"install": "更新", "guard": "关闭自动防护", "uninstall": "卸载"}.get(key, "打开" if key in ("flclash", "guardui", "logs") else "执行"),
                           command=command, style=style)
            b.grid(row=0, column=1, rowspan=2, padx=14, pady=10, sticky="e")
            if key not in ("flclash", "guardui", "diag", "logs"): self.action_buttons.append(b)
            self.maint_buttons[key] = b
        self.btn_install = self.maint_buttons["install"]

    def show_page(self, key):
        for name, frame in self.pages.items():
            frame.pack_forget()
            self.nav[name].configure(style="NavOn.TButton" if name == key else "Nav.TButton")
        self.pages[key].pack(fill="both", expand=True)
        self.current_page = key

    # -------- 刷新
    def auto_refresh(self):
        if not self.busy: self.refresh()
        self.after(15000, self.auto_refresh)

    def drain_events(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "snapshot":
                    try: self.show(value)
                    except Exception:
                        self.collection_failed("界面状态解析失败")
                elif kind == "error": self.collection_failed(value)
                elif kind == "operation": self._elevated_done(*value)
                elif kind == "callback": value()
        except queue.Empty:
            pass
        except Exception as exc:
            self.busy = False
            self.collection_failed("界面回调失败：" + type(exc).__name__)
        self.after(80, self.drain_events)

    def collection_failed(self, reason):
        self._refreshing = False
        self.verdict.config(text="⚠ 检测失败，现有显示不可作为当前防护证据", foreground=BAD)
        self.banner_bar.config(bg=BAD)
        self.updated.config(text=f"{reason}；可点刷新重试。防护规则未改动。")
        self.btn_refresh.config(state="normal")
        self.sync_buttons()

    def refresh(self):
        if self._refreshing or self.busy: return
        self._refreshing = True
        self.updated.config(text="检测中…（不更改网络设置）")
        self.btn_refresh.config(state="disabled")
        def work():
            try: self.events.put(("snapshot", collect()))
            except Exception as exc: self.events.put(("error", "采集失败：" + type(exc).__name__))
        threading.Thread(target=work, daemon=True).start()

    def sync_buttons(self):
        for button in self.action_buttons:
            button.config(state="disabled" if self.busy else "normal")
        st = self.state_data.get("ng_status") or {}
        if not self.state_data.get("ng_installed") or not fresh_status(st) or st.get("error"):
            self.btn_kill.config(state="disabled")
        if not ((st.get("guard") or {}).get("lockdown")) or self.busy:
            self.btn_release.config(state="disabled")

    def copy_diagnostics(self):
        # A field allowlist keeps credentials and raw logs off the clipboard.
        s = self.state_data
        st, guard = s.get("ng_status") or {}, s.get("guard") or {}
        g = st.get("guard") or {}
        lines = [f"NetGuard {VERSION}", self.verdict.cget("text"),
                 f"检测时间: {s.get('time', '未完成')}", f"普通出口: {s.get('egress')}",
                 f"claude.ai 域名出口: {s.get('egress_claude')}",
                 f"ClaudeGuard: {guard.get('state')} / daemon={guard.get('daemon_running')}",
                 f"NetGuard: active={st.get('active_killswitch')} filters={st.get('filter_count')} fresh={fresh_status(st)}",
                 f"自动防护: enabled={g.get('enabled')} lockdown={g.get('lockdown')} reasons={g.get('reasons')} triggers={g.get('triggers')}",
                 f"TUN: {s.get('tun_up')} / mode={s.get('flclash_mode')} / strict-route 配置={s.get('strict_route')} 界面设置={s.get('prefs_strict')}",
                 f"严格路由运行时: {strict_route_view(s)[0]}",
                 f"FlClash 配置: {config_source_text(s)}",
                 "范围: 域名出口探测，不等于 Claude 应用或断线防泄露的完整实测"]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.updated.config(text="已复制诊断摘要（不含节点、订阅或代理地址）")

    def set(self, key, text, color=None):
        self.rows[key].config(text=text, foreground=color or TEXT)

    def show(self, s):
        self._refreshing = False
        self.state_data = s
        wl, problems, warnings = s["whitelist"], [], []
        realip = s["realip"]
        e, ec = s["egress"], s["egress_claude"]
        self.set("egress", e or "无法联网", GOOD if e in wl else (WARN if realip and e else BAD))
        self.set("egress_claude", ec or "无法连接", GOOD if ec in wl else BAD)
        self.set("whitelist", ", ".join(wl) or "未设置", INFO)
        if not realip and e not in wl: problems.append("普通出口未通过白名单")
        if ec not in wl: problems.append("claude.ai 域名出口未通过白名单")
        g, net = s["guard"], s["guard"].get("network") or {}
        guard_ok = g.get("daemon_running") and s.get("guard_protection_enabled") and s.get("guard_network_enabled")
        self.set("guard_daemon", "运行中 / 保护开启" if guard_ok else "守护未运行或保护配置关闭", GOOD if guard_ok else BAD)
        self.set("guard_state", f"{g.get('state')}  {g.get('ip') or ''}", GOOD if g.get("state") == "allowed" else WARN)
        if not guard_ok: problems.append("ClaudeGuard 保护异常")
        if g.get("state") != "allowed" and not realip: problems.append("ClaudeGuard 未允许连接")
        net_ok = bool(net.get("ready")) and fresh_status(net, 30)
        self.set("guard_net", "就绪 / 状态新鲜" if net_ok else "未就绪或状态过期", GOOD if net_ok else BAD)
        if not net_ok: problems.append("网络助手未就绪或状态过期")
        exp, conf = s.get("claude_expected"), s.get("claude_configured")
        path_ok = bool(exp and conf and os.path.normcase(exp) == os.path.normcase(conf) and s.get("claude_path_exists") and s.get("cli_path_exists"))
        self.set("guard_path", "与已安装版本一致 / CLI 存在" if path_ok else "路径缺失、已过期或无法核实", GOOD if path_ok else BAD)
        if not path_ok: problems.append("Claude 程序路径待处理")
        ht = s["health_task"].split("|")
        health_ok = (len(ht) == 2 and ht[0] == "0" and s["health_last"].endswith(" OK")
                     and s.get("health_task_enabled")
                     and fresh_status({"updated_at": s.get("health_last_run")}, 1200)
                     and fresh_status({"updated_at": s.get("health_log_updated_at")}, 1200)
                     # 任务正在运行的几秒里，NextRunTime 仍是本次的开始时间（略早于现在），留 120 秒余量；
                     # 真正停摆仍会被“最近运行 / 日志新鲜”两项抓到
                     and -120 <= float(s.get("health_next_run", 0)) - time.time() <= 1200)
        self.set("health", (f"上次结果 {ht[0]}；下次 {ht[1]}" if len(ht) == 2 else "未注册 / 查询失败"), GOOD if health_ok else WARN)
        if not health_ok: warnings.append("健康检查待处理")
        fl_ok = s["flclash_ui"] and s["flclash_core"]
        self.set("fl_proc", f"界面 {'✓' if s['flclash_ui'] else '✗'} / 内核 {'✓' if s['flclash_core'] else '✗'}", GOOD if fl_ok else BAD)
        self.set("fl_tun", "已连接" if s["tun_up"] else "未连接", GOOD if s["tun_up"] else BAD)
        if not fl_ok or not s["tun_up"]: problems.append("FlClash / TUN 未就绪")
        mode = s["flclash_mode"]
        self.set("fl_mode", {"global": "全局", "rule": "规则", "direct": "直连"}.get(mode, "待核实"), GOOD if mode == "global" else WARN)
        strict_text, strict_color, strict_warning = strict_route_view(s)
        self.set("fl_strict", strict_text, strict_color)
        self.set("fl_source", config_source_text(s), INFO)
        if not realip and mode != "global": warnings.append("FlClash 不是全局模式")
        if strict_warning: warnings.append(strict_warning)
        st = s.get("ng_status") or {}
        fresh = fresh_status(st)
        active = bool(st.get("active_killswitch"))
        isolation = bool(st.get("active_claude_block"))
        lockdown = bool((st.get("guard") or {}).get("lockdown"))
        if not s["ng_installed"]:
            self.set("ng_state", "未安装", WARN)
            warnings.append("NetGuard 未安装")
        elif not fresh or st.get("error"):
            self.set("ng_state", "状态过期、读取失败或系统时间异常", BAD)
            problems.append("NetGuard 状态不可核实")
        else:
            verified = st.get("status_version", 0) >= 2 and st.get("integrity_ok") is True
            counts_ok = st.get("filter_count") == st.get("expected_filter_count") if verified else st.get("filter_count") == (14 if active and not isolation else -1)
            if not counts_ok or (st.get("wanted_killswitch") and st.get("killswitch_complete") is False) or st.get("integrity_ok") is False:
                if st.get("wanted_killswitch") and st.get("killswitch_complete") is False:
                    problems.append("基础断网保护规则不完整")
                elif st.get("wanted_claude_block") and st.get("claude_block_complete") is False:
                    problems.append("Claude 隔离规则待同步")
                else:
                    problems.append("WFP 规则与期望不一致")
            elif not verified:
                warnings.append("旧版状态缺少完整性核对，需更新管理脚本")
            if "base_filter_count" in st:
                self.set("ng_state", f"{'已开启' if active else '未开启'} / 基础 {st.get('base_filter_count')}/{st.get('expected_base_filter_count')} 条规则", GOOD if active and st.get("killswitch_complete") else BAD)
            else:
                self.set("ng_state", f"{'已开启' if active else '未开启'} / {st.get('filter_count', '?')} 条规则 / {'完整性已核对' if verified and counts_ok else '完整性待核实'}", GOOD if active and verified and counts_ok else WARN)
            if st.get("wanted_killswitch") != active or st.get("wanted_claude_block") != isolation:
                problems.append("NetGuard 实际规则与设定不一致")
        if not active: warnings.append("断网保护未开启")
        if fresh and st.get("wanted_claude_block") and "required_claude_filter_count" in st:
            covered, required = st.get("covered_claude_filter_count"), st.get("required_claude_filter_count")
            note = f"已隔离（{covered}/{required} 条，等待手动解除）" if isolation else f"隔离待同步（{covered}/{required} 条）"
            self.set("ng_claude", note, WARN if isolation else BAD)
        else:
            self.set("ng_claude", ("已隔离（自动防护锁定）" if lockdown else "已隔离") if isolation and fresh else ("待核实" if not fresh else "未隔离"), BAD if lockdown else (WARN if isolation else INFO))
        self.set("ng_mode", "进行中，请完成后退出" if realip else "未启用", WARN if realip else INFO)
        self.set("ng_log", s["ng_log"] or "无操作记录", INFO)
        if realip and (not fresh or not isolation or not active or st.get("claude_block_complete") is False):
            problems.append("真实 IP 模式隔离未核实，请勿切换代理")
        ag_rows, ag_problems, ag_warnings = guard_view(s)
        for key, (text, color) in ag_rows.items(): self.set(key, text, color)
        problems = ag_problems + problems
        warnings += ag_warnings
        if s.get("guard_patch_ok") is False:
            warnings.append("ClaudeGuard 本地补丁丢失（可能被重装覆盖），会恢复「一次检查失败就立即结束 Claude」的旧行为，见手册第 13 节")
        if s.get("ng_outdated"): warnings.append("管理脚本更新已准备，需本人完成 UAC 安装")
        if s.get("ui_source_changed"): warnings.append("工作台文件已更新，请重新打开工作台")
        if problems:
            verdict, color = "⚠ 需要处理：" + "；".join(dict.fromkeys(problems)), BAD
        elif warnings:
            verdict, color = "◐ 待核实：" + "；".join(dict.fromkeys(warnings)), WARN
        elif realip:
            verdict, color = "◐ 真实 IP 模式：Claude 程序已隔离", WARN
        else:
            verdict, color = "✔ 当前检查通过（未做断线测试）", GOOD
        self.verdict.config(text=verdict, foreground=color)
        self.btn_kill.config(text="关闭断网保护" if active else "开启断网保护")
        self.btn_realip.config(text="退出真实 IP 模式" if realip else "进入真实 IP 模式")
        self.btn_install.config(text="更新（有新版本）" if s.get("ng_outdated") else "更新")
        gd = st.get("guard") or {}
        if hasattr(self, "maint_buttons"):
            self.maint_buttons["guard"].config(text="关闭自动防护" if gd.get("enabled", True) else "开启自动防护")
        self.updated.config(text=f"NetGuard {VERSION} · 更新于 {s['time']} · 耗时 {s.get('duration', 0)} 秒")
        if hasattr(self, "banner_bar"):
            self.banner_bar.config(bg=color)
            self.banner_ip.config(text=e or "无法联网", fg=GOOD if e in wl else (WARN if realip and e else BAD))
            self.nav["maintenance"].config(text="维护  •" if s.get("ng_outdated") else "维护")
            self.nav["records"].config(text="保护记录  •" if lockdown else "保护记录")
            self.side_status.config(text=f"v{VERSION}\n刷新于 {s['time']}")
            self.update_records(s.get("events") or [])
        if hasattr(self, "btn_refresh"): self.btn_refresh.config(state="normal")
        self.sync_buttons()

    # -------- 操作
    def elevated(self, action, done=None):
        if self.busy: return
        self.busy = True
        self.sync_buttons()
        def work():
            try: code = netguard(action)
            except Exception: code = -1
            self.events.put(("operation", (code, done)))
        threading.Thread(target=work, daemon=True).start()

    def _elevated_done(self, code, done):
        self.busy = False
        self.sync_buttons()
        if code is None:
            messagebox.showinfo("NetGuard", "已取消（UAC 未授权）。")
        elif code != 0:
            messagebox.showerror("NetGuard", last_netguard_log())
        if done:
            done(code)
        self.refresh()

    def toggle_killswitch(self):
        if self.busy: return
        st = self.state_data.get("ng_status") or {}
        if not fresh_status(st) or st.get("error"):
            messagebox.showwarning("状态待核实", "无法确认实际保护状态，请先刷新或检查状态核对任务。")
            return
        if st.get("active_killswitch"):
            if not messagebox.askyesno("关闭断网保护", "关闭会同时解除 Claude 隔离和自动防护锁定。代理断开时新连接可能经真实 IP 发出。\n请先关闭浏览器、Claude 等联网程序。\n\n"
                                       "只想临时用真实 IP 办事，请改用「真实 IP 模式」，那样更安全。\n\n仍要关闭吗？", icon="warning"):
                return
            self.elevated("disable")
        else:
            if not messagebox.askyesno("开启断网保护", "开启后：只有经 FlClash 代理的流量能上网；FlClash 没开或断开时整机断网"
                                       "（局域网、本机仍可用）。\n\n脚本会先检查代理正常，开启后自检，失败自动回滚。\n需要在 UAC 窗口点「是」。继续？"):
                return
            self.elevated("enable")

    def release_lockdown(self):
        if self.busy: return
        g = (self.state_data.get("ng_status") or {}).get("guard") or {}
        if not g.get("lockdown"): return
        if not messagebox.askyesno("解除锁定", "触发原因：" + ("；".join(g.get("reasons") or []) or "未知") +
                                   "\n\n解除前后台会重新做一遍全部检查，仍有异常则保持锁定。\n建议先在「保护记录」看清原因、处理好之后再解除。\n需要在 UAC 窗口点「是」。继续？"):
            return
        def done(code):
            if code == 0:
                messagebox.showinfo("已解除", "检查全部通过，锁定已解除。现在可以重新打开 Claude。")
        self.elevated("release", done)

    def toggle_guard(self):
        if self.busy: return
        g = (self.state_data.get("ng_status") or {}).get("guard") or {}
        if g.get("enabled", True):
            if not messagebox.askyesno("关闭自动防护", "关闭后，出口异常、代理断开时不会再自动隔离 Claude。\n断网保护规则和 ClaudeGuard 不受影响。\n需要 UAC。继续？", icon="warning"):
                return
            self.elevated("guard-off")
        else:
            self.elevated("guard-on")

    def fix_guard(self):
        if self.busy: return
        if messagebox.askyesno("修复 ClaudeGuard 前请确认", "此操作会重装网络助手。切换期间可能有真实 IP 泄露风险。\n\n请先关闭浏览器、Claude 等联网程序；确认已关闭后继续，并由你本人确认 UAC。", icon="warning"):
            os.startfile(GUARD / "monitor" / "fix.cmd")

    def open_logs(self):
        os.startfile(NETGUARD if NETGUARD.exists() else HERE)

    def install(self):
        if self.busy: return
        if not messagebox.askyesno("更新管理脚本", "更新管理脚本与后台任务，保留现有保护，不重启 FlClash。\n锁定期间，新后台只补缺失的 Claude 隔离规则；不会自动解锁。\n安装前自动备份。需要你本人在 UAC 点「是」。继续？"):
            return
        self.run_install([])

    def uninstall(self):
        if self.busy: return
        if not messagebox.askyesno("卸载会移除保护", "会关闭断网保护和自动防护、解除 Claude 隔离并移除规则。\n代理断开后，新连接可能通过真实 IP 发出。\n请先关闭浏览器、Claude 等联网程序，确认后再卸载。", icon="warning"):
            return
        self.run_install(["-Uninstall"])

    def run_install(self, extra):
        self.busy = True
        self.sync_buttons()
        args = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(HERE / "install.ps1")] + extra
        def work():
            try: code = run_elevated(args)
            except Exception: code = -1
            self.events.put(("operation", (code, None)))
        threading.Thread(target=work, daemon=True).start()

    def realip_wizard(self):
        if self.busy: return
        RealIpWizard(self, leaving=bool(self.state_data.get("realip")))


class RealIpWizard(tk.Toplevel):
    ENTER = [
        ("1. 关掉浏览器里的 claude.ai 标签页", "工作台管不到浏览器里的网页。Claude 的域名会继续走代理，但网页里引用的第三方资源可能直连，最好先关掉。"),
        ("2. 隔离 Claude 程序（需 UAC）", "关闭 Claude 桌面版和 CLI，并用 WFP 强制禁止它们联网。注意：这会结束当前所有 Claude 会话。"),
        ("3. 在 FlClash 里切换", "模式改成「规则」，代理组「其他网域」选 DIRECT。\nClaude/Anthropic 域名仍走「线路选择」（美国节点），其它网站用真实 IP。\n不要关 TUN，也不要退出 FlClash，断网保护保持开启。"),
        ("4. 验证", "确认：普通出口 = 真实 IP；Claude 看到的出口仍在白名单。"),
    ]
    LEAVE = [
        ("1. 在 FlClash 里切回", "模式改回「全局」（或把「其他网域」改回 线路选择）。"),
        ("2. 验证并解除 Claude 隔离（需 UAC）", "两个出口都回到白名单后才会解除；否则保持隔离。"),
        ("3. 重新打开 Claude", "解除后再启动 Claude 桌面版 / CLI。"),
    ]

    def __init__(self, app, leaving):
        super().__init__(app)
        self.configure(bg=BG)
        self.app = app
        self.leaving = leaving
        self.title("退出真实 IP 模式" if leaving else "进入真实 IP 模式")
        self.transient(app)
        wrap = int(app.winfo_fpixels("6i"))  # 按 DPI 换算，避免高缩放下文字被挤
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)
        scroll_area = ttk.Frame(outer)
        canvas = tk.Canvas(scroll_area, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(scroll_area, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        frame = ttk.Frame(canvas, padding=(2, 2))
        body_window = canvas.create_window((0, 0), window=frame, anchor="nw")
        frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(body_window, width=event.width))
        self.bind("<MouseWheel>", lambda event: canvas.yview_scroll(int(-event.delta/120), "units"))
        ttk.Label(frame, text=self.title(), style="Big.TLabel").pack(anchor="w")
        intro = ("先切回代理，再验证；验证通过前保留 Claude 隔离。" if leaving else
                 "临时用真实 IP 办事，同时隔离 Claude 程序。网页第三方资源仍有直连风险，请先关闭 Claude 网页。")
        ttk.Label(frame, text=intro, wraplength=wrap, foreground=INFO).pack(anchor="w", pady=(4, 10))
        for title, desc in (self.LEAVE if leaving else self.ENTER):
            ttk.Label(frame, text=title, font=(UI_FONT, 11, "bold")).pack(anchor="w", pady=(6, 0))
            ttk.Label(frame, text=desc, wraplength=wrap).pack(anchor="w")
        bar = ttk.Frame(outer)
        bar.pack(side="bottom", fill="x")
        for column in range(2): bar.columnconfigure(column, weight=1)
        if leaving:
            buttons = [("打开 FlClash", lambda: os.startfile(FLCLASH_EXE)), ("验证并解除隔离", self.leave)]
        else:
            buttons = [("隔离 Claude（第 2 步）", self.isolate), ("打开 FlClash（第 3 步）", lambda: os.startfile(FLCLASH_EXE)), ("验证（第 4 步）", self.verify)]
        buttons.append(("关闭", self.destroy))
        for i, (label, command) in enumerate(buttons):
            ttk.Button(bar, text=label, command=command).grid(row=i//2, column=i%2, sticky="ew", padx=3, pady=4)
        self.result = ttk.Label(outer, text="", wraplength=wrap)
        self.result.pack(side="bottom", fill="x", pady=8)
        scroll_area.pack(fill="both", expand=True)
        self.update_idletasks()
        width = min(int(app.winfo_fpixels("7i")), self.winfo_screenwidth()-50)
        height = min(frame.winfo_reqheight()+bar.winfo_reqheight()+80, self.winfo_screenheight()-100)
        self.geometry(f"{width}x{height}")
        self.minsize(min(width, int(app.winfo_fpixels("5i"))), min(height, int(app.winfo_fpixels("3i"))))

    def say(self, text, color=None):
        if self.winfo_exists(): self.result.config(text=text, foreground=color or "")

    def isolate(self):
        if self.app.busy: return
        st = read_json(NETGUARD / "status.json") or {}
        if not (fresh_status(st) and st.get("status_version", 0) >= 2 and st.get("active_killswitch") and st.get("integrity_ok") and getattr(self.app, "state_data", {}).get("isolation_targets_ok") and isolation_targets_covered()):
            self.say("✗ 请先确认断网保护与两项 Claude 程序清单完整；必要时更新管理脚本或修复 ClaudeGuard。请勿切换代理。", BAD)
            return
        if not messagebox.askyesno("隔离 Claude", "将结束所有 Claude 桌面版 / CLI 进程（包括正在进行的会话），并强制禁止它们联网。继续？",
                                   icon="warning", parent=self):
            return
        # 标记先写：即使 UAC 被拒，也不会误报“已恢复正常”
        REALIP_FLAG.write_text(json.dumps({"since": time.time()}), encoding="utf-8")
        self.say("正在请求 UAC…")

        def done(code):
            st = read_json(NETGUARD / "status.json") or {}
            confirmed = (fresh_status(st) and not st.get("error") and st.get("status_version", 0) >= 2
                         and st.get("active_killswitch") and st.get("active_claude_block")
                         and st.get("integrity_ok") and st.get("claude_block_complete") and isolation_targets_covered())
            if code == 0 and confirmed:
                cfg = read_json(GUARD_CONFIG) or {}
                targets = []
                for key in ("desktop_path", "cli_path"):
                    if cfg.get(key):
                        targets.append(os.path.normcase(cfg[key]))
                for p in psutil.process_iter(["exe"]):
                    exe = p.info.get("exe")
                    if exe and os.path.normcase(exe) in targets:
                        try:
                            p.kill()
                        except Exception:
                            pass

                self.say("✔ Claude 已隔离。现在做第 3 步：在 FlClash 里切换，然后点「验证」。", GOOD)
            else:
                self.say("✗ 隔离未完成，请勿切换 FlClash。可重试第 2 步。", BAD)
        self.app.elevated("claude-block", done)

    def verify(self):
        self.say("检测中…")

        def work():
            wl = (read_json(GUARD_CONFIG) or {}).get("allowed_ips") or []
            e, ec = trace_ip(CHECK_URL), trace_ip(CLAUDE_URL)
            st = read_json(NETGUARD / "status.json") or {}
            if not fresh_status(st) or st.get("error") or not st.get("active_killswitch") or st.get("claude_block_complete") is not True:
                msg, color = "✗ 隔离或断网保护尚未完成完整性核验，请保持现有代理设置。", BAD
            elif not st.get("active_claude_block"):
                msg, color = "✗ Claude 尚未隔离（先完成第 2 步）。", BAD
            elif ec not in wl:
                msg, color = f"✗ 危险：Claude 域名出口是 {ec}，不在白名单！请检查 FlClash 规则，保持 Claude 隔离。", BAD
            elif e in wl:
                msg, color = f"◐ 普通出口仍是代理 IP {e}，FlClash 还没切换（第 3 步）。", WARN
            elif not e:
                msg, color = "✗ 普通流量无法联网，检查 FlClash 设置。", BAD
            else:
                msg, color = f"✔ 隔离与域名出口检查通过。普通出口 {e} 与白名单不同，是否为真实宽带 IP 尚未独立核实；claude.ai 域名出口 {ec}（白名单）。办完事记得退出此模式。", GOOD
            self.app.events.put(("callback", lambda: self.say(msg, color) if self.winfo_exists() else None))
        threading.Thread(target=work, daemon=True).start()

    def leave(self):
        if self.app.busy: return
        self.say("正在验证出口并请求 UAC…")

        def done(code):
            if code == 0:
                REALIP_FLAG.unlink(missing_ok=True)
                self.say("✔ 已退出真实 IP 模式，Claude 隔离已解除，可以重新打开 Claude。", GOOD)
            else:
                self.say("✗ 未解除：出口还没回到白名单，或 UAC 被取消。先在 FlClash 切回「全局」。", BAD)
        self.app.elevated("claude-unblock", done)


def already_running():
    """只允许一个工作台：已开着时把旧窗口提到最前并退出（开机自启 + 手动双击不会出现两个）。"""
    kernel32, user32 = ctypes.windll.kernel32, ctypes.windll.user32
    kernel32.CreateMutexW.restype = wt.HANDLE
    already_running.mutex = kernel32.CreateMutexW(None, False, "Local\\NetGuardWorkbench")
    if kernel32.GetLastError() != 183:  # ERROR_ALREADY_EXISTS
        return False
    hwnd = user32.FindWindowW(None, "NetGuard 工作台")
    if hwnd:
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        user32.SetForegroundWindow(hwnd)
    return True


if __name__ == "__main__":
    if not already_running():
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        Workbench().mainloop()
