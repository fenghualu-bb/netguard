"""Automatic updates of NetGuard itself and of the verified ClaudeGuard version (root).

Run by the com.netguard.updater LaunchDaemon every 6 hours (`netguard-updater run`).

NetGuard: only a commit that is the head of the configured branch of the configured GitHub
repository, has been that head for `soak_hours`, and passed both CI jobs on that exact SHA
is installed. It is downloaded by SHA into a root-only directory, installed with its own
install.sh, then checked (new version running, rules complete, services up). Any failure
restores the previous files from the installer's backup and marks the commit bad.

ClaudeGuard: the installed NetGuard carries upstream/claudeguard.json, the version the
upstream workflow verified. A "pkg" pin (mirrored with its SHA-256 into NetGuard's own
GitHub release, so an upstream history rewrite cannot remove it) is installed with
`installer` and checked; a "source" pin means the existing source install is kept as is.
"""
import fcntl
import hashlib
import json
import os
import shutil
import sys
import tarfile
import time

from . import notify, paths, util

POLICY = paths.p("update-policy.json")
STATE = paths.p("update-state.json")
WORK = paths.p("updates")
PIN = os.path.join(paths.ROOT, "lib", "upstream", "claudeguard.json")
LAST_BACKUP = paths.p("last-backup")
API = "https://api.github.com/"
DEFAULT_POLICY = {"enabled": True, "repo": "fenghualu-bb/netguard", "branch": "main", "soak_hours": 24,
                  "workflow": "macOS NetGuard",
                  "jobs": ["Offline tests (system Python 3.9)", "Real pf integration (disposable VM)"],
                  "claudeguard": True}
RELEVANT = ("macos/", ".github/workflows/")
HEALTH_SECONDS = 150


class UpdateError(RuntimeError):
    pass


# ---------------------------------------------------------------------------- io
def load_policy():
    data = util.read_json(POLICY, None)
    policy = dict(DEFAULT_POLICY)
    if isinstance(data, dict):
        policy.update({k: v for k, v in data.items() if k in DEFAULT_POLICY})
    return policy


def load_state():
    data = util.read_json(STATE, None)
    state = {"installed": None, "first_seen": {}, "bad": [], "last_check": 0, "last": None,
             "claudeguard_installed": None, "history": []}
    if isinstance(data, dict):
        state.update(data)
    return state


def save_state(state):
    state["history"] = (state.get("history") or [])[-20:]
    util.write_json(STATE, state, mode=0o644)


def run(args, timeout=60, env=None, cwd="/"):
    import subprocess
    base = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"}
    base.update(env or {})
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, env=base, cwd=cwd)


def github(path, fetch=None):
    """GET from the GitHub API with the system curl (system trust store)."""
    if fetch:
        return fetch(path)
    result = run([paths.CURL, "-q", "-fsS", "--max-time", "25", "-H", "Accept: application/vnd.github+json",
                  "-H", "User-Agent: netguard-updater", API + path], timeout=40)
    if result.returncode != 0:
        raise UpdateError("GitHub API 请求失败：%s" % (result.stderr.strip()[:200] or result.returncode))
    return json.loads(result.stdout)


def download(url, target, timeout=900):
    result = run([paths.CURL, "-q", "-fsSL", "--max-time", str(timeout), "-H", "User-Agent: netguard-updater",
                  "-o", target, url], timeout=timeout + 30)
    if result.returncode != 0:
        raise UpdateError("下载失败：%s" % (result.stderr.strip()[:200] or url))


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def tell(title, message):
    try:
        from .probes import Probes
        from . import config
        notify.send(Probes(config.load()), title, message, key="update-" + title, every=60)
    except Exception:
        pass


# ---------------------------------------------------------------------------- decisions
def ci_passed(policy, sha, fetch=None):
    runs = github("repos/%s/actions/runs?head_sha=%s&event=push&per_page=30" % (policy["repo"], sha), fetch)
    for item in runs.get("workflow_runs", []):
        if item.get("head_sha") != sha or item.get("name") != policy["workflow"] or \
                item.get("head_branch") != policy["branch"] or item.get("status") != "completed" or \
                item.get("conclusion") != "success":
            continue
        jobs = github("repos/%s/actions/runs/%s/jobs?per_page=100" % (policy["repo"], item["id"]), fetch)
        good = {j.get("name") for j in jobs.get("jobs", []) if j.get("conclusion") == "success"}
        if set(policy["jobs"]) <= good:
            return item.get("html_url")
    return None


def touches_macos(policy, base, sha, fetch=None):
    if not base:
        return True
    data = github("repos/%s/compare/%s...%s" % (policy["repo"], base, sha), fetch)
    return any(f.get("filename", "").startswith(RELEVANT) for f in data.get("files", [])) or \
        len(data.get("files", [])) >= 300  # the compare API truncates: assume relevant


def installed_commit(state, fetch=None, policy=None):
    if state.get("installed"):
        return state["installed"]
    source = util.read_json(paths.SOURCE, {}) or {}
    commit = str(source.get("commit") or "")
    if len(commit) == 40:
        return commit
    if commit and policy:
        try:
            return github("repos/%s/commits/%s" % (policy["repo"], commit), fetch)["sha"]
        except (UpdateError, KeyError, ValueError):
            return None
    return None


def decide(policy, state, now, fetch=None, force=False):
    """What to do about NetGuard: ("current"|"skip"|"wait"|"record"|"install", sha, note)."""
    head = github("repos/%s/commits/%s" % (policy["repo"], policy["branch"]), fetch)["sha"]
    installed = installed_commit(state, fetch, policy)
    if head == installed:
        return "current", head, "已是最新"
    if head in state.get("bad", []):
        return "skip", head, "这个版本上次安装后自检失败，已回滚，等待更新的版本"
    seen = state.setdefault("first_seen", {})
    seen.setdefault(head, now)
    state["first_seen"] = {k: v for k, v in seen.items() if k == head or now - v < 30 * 86400}
    if not touches_macos(policy, installed, head, fetch):
        return "record", head, "新提交没有改动 macOS 部分"
    waited = now - seen[head]
    if not force and waited < policy["soak_hours"] * 3600:
        return "wait", head, "新版本在 main 上满 %d 小时后安装（还剩约 %.1f 小时）" % (
            policy["soak_hours"], (policy["soak_hours"] * 3600 - waited) / 3600)
    if not ci_passed(policy, head, fetch):
        return "wait", head, "新版本的 CI 尚未全部通过"
    if console_uid() is None:
        return "wait", head, "没有用户登录，等登录后再安装（安装需要为桌面用户编译界面）"
    return "install", head, "CI 已通过"


def console_uid():
    try:
        uid = os.stat("/dev/console").st_uid
    except OSError:
        return None
    return uid or None


# ---------------------------------------------------------------------------- install / rollback
def daemon_ok(label):
    return run([paths.LAUNCHCTL, "print", "system/" + label], timeout=15).returncode == 0


def healthy(expected_version, since, read_status=None, sleep=time.sleep, deadline=HEALTH_SECONDS):
    read_status = read_status or (lambda: util.read_json(paths.STATUS, {}) or {})
    end = time.time() + deadline
    reason = "后台没有写出新状态"
    while time.time() < end:
        status = read_status()
        if status.get("updated_at", 0) >= since and status.get("version") == expected_version:
            if status.get("wanted_killswitch") and not status.get("killswitch_complete"):
                reason = "断网保护规则不完整"
            elif not daemon_ok("com.netguard.daemon") or not daemon_ok("com.netguard.control"):
                reason = "后台服务没有在运行"
            else:
                return True, "新版本 %s 正在运行，规则完整" % expected_version
        elif status.get("version") and status.get("version") != expected_version:
            reason = "运行的仍是 %s，不是 %s" % (status.get("version"), expected_version)
        sleep(5)
    return False, reason


def version_in(tree):
    text = open(os.path.join(tree, "macos", "netguard", "__init__.py"), encoding="utf-8").read()
    for line in text.splitlines():
        if line.startswith("VERSION"):
            return line.split("=", 1)[1].strip().strip("\"'")
    raise UpdateError("新版本里找不到版本号")


def fetch_tree(policy, sha):
    os.makedirs(WORK, mode=0o700, exist_ok=True)
    os.chmod(WORK, 0o700)
    stage = os.path.join(WORK, "stage-" + sha[:12])
    shutil.rmtree(stage, ignore_errors=True)
    archive = stage + ".tar.gz"
    download("https://codeload.github.com/%s/tar.gz/%s" % (policy["repo"], sha), archive, timeout=300)
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            name = os.path.normpath(member.name)
            if name.startswith(("/", "..")) or not (member.isfile() or member.isdir()):
                raise UpdateError("压缩包里有不安全的条目：%s" % member.name)
        tar.extractall(stage)
    os.unlink(archive)
    tops = os.listdir(stage)
    if len(tops) != 1 or not os.path.isfile(os.path.join(stage, tops[0], "macos", "install.sh")):
        raise UpdateError("下载的源码结构不对")
    return os.path.join(stage, tops[0])


def ensure_services():
    for label in ("com.netguard.daemon", "com.netguard.control"):
        plist = "/Library/LaunchDaemons/%s.plist" % label
        if not daemon_ok(label) and os.path.exists(plist):
            run([paths.LAUNCHCTL, "bootstrap", "system", plist], timeout=30)
        run([paths.LAUNCHCTL, "kickstart", "-k", "system/" + label], timeout=30)


def rollback(note, since=0):
    """Restore the backup this install made; never an older one (that would downgrade)."""
    backup = (open(LAST_BACKUP).read().strip() if os.path.exists(LAST_BACKUP) else "")
    fresh = bool(backup) and os.path.isdir(os.path.join(backup, "lib")) and os.path.getmtime(LAST_BACKUP) >= since
    if not fresh:
        ensure_services()  # the installer stopped before touching files; just bring services back
        return False, "安装在改动文件之前就停止了，原版本未受影响，后台已重新启动"
    for name in ("lib", "bin"):
        target = paths.p(name)
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(os.path.join(backup, name), target, symlinks=True)
    app = os.path.join(backup, "NetGuard.app")
    if os.path.isdir(app):
        run(["/bin/rm", "-rf", "/Applications/NetGuard.app"])
        run(["/usr/bin/ditto", app, "/Applications/NetGuard.app"], timeout=120)
    ensure_services()
    user = util.read_json(paths.SOURCE, {}) or {}
    try:
        import pwd
        uid = pwd.getpwnam(user.get("user", "")).pw_uid
        run([paths.LAUNCHCTL, "kickstart", "-k", "gui/%d/com.netguard.menu" % uid], timeout=30)
    except (KeyError, TypeError):
        pass
    return True, "已恢复到安装前的版本（%s）" % note


def install_netguard(policy, sha, state, now):
    tree = fetch_tree(policy, sha)
    expected = version_in(tree)
    log = os.path.join(WORK, "install-%s.log" % sha[:12])
    started = time.time()
    result = run(["/bin/bash", os.path.join(tree, "macos", "install.sh")], timeout=1800,
                 env={"NETGUARD_FROM_UPDATER": "1", "NETGUARD_UPDATE_REPO": "github:" + policy["repo"],
                      "NETGUARD_UPDATE_COMMIT": sha})
    with open(log, "w", encoding="utf-8") as stream:
        stream.write(result.stdout + "\n" + result.stderr)
    if result.returncode != 0:
        ok, how = rollback("安装脚本失败", started)
        return False, "安装脚本失败（日志 %s）；%s" % (log, how)
    ok, why = healthy(expected, started)
    if not ok:
        done, how = rollback(why, started)
        return False, "安装后自检未通过：%s；%s" % (why, how)
    shutil.rmtree(os.path.dirname(tree), ignore_errors=True)
    return True, why


def update_netguard(policy, state, now, force=False, fetch=None, installer=None):
    action, sha, note = decide(policy, state, now, fetch, force)
    result = {"action": action, "commit": sha, "note": note, "at": int(now)}
    if action == "record":
        state["installed"] = sha
    elif action == "install":
        ok, why = (installer or install_netguard)(policy, sha, state, now)
        result.update(ok=ok, note=why)
        if ok:
            state["installed"] = sha
            state.setdefault("history", []).append({"at": int(now), "commit": sha, "result": "installed"})
            tell("NetGuard 已自动更新", "已安装 %s：%s" % (sha[:7], why))
        else:
            state.setdefault("bad", []).append(sha)
            state["bad"] = state["bad"][-20:]
            state.setdefault("history", []).append({"at": int(now), "commit": sha, "result": "rolled_back"})
            tell("NetGuard 更新未成功，已回滚", why[:180])
    return result


# ---------------------------------------------------------------------------- ClaudeGuard
def claudeguard_running(read_state=None):
    from .probes import Probes
    from . import config
    info = (read_state or (lambda: Probes(config.load()).claudeguard()))()
    return bool(info.get("installed") and info.get("fresh") and info.get("helper_loaded"))


def follow_claudeguard(policy, state, now, pin_path=PIN, installer=None, running=claudeguard_running,
                       sleep=time.sleep):
    pin = util.read_json(pin_path, None)
    if not policy.get("claudeguard") or not isinstance(pin, dict):
        return {"action": "off", "note": "未启用"}
    version = str(pin.get("version"))
    if pin.get("kind") != "pkg":
        return {"action": "keep", "version": version, "note": "已验证版本是源码安装，保持现状"}
    if state.get("claudeguard_installed") == version:
        return {"action": "current", "version": version, "note": "已是已验证版本"}
    if version in (state.get("claudeguard_bad") or []):
        return {"action": "skip", "version": version, "note": "这个版本安装后没能正常运行，已停止重试"}
    target = os.path.join(WORK, "ClaudeGuard-%s.pkg" % version)
    os.makedirs(WORK, mode=0o700, exist_ok=True)
    try:
        if installer is None:
            download(pin["url"], target)
            if sha256(target) != pin["sha256"]:
                raise UpdateError("ClaudeGuard 安装包的哈希不符，拒绝安装")
            result = run(["/usr/sbin/installer", "-pkg", target, "-target", "/"], timeout=900)
            if result.returncode != 0:
                raise UpdateError("installer 失败：%s" % (result.stderr or result.stdout).strip()[-200:])
        else:
            installer(pin)
    except (UpdateError, KeyError, OSError) as exc:
        state.setdefault("claudeguard_bad", []).append(version)
        tell("ClaudeGuard 自动升级失败", str(exc)[:180])
        return {"action": "failed", "version": version, "note": str(exc)}
    finally:
        if os.path.exists(target):
            os.unlink(target)
    for _ in range(24):
        if running():
            state["claudeguard_installed"] = version
            tell("ClaudeGuard 已升级", "已升级到已验证版本 %s" % version)
            return {"action": "installed", "version": version, "note": "已升级并正在运行"}
        sleep(5)
    state.setdefault("claudeguard_bad", []).append(version)
    tell("ClaudeGuard 升级后没有正常运行", "版本 %s；NetGuard 会报告 ClaudeGuard 的状态" % version)
    return {"action": "failed", "version": version, "note": "升级后 2 分钟内没有正常运行"}


# ---------------------------------------------------------------------------- entry
def run_once(force=False):
    os.makedirs(WORK, mode=0o700, exist_ok=True)
    lock = open(os.path.join(WORK, ".lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return {"netguard": {"action": "busy", "note": "另一次更新正在进行"}}
    policy = load_policy()
    state = load_state()
    now = time.time()
    out = {}
    if not policy["enabled"] and not force:
        out["netguard"] = {"action": "off", "note": "自动更新已关闭"}
    else:
        try:
            out["netguard"] = update_netguard(policy, state, now, force=force)
        except Exception as exc:
            out["netguard"] = {"action": "error", "note": str(exc)[:300], "at": int(now)}
    if out["netguard"].get("action") in ("current", "wait", "record", "off", "skip") or out["netguard"].get("ok"):
        try:
            out["claudeguard"] = follow_claudeguard(policy, state, now)
        except Exception as exc:
            out["claudeguard"] = {"action": "error", "note": str(exc)[:300]}
    state["last_check"] = int(now)
    state["last"] = out
    save_state(state)
    util.log("自动更新：%s" % json.dumps(out, ensure_ascii=False)[:400], "update")
    return out


def set_enabled(enabled):
    policy = load_policy()
    policy["enabled"] = bool(enabled)
    util.write_json(POLICY, policy, mode=0o644)
    return policy


def summary():
    """For status.json and the workbench (readable without root)."""
    state = load_state()
    policy = load_policy()
    return {"enabled": policy["enabled"], "installed": state.get("installed"), "last_check": state.get("last_check"),
            "last": state.get("last"), "soak_hours": policy["soak_hours"],
            "claudeguard_installed": state.get("claudeguard_installed")}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[0] if argv else "run"
    if command == "status":
        print(json.dumps(summary(), ensure_ascii=False, indent=2))
        return 0
    if os.geteuid() != 0:
        print("需要管理员权限：sudo /Library/NetGuard/bin/netguard update %s" % command, file=sys.stderr)
        return 2
    if command in ("run", "check", "now"):
        print(json.dumps(run_once(force=command == "now"), ensure_ascii=False, indent=2))
        return 0
    if command in ("enable", "disable"):
        set_enabled(command == "enable")
        print("自动更新已%s。" % ("开启" if command == "enable" else "关闭"))
        return 0
    print("用法：netguard update status|check|now|enable|disable", file=sys.stderr)
    return 2
