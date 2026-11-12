"""Read-only observations of the Mac. Every method is overridable in tests."""
import ipaddress
import json
import os
import re
import time

from . import paths, util


def parse_ps(output):
    """`ps -axww -o pid=,uid=,rgid=,comm=` -> list of dicts (comm may contain spaces)."""
    rows = []
    for line in (output or "").splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 4 or not parts[0].isdigit():
            continue
        try:
            rows.append({"pid": int(parts[0]), "uid": int(parts[1]), "gid": int(parts[2]),
                         "comm": parts[3].strip()})
        except ValueError:
            continue
    return rows


def parse_ps_args(output):
    out = {}
    for line in (output or "").splitlines():
        parts = line.strip().split(None, 1)
        if parts and parts[0].isdigit():
            out[int(parts[0])] = parts[1] if len(parts) > 1 else ""
    return out


def parse_ifconfig(output):
    """-> {ifname: {"flags": set, "inet": [..], "inet6": [..], "status": str|None}}"""
    result = {}
    current = None
    for line in (output or "").splitlines():
        head = re.match(r"^([A-Za-z0-9]+): flags=\w+<([^>]*)>", line)
        if head:
            current = head.group(1)
            result[current] = {"flags": set(filter(None, head.group(2).split(","))),
                               "inet": [], "inet6": [], "status": None}
            continue
        if current is None:
            continue
        s = line.strip()
        if s.startswith("inet "):
            result[current]["inet"].append(s.split()[1])
        elif s.startswith("inet6 "):
            result[current]["inet6"].append(s.split()[1].split("%")[0])
        elif s.startswith("status:"):
            result[current]["status"] = s.split(":", 1)[1].strip()
    return result


def parse_trace(text):
    match = re.search(r"(?m)^ip=(\S+)\s*$", text or "")
    if not match:
        return None
    try:
        return str(ipaddress.ip_address(match.group(1)))
    except ValueError:
        return None


def parse_sysctl_time(text):
    match = re.search(r"sec\s*=\s*(\d+)", text or "")
    return int(match.group(1)) if match else 0


def parse_etime(text):
    """ps etime `[[dd-]hh:]mm:ss` -> seconds."""
    text = (text or "").strip()
    if not text:
        return None
    days = 0
    if "-" in text:
        d, text = text.split("-", 1)
        days = int(d)
    parts = [int(p) for p in text.split(":")]
    while len(parts) < 3:
        parts.insert(0, 0)
    h, m, s = parts[-3:]
    return days * 86400 + h * 3600 + m * 60 + s


class Probes:
    def __init__(self, cfg, runner=util.run):
        self.cfg = cfg
        self.runner = runner

    # ---- processes ----
    def processes(self):
        out = self.runner([paths.PS, "-axww", "-o", "pid=,uid=,rgid=,comm="]).stdout
        return parse_ps(out)

    def process_args(self):
        return parse_ps_args(self.runner([paths.PS, "-axww", "-o", "pid=,args="]).stdout)

    def find_core(self):
        names = set(self.cfg["core_names"])
        cores = []
        for row in self.processes():
            if os.path.basename(row["comm"]) in names:
                row = dict(row)
                row["privileged"] = row["uid"] == 0 and row["gid"] != 0
                cores.append(row)
        return cores

    # ---- interfaces ----
    def interfaces(self):
        return parse_ifconfig(self.runner([paths.IFCONFIG, "-a"]).stdout)

    def tun_interface(self):
        net = ipaddress.ip_network(self.cfg["tun_v4"])
        for name, info in sorted(self.interfaces().items()):
            if "UP" not in info["flags"]:
                continue
            for addr in info["inet"]:
                try:
                    if ipaddress.ip_address(addr) in net:
                        return name
                except ValueError:
                    continue
        return None

    def physical_interfaces(self):
        tun = ipaddress.ip_network(self.cfg["tun_v4"])
        found = []
        for name, info in sorted(self.interfaces().items()):
            if not re.match(r"^(en|bridge)\d+$", name) or "UP" not in info["flags"]:
                continue
            if info["status"] not in (None, "active"):
                continue
            for addr in info["inet"]:
                ip = ipaddress.ip_address(addr)
                if not ip.is_loopback and not ip.is_link_local and ip not in tun:
                    found.append(name)
                    break
        return found

    # ---- network checks ----
    def egress(self, url):
        result = self.runner([paths.CURL, "-s", "--noproxy", "*", "--max-time", "8", url], timeout=12)
        return parse_trace(result.stdout) if result.returncode == 0 else None

    def direct_bypass(self, interface, target):
        """True if a connection pinned to a physical interface SUCCEEDS (= kill switch broken).

        The response body (which would contain the real IP) is discarded.
        """
        result = self.runner([paths.CURL, "-s", "-o", "/dev/null", "--noproxy", "*",
                              "--interface", interface, "--connect-timeout", "4", "--max-time", "6",
                              "-w", "%{http_code}", "https://%s/cdn-cgi/trace" % target], timeout=10)
        return result.returncode == 0 and (result.stdout or "").strip() not in ("", "000")

    def dns_ok(self, name="www.apple.com"):
        result = self.runner([paths.DSCACHEUTIL, "-q", "host", "-a", "name", name], timeout=10)
        return result.returncode == 0 and "ip_address" in (result.stdout or "")

    # ---- user session ----
    def console_user(self):
        try:
            import pwd
            uid = os.stat("/dev/console").st_uid
            if uid == 0:
                return None
            return pwd.getpwuid(uid).pw_name, uid
        except (OSError, KeyError, ImportError):
            return None

    def boot_time(self):
        return parse_sysctl_time(self.runner([paths.SYSCTL, "-n", "kern.boottime"]).stdout)

    def wake_time(self):
        return parse_sysctl_time(self.runner([paths.SYSCTL, "-n", "kern.waketime"]).stdout)

    def login_time(self, uid):
        """Start time of the console user's Dock (the macOS analogue of explorer.exe)."""
        for row in self.processes():
            if row["uid"] == uid and os.path.basename(row["comm"]) == "Dock":
                out = self.runner([paths.PS, "-o", "etime=", "-p", str(row["pid"])]).stdout
                elapsed = parse_etime(out)
                if elapsed is not None:
                    return int(time.time() - elapsed)
        return None

    def user_home(self):
        user = self.console_user()
        if not user:
            return None
        import pwd
        try:
            return pwd.getpwnam(user[0]).pw_dir
        except KeyError:
            return None

    # ---- FlClash ----
    def flclash_ui(self):
        return any(os.path.basename(r["comm"]) == "FlClash" for r in self.processes())

    def flclash_config(self):
        """Proxy mode from FlClash's own files. Only the mode is read; never nodes or credentials."""
        home = self.user_home()
        result = {"mode": None, "path": None, "mtime": None, "source": None}
        if not home:
            return result
        bases = [os.path.join(home, "Library", "Application Support", "com.follow.clash"),
                 os.path.join(home, "Library", "Containers", "com.follow.clash", "Data", "Library",
                              "Application Support", "com.follow.clash")]
        found = []
        for base in bases:
            path = os.path.join(base, "config.yaml")
            try:
                found.append((os.stat(path).st_mtime, path))
            except OSError:
                continue
        if found:
            mtime, path = max(found)
            result.update(path=path, mtime=int(mtime), source="config.yaml")
            try:
                with open(path, "r", encoding="utf-8-sig", errors="replace") as stream:
                    head = stream.read(400_000)
                mode = re.search(r'^mode:\s*["\']?(global|rule|direct)["\']?\s*(?:#.*)?$', head, re.M | re.I)
                if mode:
                    result["mode"] = mode.group(1).lower()
            except OSError:
                pass
        if result["mode"] is None:
            for base in bases:
                prefs = util.read_json(os.path.join(base, "shared_preferences.json"), None)
                try:
                    patch = json.loads(prefs["flutter.config"])["patchClashConfig"]
                    mode = str(patch.get("mode", "")).lower()
                except (TypeError, KeyError, ValueError):
                    continue
                if mode in ("global", "rule", "direct"):
                    result.update(mode=mode, path=os.path.join(base, "shared_preferences.json"),
                                  source="shared_preferences.json")
                    break
        return result

    def route_interface(self, target="1.1.1.1"):
        out = self.runner([paths.ROUTE, "-n", "get", target]).stdout
        match = re.search(r"interface:\s*(\S+)", out or "")
        return match.group(1) if match else None

    # ---- DNS that bypasses every cache: the system resolver's first server, asked directly ----
    def dns_reachable(self, name="www.apple.com"):
        result = self.runner([paths.DIG, "+time=3", "+tries=1", "+short", name], timeout=8)
        return result.returncode == 0 and bool(re.search(r"^\d+\.\d+\.\d+\.\d+$", result.stdout or "", re.M))

    # ---- programs that share the proxy core's pf exemption (uid 0 + user group) ----
    def exemption_users(self, core_gid, core_names):
        others = [r for r in self.processes()
                  if r["uid"] == 0 and r["gid"] == core_gid and os.path.basename(r["comm"]) not in core_names]
        if not others:
            return []
        pids = ",".join(str(r["pid"]) for r in others)
        out = self.runner(["/usr/sbin/lsof", "+c", "0", "-nP", "-a", "-i", "-p", pids, "-Fpc"], timeout=15).stdout
        names, current = set(), None
        for line in (out or "").splitlines():
            if line.startswith("p"):
                current = line[1:]
            elif line.startswith("c") and current:
                names.add(line[1:])
        return sorted(names)

    # ---- ClaudeGuard (upstream macOS version) ----
    def claudeguard(self):
        info = {"installed": False, "fresh": False, "age": None, "state": None, "error": None,
                "ip": None, "protection_enabled": None, "helper_loaded": None,
                "cli_hooked": None, "cli_links": [], "app_path": None, "app_path_ok": None,
                "cli_path_ok": None}
        home = self.user_home()
        if not home:
            return info
        info["installed"] = os.path.isdir("/Applications/ClaudeGuard.app") or \
            os.path.isdir(os.path.join(home, ".local", "share", "ClaudeGuard"))
        data = util.read_json(os.path.join(home, ".config", "claudeguard", "state.json"), None)
        if isinstance(data, dict):
            try:
                info["age"] = round(time.time() - float(data.get("updated_at", 0)), 1)
            except (TypeError, ValueError):
                info["age"] = None
            info["fresh"] = info["age"] is not None and -5 <= info["age"] <= 30
            info["state"] = data.get("state")
            info["ip"] = data.get("ip")
            info["protection_enabled"] = data.get("protection_enabled")
            info["error"] = data.get("enforcement_error") or None
        info["helper_loaded"] = self.runner([paths.LAUNCHCTL, "print", "system/com.claudeguard.helper"],
                                            timeout=10).returncode == 0
        cfg = util.read_json(os.path.join(home, ".config", "claudeguard", "config.json"), {}) or {}
        info.update(judge_claude_paths(cfg if isinstance(cfg, dict) else {}, home))
        return info


def _is_shim(path):
    real = os.path.realpath(path)
    return os.path.basename(real) == "cli_wrapper.py" or "/ClaudeGuard/" in real


def find_claude_apps(home, app_dirs=None):
    """Installed Claude Desktop bundles (bundle id prefix com.anthropic.claude, as ClaudeGuard does)."""
    import plistlib
    found = []
    for base in app_dirs or ("/Applications", os.path.join(home, "Applications")):
        try:
            names = os.listdir(base)
        except OSError:
            continue
        for name in names:
            if not name.endswith(".app") or "claudeguard" in name.lower():
                continue
            app = os.path.join(base, name)
            try:
                with open(os.path.join(app, "Contents", "Info.plist"), "rb") as stream:
                    bundle = str(plistlib.load(stream).get("CFBundleIdentifier", ""))
            except (OSError, ValueError, plistlib.InvalidFileException):
                continue
            if bundle.startswith("com.anthropic.claude"):
                found.append(app)
    return sorted(found)


def find_claude_cli(home, extra_roots=()):
    """Real Claude Code installations (native, Homebrew cask, npm), never ClaudeGuard's shim."""
    found = []
    versions = os.path.join(home, ".local", "share", "claude", "versions")
    try:
        found += [os.path.join(versions, v) for v in os.listdir(versions)
                  if os.path.isfile(os.path.join(versions, v))]
    except OSError:
        pass
    candidates = [os.path.join(home, ".claude", "local", "claude")]
    for prefix in ("/opt/homebrew", "/usr/local", os.path.join(home, ".npm-global")) + tuple(extra_roots):
        candidates.append(os.path.join(prefix, "lib", "node_modules", "@anthropic-ai", "claude-code", "cli.js"))
        candidates.append(os.path.join(prefix, "bin", "claude"))
        cask = os.path.join(prefix, "Caskroom", "claude-code")
        try:
            for v in os.listdir(cask):
                candidates.append(os.path.join(cask, v, "claude"))
        except OSError:
            pass
    for path in candidates:
        if os.path.isfile(path) and not _is_shim(path):
            found.append(path)
    return sorted(set(found))


CG_INTEGRITY_ORIGINAL = "165a1ea4d857e3da7f0e539573396153c2ae962486ea7315de216e5da130f1f9"
CG_INTEGRITY_PATCHED = "75ab8749ea6bf3f1ccd37471da98b6d5b46d9754a2dd6c4f9fd7aeed79cca70c"


def claudeguard_patch_state(home):
    """NetGuard's ClaudeGuard compatibility patch (macos/patches/claudeguard/apply.sh)."""
    import hashlib
    try:
        with open(os.path.join(home, ".local", "share", "ClaudeGuard", "src", "integrity.py"), "rb") as stream:
            digest = hashlib.sha256(stream.read()).hexdigest()
    except OSError:
        return None
    return {CG_INTEGRITY_PATCHED: "patched", CG_INTEGRITY_ORIGINAL: "original"}.get(digest, "unknown")


def judge_claude_paths(cg_config, home, app_dirs=None, extra_roots=()):
    """Separate "not installed" (nothing to protect) from "installed but ClaudeGuard detached".

    True = ok, False = installed but ClaudeGuard's record/hook is stale (claude_path finding),
    None = that Claude program is not installed on this Mac.
    """
    apps = find_claude_apps(home, app_dirs)
    clis = find_claude_cli(home, extra_roots)
    app = cg_config.get("real_claude_app_path")
    cli = cg_config.get("real_claude_cli_path")
    out = {"app_path": app, "app_installed": apps, "cli_installed": clis}
    if not apps:
        out["app_path_ok"] = None
    else:
        out["app_path_ok"] = bool(app) and os.path.realpath(app) in [os.path.realpath(a) for a in apps]
    if not clis:
        out["cli_path_ok"] = None
    else:
        out["cli_path_ok"] = bool(cli) and os.path.isfile(os.path.realpath(cli)) and not _is_shim(cli)
    # Same rule as ClaudeGuard's own `doctor`: every `claude` in these directories must be
    # ClaudeGuard's shim, otherwise typing `claude` bypasses the pre-flight check.
    links = []
    for directory in (os.path.join(home, ".local", "bin"), "/opt/homebrew/bin", "/usr/local/bin"):
        link = os.path.join(directory, "claude")
        if os.path.lexists(link):
            links.append({"path": link, "guarded": _is_shim(link)})
    out["cli_links"] = links
    out["cg_patch"] = claudeguard_patch_state(home)
    if links:
        out["cli_hooked"] = all(l["guarded"] for l in links)
    else:
        out["cli_hooked"] = False if clis else None  # no shim matters only when Claude Code exists
    return out
