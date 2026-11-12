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
        app = cfg.get("real_claude_app_path") if isinstance(cfg, dict) else None
        cli = cfg.get("real_claude_cli_path") if isinstance(cfg, dict) else None
        info["app_path"] = app
        info["app_path_ok"] = bool(app and os.path.isdir(app)) if app else None
        info["cli_path_ok"] = bool(cli and os.path.isfile(os.path.realpath(cli))) if cli else None
        # Same rule as ClaudeGuard's own `doctor`: every `claude` in these directories must be
        # ClaudeGuard's shim, otherwise typing `claude` bypasses the pre-flight check.
        links = []
        for directory in (os.path.join(home, ".local", "bin"), "/opt/homebrew/bin", "/usr/local/bin"):
            link = os.path.join(directory, "claude")
            if os.path.lexists(link):
                real = os.path.realpath(link)
                ours = os.path.basename(real) == "cli_wrapper.py" or "/ClaudeGuard/" in real
                links.append({"path": link, "guarded": ours})
        info["cli_links"] = links
        info["cli_hooked"] = bool(links) and all(l["guarded"] for l in links)
        return info
