"""Read-only observations of the Mac. Every method is overridable in tests."""
import ipaddress
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

    # ---- ClaudeGuard (upstream macOS version) ----
    def claudeguard(self):
        user = self.console_user()
        info = {"installed": False, "fresh": False, "age": None, "state": None, "error": None}
        if not user:
            return info
        import pwd
        try:
            home = pwd.getpwnam(user[0]).pw_dir
        except KeyError:
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
            info["error"] = data.get("enforcement_error") or None
        return info
