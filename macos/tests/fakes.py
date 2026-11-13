"""Test doubles: a pfctl emulator and scripted probes. No real network or pf access."""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from netguard import config, paths  # noqa: E402


def use_temp_root(testcase):
    tmp = tempfile.TemporaryDirectory()
    testcase.addCleanup(tmp.cleanup)
    root = tmp.name
    for name, file in (("CONFIG", "config.json"), ("STATE", "state.json"), ("GUARD", "guard.json"),
                       ("STATUS", "status.json"), ("EVENTS", "events.jsonl"), ("LOG", "netguard.log"),
                       ("LOCK", "state.lock"), ("TOKEN", "pf-token"), ("ANCHOR_FILE", "anchor.rules")):
        old = getattr(paths, name)
        setattr(paths, name, os.path.join(root, file))
        testcase.addCleanup(setattr, paths, name, old)
    return root


class FakePfctl:
    """Emulates the pfctl invocations NetGuard makes and records every argv."""

    def __init__(self):
        self.anchor_text = ""
        self.tokens = []
        self.table = None
        self.next_token = 1000
        self.other_enabled = False
        self.main_ref = True
        self.calls = []
        self.fail_load = False
        self.table = None  # None = no ng_claude table
        self.main_extra = []      # extra main-ruleset lines after the com.apple/* anchor
        self.foreign = {}         # other anchor name -> rules text (siblings or main anchors)

    def rules_output(self):
        out = []
        for line in self.anchor_text.splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                out.append(s)
        return "\n".join(out) + ("\n" if out else "")

    def __call__(self, args, input=None, timeout=15, env=None):
        args = list(args)
        self.calls.append(args)
        assert args[0] == paths.PFCTL, args
        a = args[1:]
        ok = lambda out="", err="": subprocess.CompletedProcess(args, 0, out, err)  # noqa: E731
        if a[:1] == ["-n"]:
            return ok()
        if a == ["-a", paths.ANCHOR, "-f", "-"]:
            if self.fail_load:
                return subprocess.CompletedProcess(args, 1, "", "syntax error")
            self.anchor_text = input
            if "table <ng_claude>" in input:
                self.table = []  # a reload empties the declared table
            return ok()
        if a[:4] == ["-a", paths.ANCHOR, "-t", "ng_claude"]:
            op = a[5]
            if op == "replace":
                self.table = list(a[6:])
            elif op == "flush":
                self.table = [] if self.table is not None else None
            elif op == "kill":
                self.table = None
            elif op == "show":
                return ok("".join("   %s\n" % x for x in (self.table or [])))
            return ok()
        if a == ["-a", paths.ANCHOR, "-sr"]:
            return ok(self.rules_output())
        if a == ["-a", paths.ANCHOR, "-F", "rules"]:
            self.anchor_text = ""
            return ok()
        if a == ["-sr"]:
            main = ['anchor "com.apple/*" all'] if self.main_ref else []
            return ok("".join(l + "\n" for l in main + self.main_extra))
        if a == ["-a", "com.apple", "-sA"]:
            kids = [n for n in self.foreign if n.startswith("com.apple/") and n.count("/") == 1]
            if self.anchor_text:
                kids.append(paths.ANCHOR)
            return ok("".join("  %s\n" % n for n in sorted(kids)))
        if len(a) == 3 and a[0] == "-a" and a[2] == "-sr" and a[1] in self.foreign:
            return ok(self.foreign[a[1]])
        if a == ["-s", "info"]:
            on = bool(self.tokens) or self.other_enabled
            return ok("Status: %s for 0 days\n" % ("Enabled" if on else "Disabled"))
        if a == ["-s", "References"]:
            rows = "TOKENS:\nPID      Process Name                TOKEN                     TIMESTAMP\n"
            for t in self.tokens:
                rows += "123      pfctl                       %s                     1h\n" % t
            return ok(rows)
        if a == ["-E"]:
            self.next_token += 1
            self.tokens.append(str(self.next_token))
            return ok("", "pf enabled\nToken : %d\n" % self.next_token)
        if a[:1] == ["-X"]:
            if a[1] in self.tokens:
                self.tokens.remove(a[1])
            return ok()
        if a[-2:] == ["-s", "labels"]:
            return ok()
        raise AssertionError("unexpected pfctl call %r" % args)

    def reboot(self):
        self.anchor_text = ""
        self.tokens = []
        self.table = None


class FakeProbes:
    def __init__(self, cfg):
        self.cfg = cfg
        self.egress_ip = "203.0.113.10"
        self.claude_ip = "203.0.113.10"
        self.cores = [{"pid": 50, "uid": 0, "gid": 20, "comm": "/Applications/FlClash.app/Contents/MacOS/FlClashCore",
                       "privileged": True}]
        self.tun = "utun5"
        self.physical = ["en0"]
        self.bypass = False
        self.dns = True
        self.user = ("alice", 501)
        self.boot = 0
        self.wake = 0
        self.login = 0
        self.cg = {"installed": True, "fresh": True, "age": 1.0, "state": "allowed", "error": None,
                   "ip": "203.0.113.10", "protection_enabled": True, "helper_loaded": True,
                   "cli_hooked": True, "cli_links": [{"path": "/Users/alice/.local/bin/claude", "guarded": True}],
                   "app_path": "/Applications/Claude.app", "app_path_ok": True, "cli_path_ok": True}
        self.ui = True
        self.mode = "global"
        self.route = None  # None = same as tun
        self.dns_reach = True
        self.dns_calls = 0
        self.exempt = []
        self.procs = []
        self.args = {}
        self.fake_ips = ["198.18.0.58", "198.18.0.79"]
        self.resolve_calls = 0

    def tun_addresses(self, domains, resolver="1.1.1.1"):
        self.resolve_calls += 1
        return list(self.fake_ips)

    def egress(self, url, max_time=8):
        self.egress_calls = getattr(self, "egress_calls", 0) + 1
        return self.claude_ip if "claude" in url else self.egress_ip

    def find_core(self):
        return [dict(c) for c in self.cores]

    def tun_interface(self):
        return self.tun

    def physical_interfaces(self):
        return list(self.physical)

    def direct_bypass(self, iface, target):
        return self.bypass

    def dns_ok(self, name="www.apple.com"):
        return self.dns

    def console_user(self):
        return self.user

    def boot_time(self):
        return self.boot

    def wake_time(self):
        return self.wake

    def login_time(self, uid):
        return self.login

    def claudeguard(self):
        return dict(self.cg)

    def processes(self):
        return list(self.procs)

    def flclash_ui(self):
        return self.ui

    def flclash_config(self):
        return {"mode": self.mode, "path": "/Users/alice/Library/Application Support/com.follow.clash/config.yaml",
                "mtime": 1, "source": "config.yaml"}

    def route_interface(self, target="1.1.1.1"):
        return self.route if self.route is not None else self.tun

    def dns_reachable(self, name="www.apple.com"):
        self.dns_calls += 1
        return self.dns_reach(self) if callable(self.dns_reach) else self.dns_reach

    def exemption_users(self, gid, names):
        return list(self.exempt)

    def process_args(self):
        return dict(self.args)


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def make_service(testcase, whitelist=("203.0.113.10",), **cfg_overrides):
    from netguard import pfrules
    from netguard.service import Service
    use_temp_root(testcase)
    data = {"whitelist": list(whitelist)}
    data.update(cfg_overrides)
    cfg = config.validate(data)
    pf_runner = FakePfctl()
    probes = FakeProbes(cfg)
    clock = Clock()
    kills = []
    notes = []
    svc = Service(cfg=cfg, probes=probes, pf=pfrules.PF(runner=pf_runner), clock=clock,
                  notifier=lambda title, msg, key=None: notes.append((title, msg)),
                  killer=lambda: kills.append(clock()) or 3, sleeper=lambda s: clock.advance(s))
    return svc, pf_runner, probes, clock, kills, notes
