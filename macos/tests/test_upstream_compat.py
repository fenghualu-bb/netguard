"""Compatibility with the upstream projects NetGuard depends on.

Always runs against recorded fixtures. With CG_SRC=<ClaudeGuard checkout> it also checks that
checkout's own source (the daily upstream workflow points it at ClaudeGuard's latest main):
the pf rules it loads must not look like a bypass, the files and keys NetGuard reads must
still exist, and Claude Code discovery must work (natively or with NetGuard's patch).
"""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from fakes import make_service
from netguard import pfrules, probes

CG_SRC = os.environ.get("CG_SRC")
TUN = "utun4"

# `pfctl -sr` output of ClaudeGuard v2's VPN rule (6a864c3) while the exit is whitelisted.
CG_V2_RULES = (
    "pass out quick on utun4 inet proto tcp from any to <claude_guard> flags S/SA keep state (if-bound)\n"
    "pass out quick on utun4 inet proto udp from any to <claude_guard> keep state (if-bound)\n"
    "block drop out quick proto tcp from any to <claude_guard>\n"
    "block drop out quick proto udp from any to <claude_guard>\n")


def permits(text, tunnel):
    return [r for r in text.splitlines() if pfrules.foreign_permit(r, False, tunnel=tunnel)]


class TunnelBoundPermitTests(unittest.TestCase):
    def test_claudeguard_v2_rules_are_not_a_bypass(self):
        self.assertEqual(permits(CG_V2_RULES, TUN), [])

    def test_the_same_rule_on_another_interface_is_a_bypass(self):
        self.assertEqual(len(permits(CG_V2_RULES, "utun5")), 2)
        self.assertEqual(len(permits(CG_V2_RULES, None)), 2)
        self.assertEqual(len(permits(CG_V2_RULES.replace("on utun4", "on en0"), TUN)), 2)

    def test_everything_except_the_tunnel_is_a_bypass(self):
        self.assertTrue(pfrules.foreign_permit("pass out quick on ! utun4 all", False, tunnel=TUN))

    def test_daemon_does_not_lock_on_claudeguard_v2(self):
        svc, pf, pr, clock, kills, _ = make_service(self)
        svc.enable(out=lambda *_: None)
        pr.tun = TUN
        pf.foreign = {"com.apple/100.claudeguard": CG_V2_RULES}
        svc.tick()
        clock.advance(10)
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])
        self.assertEqual(svc.read_guard()["observations"]["foreign_permits"], [])


class ClaudeGuardModeTests(unittest.TestCase):
    def test_proxy_mode_is_reported(self):
        svc, pf, pr, clock, kills, _ = make_service(self)
        pr.cg = dict(pr.cg, mode="proxy")
        svc.tick()
        self.assertIn("ClaudeGuard 处于代理模式，请切回 VPN 模式", svc.read_guard()["last_findings"])

    def test_vpn_mode_and_v1_are_fine(self):
        for mode in ("vpn", None):
            svc, pf, pr, clock, kills, _ = make_service(self)
            pr.cg = dict(pr.cg, mode=mode)
            svc.tick()
            self.assertEqual(svc.read_guard()["last_findings"], [], mode)


class FlClashUpdateTests(unittest.TestCase):
    def test_update_that_drops_the_authorization_is_explained(self):
        svc, pf, pr, clock, kills, notes = make_service(self)
        svc.enable(out=lambda *_: None)
        svc.tick()
        self.assertEqual(svc.read_state()["flclash_authorized_version"], "0.9.3")
        pr.fl_version = "0.9.4"
        pr.cores = [dict(pr.cores[0], uid=501, privileged=False)]  # the update replaced the setuid core
        clock.advance(10)
        svc.tick()
        findings = svc.read_guard()["last_findings"]
        self.assertTrue(any("从 0.9.3 更新到 0.9.4" in f and "重新开启 TUN" in f for f in findings), findings)
        self.assertTrue(any("需要重新授权" in t for t, _ in notes))
        pr.cores = [dict(pr.cores[0], uid=0, privileged=True)]  # re-authorized
        clock.advance(10)
        svc.tick()
        self.assertEqual(svc.read_state()["flclash_authorized_version"], "0.9.4")
        self.assertFalse(any("更新到" in f for f in svc.read_guard()["last_findings"]))

    def test_moved_tun_address_is_pointed_out(self):
        svc, pf, pr, clock, kills, notes = make_service(self)
        pr.tun = None
        pr.tunnels = [("utun6", "172.19.0.1")]
        svc.tick()
        self.assertTrue(any("utun6 172.19.0.1" in f and "tun_v4" in f for f in svc.read_guard()["last_findings"]))


class FlClashCoreDiscoveryTests(unittest.TestCase):
    def rows(self, *rows):
        from netguard import config, probes as probes_mod
        p = probes_mod.Probes(config.validate({}))
        p.processes = lambda: [dict(pid=pid, uid=uid, gid=gid, path=path, comm=path) for pid, uid, gid, path in rows]
        return p.find_core()

    def test_renamed_core_inside_flclash_app_is_found(self):
        cores = self.rows((10, 501, 20, "/Applications/FlClash.app/Contents/MacOS/FlClash"),
                          (11, 0, 20, "/Applications/FlClash.app/Contents/MacOS/MihomoCore"))
        self.assertEqual([(c["pid"], c["privileged"], c.get("renamed")) for c in cores], [(11, True, True)])

    def test_named_core_wins_and_unprivileged_helpers_are_not_cores(self):
        cores = self.rows((11, 0, 20, "/Applications/FlClash.app/Contents/MacOS/FlClashCore"),
                          (12, 0, 0, "/Applications/FlClash.app/Contents/MacOS/HelperService"))
        self.assertEqual([c["pid"] for c in cores], [11])
        self.assertEqual(self.rows((12, 0, 0, "/Applications/FlClash.app/Contents/MacOS/HelperService")), [])


@unittest.skipUnless(CG_SRC, "set CG_SRC to a ClaudeGuard checkout")
class ClaudeGuardSourceTests(unittest.TestCase):
    """Run against the actual upstream source tree."""

    def read(self, rel):
        with open(os.path.join(CG_SRC, rel), encoding="utf-8") as stream:
            return stream.read()

    def source(self):
        out = []
        for base, _dirs, names in os.walk(os.path.join(CG_SRC, "src")):
            for name in names:
                if name.endswith((".py", ".swift")):
                    with open(os.path.join(base, name), encoding="utf-8", errors="replace") as stream:
                        out.append(stream.read())
        out.append(self.read("install.sh"))
        return "\n".join(out)

    def module(self, name):
        sys.path.insert(0, os.path.join(CG_SRC, "src"))
        try:
            spec = importlib.util.spec_from_file_location("cg_" + name, os.path.join(CG_SRC, "src", name + ".py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        finally:
            sys.path.pop(0)

    def test_pf_rules_are_not_a_bypass(self):
        pf_mod = self.module("pf_controller")
        rules = []
        if hasattr(pf_mod, "make_vpn_rule"):
            rules.append(pf_mod.make_vpn_rule(["160.79.104.10"], TUN))
        if hasattr(pf_mod, "make_rule"):
            rules.append(pf_mod.make_rule(["160.79.104.10"]))
        self.assertTrue(rules, "ClaudeGuard no longer builds pf rules the way NetGuard expects")
        for text in rules:
            self.assertEqual(permits(text, TUN), [], text)

    def test_files_and_keys_netguard_reads_still_exist(self):
        text = self.source()
        for needle in ("updated_at", "protection_enabled", "allowed_ips", "real_claude_cli_path",
                       "real_claude_app_path", "com.claudeguard.helper", ".local/share/ClaudeGuard",
                       "cli_wrapper", ".config/claudeguard", "state.json"):
            self.assertIn(needle, text, needle)

    def test_connection_mode_values(self):
        config_src = self.read("src/config.py")
        if "connection_mode" in config_src:
            self.assertIn('"vpn"', config_src)

    def test_claude_code_discovery_works(self):
        """Natively, or with NetGuard's hash-checked patch (macos/patches/claudeguard/apply.sh)."""
        integrity = os.path.join(CG_SRC, "src", "integrity.py")
        digest = hashlib.sha256(open(integrity, "rb").read()).hexdigest()
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, True)
        os.makedirs(os.path.join(home, ".local/share/ClaudeGuard/src"))
        os.makedirs(os.path.join(home, ".local/share/claude/versions"))
        shutil.copy(integrity, os.path.join(home, ".local/share/ClaudeGuard/src/integrity.py"))
        cli = os.path.join(home, ".local/share/claude/versions/2.1.322")
        with open(cli, "w") as stream:
            stream.write("#!/bin/sh\n")
        os.chmod(cli, 0o755)
        patcher = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "patches", "claudeguard", "apply.sh")
        env = dict(os.environ, HOME=home)
        if digest == probes.CG_INTEGRITY_ORIGINAL:
            subprocess.run(["bash", patcher], env=env, check=True, capture_output=True)
        probe = ("import importlib.util, sys; spec = importlib.util.spec_from_file_location('i', sys.argv[1]);"
                 "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m);"
                 "print(m.discover_real_cli() or '')")
        out = subprocess.run([sys.executable, "-c", probe, os.path.join(home, ".local/share/ClaudeGuard/src/integrity.py")],
                             env=env, capture_output=True, text=True, cwd=os.path.join(CG_SRC, "src"))
        self.assertTrue(out.stdout.strip().endswith("/versions/2.1.322"),
                        "Claude Code not discovered (integrity.py %s…): %s %s" % (digest[:12], out.stdout, out.stderr))


if __name__ == "__main__":
    unittest.main()
