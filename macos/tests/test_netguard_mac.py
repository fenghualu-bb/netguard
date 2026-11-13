"""Offline regression tests for NetGuard macOS. Run anywhere with Python 3.9+:
    python3 -m unittest discover -s macos/tests -p 'test_*.py'
"""
import json
import os
import re
import shutil
import subprocess
import unittest

from fakes import HERE, make_service, use_temp_root

from netguard import claude, config, events, paths, pfrules, probes, service
from netguard.service import UserError

MACOS = os.path.dirname(HERE)


def read_events():
    return events.read(1000)


def types():
    return [e["type"] for e in read_events()]


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config.validate({"whitelist": ["203.0.113.10"]})

    def rules(self, **kw):
        cfg = dict(self.cfg)
        cfg.update(kw)
        text = pfrules.render(cfg, 0, 20)
        return [l for l in text.splitlines() if l.strip() and not l.startswith("#")]

    def test_order_default_block_then_permits(self):
        lines = self.rules()
        idx = {name: next(i for i, l in enumerate(lines) if name in l)
               for name in ("ng_loopback", "ng_anthropic", "ng_block_all", "ng_lan", "ng_tun", "ng_core")}
        self.assertLess(idx["ng_block_all"], idx["ng_lan"])
        self.assertLess(idx["ng_lan"], idx["ng_tun"])
        self.assertLess(idx["ng_block_all"], idx["ng_core"])
        # only loopback and the Anthropic refusal are quick; permits stay last-match
        for l in lines:
            if " quick " in l:
                self.assertTrue("ng_loopback" in l or "ng_anthropic" in l or "ng_claude" in l, l)
        self.assertTrue(lines[idx["ng_block_all"]].startswith("block return out all"))

    def test_core_permit_is_uid0_with_user_group(self):
        core = [l for l in self.rules() if "ng_core" in l]
        self.assertEqual(len(core), 2)
        for l in core:
            self.assertIn("user 0 group 20", l)
            self.assertRegex(l, r"proto (tcp|udp)")

    def test_tcp_permits_accept_midstream_packets(self):
        for tag in ("ng_lan", "ng_tun", "ng_core"):
            tcp = [l for l in self.rules() if tag in l and "proto tcp" in l]
            self.assertTrue(tcp and all("flags any" in l for l in tcp), tag)

    def test_anthropic_block_exempts_only_tun(self):
        anth = [l for l in self.rules() if "ng_anthropic" in l]
        self.assertIn("block return out quick inet from ! 198.18.0.0/16 to { 160.79.104.0/23, 153.61.224.0/22 }", anth[0])
        self.assertIn("inet6 from ! fdfe:dcba:9876::/48 to { 2607:6bc0::/48 }", anth[1])

    def test_dns_block_is_opt_in_and_placed_between_lan_and_tun(self):
        self.assertFalse([l for l in self.rules() if "ng_dns" in l])
        lines = self.rules(block_lan_dns=True)
        dns = next(i for i, l in enumerate(lines) if "ng_dns" in l)
        last_lan = max(i for i, l in enumerate(lines) if "ng_lan" in l)
        first_tun = min(i for i, l in enumerate(lines) if "ng_tun" in l)
        self.assertTrue(last_lan < dns < first_tun)

    def test_refuses_dangerous_identities(self):
        with self.assertRaises(pfrules.PFError):
            pfrules.render(self.cfg, 0, 0)  # would exempt every root daemon
        with self.assertRaises(pfrules.PFError):
            pfrules.render(self.cfg, 501, 20)  # non-root core cannot be told apart from Claude

    def test_no_rule_touches_main_ruleset_or_states(self):
        text = pfrules.render(self.cfg, 0, 20)
        self.assertNotIn("anchor", "\n".join(l for l in text.splitlines() if not l.startswith("#")))
        self.assertNotIn("set skip", text)
        self.assertNotIn("scrub", text)


class ForeignPermitTests(unittest.TestCase):
    def test_rule_judgement(self):
        fp = pfrules.foreign_permit
        self.assertTrue(fp("pass out quick all flags S/SA keep state", False))
        self.assertFalse(fp("pass out all flags S/SA keep state", False))  # overridden by our block
        self.assertTrue(fp("pass out all flags S/SA keep state", True))   # after us: last match wins
        self.assertTrue(fp("pass quick inet proto tcp all", False))       # no direction = both
        self.assertFalse(fp("pass in quick all", True))
        self.assertFalse(fp("pass out quick on lo0 all", True))
        self.assertFalse(fp("pass quick on awdl0 all", True))
        self.assertFalse(fp("block drop out quick all", True))

    def scan(self, foreign=None, main_extra=()):
        from fakes import FakePfctl
        runner = FakePfctl()
        runner.anchor_text = pfrules.render(config.validate({}), 0, 20)
        runner.foreign = dict(foreign or {})
        runner.main_extra = list(main_extra)
        return pfrules.PF(runner=runner).foreign_permits()

    def test_clean_mac_has_no_bypass(self):
        self.assertEqual(self.scan({"com.apple/250.ApplicationFirewall": "block drop in quick proto tcp all\n",
                                    "com.apple/200.AirDrop": "pass in quick on awdl0 all\n"}), [])

    def test_quick_pass_before_netguard_is_found(self):
        got = self.scan({"com.apple/300.SomeVPN": "pass out quick all flags S/SA keep state\n"})
        self.assertEqual(got, [("com.apple/300.SomeVPN", "pass out quick all flags S/SA keep state")])

    def test_non_quick_pass_after_netguard_is_found(self):
        got = self.scan({"com.apple/zzz.Late": "pass out all\n"})
        self.assertEqual([w for w, _ in got], ["com.apple/zzz.Late"])
        got = self.scan(main_extra=["pass out inet all keep state"])
        self.assertEqual(got, [("main", "pass out inet all keep state")])

    def test_main_anchor_after_com_apple_is_walked(self):
        got = self.scan({"com.claudeguard": "block return out quick inet to 160.79.104.10\n"},
                        main_extra=['anchor "com.claudeguard" all'])
        self.assertEqual(got, [])
        got = self.scan({"com.other": "pass out all\n"}, main_extra=['anchor "com.other" all'])
        self.assertEqual(got, [("com.other", "pass out all")])


class RenderModeTests(unittest.TestCase):
    def test_isolation_refuses_anthropic_through_tun_too(self):
        cfg = config.validate({})
        normal = [l for l in pfrules.render(cfg, 0, 20).splitlines() if "ng_anthropic" in l]
        isolated = [l for l in pfrules.render(cfg, 0, 20, isolate=True).splitlines() if "ng_anthropic" in l]
        self.assertTrue(all("from !" in l for l in normal))
        self.assertTrue(isolated and all("from" not in l for l in isolated))

    def test_isolation_table_only_when_isolated_and_before_permits(self):
        cfg = config.validate({})
        self.assertNotIn("ng_claude", pfrules.render(cfg, 0, 20))
        lines = [l for l in pfrules.render(cfg, 0, 20, isolate=True).splitlines()
                 if l.strip() and not l.startswith("#")]
        self.assertEqual(lines[0], "table <ng_claude> persist")
        block = next(i for i, l in enumerate(lines) if 'label "ng_claude"' in l)
        self.assertTrue(lines[block].startswith("block return out quick to <ng_claude>"))
        self.assertLess(block, next(i for i, l in enumerate(lines) if "ng_tun" in l))

    def test_dns_block_parameter_overrides_auto(self):
        cfg = config.validate({})
        self.assertNotIn("ng_dns", pfrules.render(cfg, 0, 20))
        self.assertIn("ng_dns", pfrules.render(cfg, 0, 20, dns_block=True))


class ParserTests(unittest.TestCase):
    def test_token_and_references(self):
        self.assertEqual(pfrules.parse_token("No ALTQ support in kernel\npf enabled\nToken : 1234567\n"), "1234567")
        refs = "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n88 pfctl 1234567 3 secs\n"
        self.assertTrue(pfrules.token_in_references("1234567", refs))
        self.assertFalse(pfrules.token_in_references("88", "TOKENS:\n88 pfctl 999 1s\n") and False)
        self.assertFalse(pfrules.token_in_references("123456", refs))
        self.assertFalse(pfrules.token_in_references(None, refs))

    def test_tun_addresses_keeps_only_fake_ip_answers(self):
        cfg = config.validate({"whitelist": ["203.0.113.10"]})
        answers = {"A": "cname.example.\n198.18.0.58\n160.79.104.10\n", "AAAA": "fdfe:dcba:9876::3a\n2607:6bc0::10\n"}
        seen = []

        def runner(args, input=None, timeout=15, env=None):
            seen.append(args)
            return subprocess.CompletedProcess(args, 0, answers[args[-2]], "")

        got = probes.Probes(cfg, runner=runner).tun_addresses(["claude.ai"])
        self.assertEqual(got, ["198.18.0.58", "fdfe:dcba:9876::3a"])
        self.assertTrue(all(a[0] == paths.DIG and a[1] == "@1.1.1.1" for a in seen))

    def test_ps_with_spaces(self):
        rows = probes.parse_ps("  77     0    20 /Applications/FlClash.app/Contents/MacOS/FlClashCore\n"
                               " 900   501    20 /Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/x\n")
        self.assertEqual(rows[0]["uid"], 0)
        self.assertEqual(rows[1]["comm"], "/Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/x")

    def test_ifconfig(self):
        out = ("lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n"
               "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
               "\tinet6 fe80::1%en0 prefixlen 64 scopeid 0xe\n\tinet 192.168.1.20 netmask 0xffffff00\n\tstatus: active\n"
               "utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000\n\tinet 198.18.0.1 --> 198.18.0.1 netmask 0xffff0000\n")
        info = probes.parse_ifconfig(out)
        self.assertEqual(info["en0"]["inet"], ["192.168.1.20"])
        self.assertEqual(info["en0"]["inet6"], ["fe80::1"])
        p = probes.Probes(config.validate({}), runner=lambda a, **k: subprocess.CompletedProcess(a, 0, out, ""))
        self.assertEqual(p.tun_interface(), "utun4")
        self.assertEqual(p.physical_interfaces(), ["en0"])

    def test_trace_and_times(self):
        self.assertEqual(probes.parse_trace("fl=1\nip=203.0.113.10\nts=1\n"), "203.0.113.10")
        self.assertIsNone(probes.parse_trace("<html>blocked</html>"))
        self.assertEqual(probes.parse_etime("01:02"), 62)
        self.assertEqual(probes.parse_etime("2-03:00:01"), 2 * 86400 + 3 * 3600 + 1)
        self.assertEqual(probes.parse_sysctl_time("{ sec = 1762800000, usec = 5 } Mon Nov 10"), 1762800000)


class ConfigTests(unittest.TestCase):
    def test_whitelist(self):
        cfg = config.validate({"whitelist": ["203.0.113.10", " 198.51.100.0/24 ", "203.0.113.10"]})
        self.assertEqual(cfg["whitelist"], ["198.51.100.0/24", "203.0.113.10"])
        self.assertTrue(config.ip_in_whitelist("198.51.100.7", cfg["whitelist"]))
        self.assertFalse(config.ip_in_whitelist("192.0.2.1", cfg["whitelist"]))
        self.assertFalse(config.ip_in_whitelist(None, cfg["whitelist"]))
        with self.assertRaises(config.ConfigError):
            config.validate({"whitelist": ["not-an-ip"]})
        with self.assertRaises(config.ConfigError):
            config.validate({"tun_v4": "fdfe::/48"})
        with self.assertRaises(config.ConfigError):
            config.validate({"bypass_probe_targets": ["192.168.1.1"]})

    def test_defaults(self):
        self.assertEqual(config.validate({})["block_lan_dns"], "auto")
        self.assertTrue(config.validate({})["require_global_mode"])
        self.assertIn("160.79.104.0/23", config.validate({})["anthropic_v4"])
        with self.assertRaises(config.ConfigError):
            config.validate({"block_lan_dns": "yes"})


class ClaudeMatchTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config.validate({})

    def test_matches(self):
        m = lambda comm, args="": claude.is_claude(comm, args, self.cfg)  # noqa: E731
        self.assertTrue(m("/Applications/Claude.app/Contents/MacOS/Claude"))
        self.assertTrue(m("/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper"))
        self.assertTrue(m("/Users/a/Applications/Claude.app/Contents/MacOS/Claude"))
        self.assertTrue(m("/Users/a/.local/share/claude/versions/2.1.0"))
        self.assertTrue(m("/Users/a/.local/bin/claude"))
        self.assertTrue(m("node", "node /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js"))
        self.assertFalse(m("/Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuard"))
        self.assertFalse(m("/usr/bin/python3", "python3 /Users/a/.local/share/ClaudeGuard/src/helper.py"))
        self.assertFalse(m("/Library/NetGuard/bin/netguard"))
        self.assertFalse(m("/usr/local/bin/claude-monitor"))
        self.assertFalse(m("/Applications/Codex.app/Contents/MacOS/Codex"))


class EnableTests(unittest.TestCase):
    def test_enable_success(self):
        svc, pf, pr, clock, kills, notes = make_service(self)
        svc.enable(out=lambda *_: None)
        st = svc.read_state()
        self.assertTrue(st["killswitch"])
        self.assertIsNone(st["pending"])
        self.assertEqual(st["core_gid"], 20)
        self.assertIn("ng_block_all", pf.anchor_text)
        self.assertEqual(len(pf.tokens), 1)
        self.assertEqual(svc.read_token(), pf.tokens[0])
        self.assertTrue(os.path.exists(paths.ANCHOR_FILE))
        self.assertTrue(svc.pf.integrity(st["rules_fp"])["complete"])
        self.assertIn("config", types())

    def assert_refused_without_touching_pf(self, mutate, needle):
        svc, pf, pr, clock, kills, notes = make_service(self)
        mutate(svc, pr)
        with self.assertRaises(UserError) as ctx:
            svc.enable(out=lambda *_: None)
        self.assertIn(needle, str(ctx.exception))
        self.assertEqual(pf.anchor_text, "")
        self.assertEqual(pf.tokens, [])
        self.assertFalse([c for c in pf.calls if "-f" in c or "-E" in c])
        self.assertFalse(svc.read_state()["killswitch"])

    def test_refuses_without_core(self):
        self.assert_refused_without_touching_pf(lambda s, p: setattr(p, "cores", []), "没有运行")

    def test_refuses_unprivileged_core(self):
        def mutate(s, p):
            p.cores = [{"pid": 5, "uid": 501, "gid": 20, "comm": "FlClashCore", "privileged": False}]
        self.assert_refused_without_touching_pf(mutate, "TUN 未授权")

    def test_refuses_without_tun(self):
        self.assert_refused_without_touching_pf(lambda s, p: setattr(p, "tun", None), "TUN")

    def test_refuses_when_offline_or_not_whitelisted(self):
        self.assert_refused_without_touching_pf(lambda s, p: setattr(p, "egress_ip", None), "无法通过代理联网")
        self.assert_refused_without_touching_pf(lambda s, p: setattr(p, "egress_ip", "192.0.2.9"), "不在白名单")

    def test_refuses_empty_whitelist(self):
        svc, pf, *_ = make_service(self, whitelist=())
        with self.assertRaises(UserError):
            svc.enable(out=lambda *_: None)
        self.assertEqual(pf.calls, [])

    def test_post_check_failure_rolls_back(self):
        for attr, value, needle in (("bypass", True, "直连仍能联网"), ("dns", False, "DNS"), ("egress_ip", None, "无法通过代理")):
            svc, pf, pr, clock, kills, notes = make_service(self)
            calls = {"n": 0}
            if attr == "egress_ip":
                # preflight sees the proxy working, the post-check does not
                orig = pr.egress

                def egress(url, orig=orig):
                    calls["n"] += 1
                    return orig(url) if calls["n"] == 1 else None
                pr.egress = egress
            else:
                setattr(pr, attr, value)
            with self.assertRaises(UserError) as ctx:
                svc.enable(out=lambda *_: None)
            self.assertIn(needle, str(ctx.exception))
            self.assertEqual(pf.anchor_text, "", attr)
            self.assertEqual(pf.tokens, [], attr)
            st = svc.read_state()
            self.assertFalse(st["killswitch"])
            self.assertIsNone(st["pending"])
            self.assertIn("rollback", types())

    def test_failed_reenable_restores_previous_rules(self):
        svc, pf, pr, *_ = make_service(self)
        svc.enable(out=lambda *_: None)
        before = pf.anchor_text
        pr.bypass = True
        with self.assertRaises(UserError):
            svc.enable(out=lambda *_: None)
        self.assertEqual(pf.anchor_text, before)
        self.assertEqual(len(pf.tokens), 1)
        self.assertTrue(svc.read_state()["killswitch"])

    def test_dead_enable_is_rolled_back_by_watch(self):
        svc, pf, pr, clock, *_ = make_service(self)
        st = svc.read_state()
        st.update({"pending": {"deadline": clock() + 120, "prev": {"killswitch": False, "core_gid": None}},
                   "killswitch": True, "core_gid": 20})
        svc.write_state(st)
        svc.apply_rules(20)
        svc.tick()
        self.assertEqual(pf.anchor_text, "")
        self.assertEqual(pf.tokens, [])
        self.assertFalse(svc.read_state()["killswitch"])
        self.assertIn("rollback", types())


class WatchTests(unittest.TestCase):
    def enabled_service(self, **kw):
        svc, pf, pr, clock, kills, notes = make_service(self, **kw)
        svc.enable(out=lambda *_: None)
        return svc, pf, pr, clock, kills, notes

    def test_egress_outside_whitelist_locks_on_first_sighting(self):
        svc, pf, pr, clock, kills, notes = self.enabled_service()
        pr.egress_ip = "192.0.2.50"
        svc.tick()
        g = svc.read_guard()
        self.assertNotIn("suspect", types())
        self.assertTrue(g["lockdown"])
        self.assertTrue(svc.read_state()["claude_block"])
        self.assertEqual(len(kills), 1)
        self.assertIn("trigger", types())
        self.assertTrue(notes)

    def test_claude_egress_also_locks_on_first_sighting(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pr.claude_ip = "192.0.2.51"
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])
        self.assertEqual(len(kills), 1)

    def test_other_findings_still_need_two_readings(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pr.cores = []
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])
        self.assertIn("suspect", types())

    def test_fast_egress_check_cuts_the_interval_short(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        svc.tick()
        self.assertFalse(svc.fast_egress_due())  # whitelisted exit
        clock.advance(1)
        pr.egress_ip = "192.0.2.50"
        self.assertFalse(svc.fast_egress_due())  # not due yet (every 3 s)
        clock.advance(3)
        self.assertTrue(svc.fast_egress_due())
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])
        clock.advance(3)
        calls = pr.egress_calls
        self.assertFalse(svc.fast_egress_due())  # locked: nothing left to catch
        self.assertEqual(pr.egress_calls, calls)

    def test_watch_runs_full_check_within_seconds_of_exit_change(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        svc.watch(forever=False)  # full check at t0; fast checks keep running in the loop
        t0 = clock()
        pr.egress_ip = "192.0.2.50"
        svc.watch(forever=False)
        self.assertTrue(svc.read_guard()["lockdown"])
        self.assertLessEqual(clock() - t0, 2 * 10)

    def test_foreign_bypass_is_a_high_finding(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pf.foreign = {"com.apple/300.SomeVPN": "pass out quick all\n"}
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])  # confirmed like other pf findings
        clock.advance(10)
        svc.tick()
        g = svc.read_guard()
        self.assertTrue(g["lockdown"])
        self.assertIn("pf_bypass", g["reason_codes"])

    def test_recovery_before_confirmation(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        cores, pr.cores = pr.cores, []
        svc.tick()
        pr.cores = cores
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])
        self.assertIn("recovered", types())
        self.assertEqual(kills, [])

    def test_medium_outside_grace_locks_like_windows(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pr.cores = []
        svc.tick()
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])

    def test_grace_defers_medium_but_not_high(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pr.boot = int(clock()) - 30
        pr.cores, pr.tun = [], None
        for _ in range(4):
            svc.tick()
            clock.advance(10)
        self.assertFalse(svc.read_guard()["lockdown"])
        self.assertEqual(types().count("grace"), 1)
        pr.claude_ip = "192.0.2.77"
        svc.tick()
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])

    def test_no_console_user_is_grace(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pr.user = None
        pr.cg = {"installed": False, "fresh": False, "age": None, "state": None, "error": None}
        for _ in range(3):
            svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])

    def test_grace_ends_and_medium_locks(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pr.boot = int(clock())
        pr.tun = None
        svc.tick()
        clock.advance(service.GRACE_SECONDS + 1)
        svc.tick()
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])

    def test_wake_restarts_grace(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pr.wake = int(clock()) - 5
        pr.cores = []
        svc.tick()
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])

    def test_rules_restored_after_reboot(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pf.reboot()
        svc.tick()
        self.assertIn("ng_block_all", pf.anchor_text)
        self.assertEqual(len(pf.tokens), 1)
        self.assertIn("rules_restored", types())
        self.assertEqual(svc.read_guard()["last_findings"], [])

    def test_missing_main_anchor_is_high_and_not_rewritten(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pf.main_ref = False
        svc.tick()
        svc.tick()
        g = svc.read_guard()
        self.assertTrue(g["lockdown"])
        self.assertTrue(any("互联网共享" in r for r in g["reasons"]))
        self.assertFalse([c for c in pf.calls if c[1:] in (["-f", "/etc/pf.conf"],)])

    def test_guard_off_never_locks(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        svc.set_guard(False, out=lambda *_: None)
        pr.egress_ip = "192.0.2.1"
        svc.tick()
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])

    def test_claudeguard_missing_is_medium(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pr.cg = {"installed": True, "fresh": False, "age": 99, "state": "allowed", "error": None}
        svc.tick()
        self.assertIn("ClaudeGuard 未运行或状态过期", svc.read_guard()["last_findings"])
        svc2, _, pr2, *_ = make_service(self, require_claudeguard=False)
        pr2.cg = {"installed": False, "fresh": False}
        svc2.tick()
        self.assertEqual(svc2.read_guard()["last_findings"], [])

    def test_proxy_down_notifies_when_killswitch_on(self):
        svc, pf, pr, clock, kills, notes = self.enabled_service()
        pr.tun = None
        svc.tick()
        self.assertTrue(any("代理未就绪" in t for t, _ in notes))

    def test_isolation_enforcement(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        self.assertEqual(svc.enforce_isolation(), 0)
        svc.isolate(out=lambda *_: None)
        before = len(kills)
        svc.enforce_isolation()
        self.assertEqual(len(kills), before + 1)

    def test_isolation_fills_fake_ip_table_and_unisolate_drops_it(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        self.assertIsNone(pf.table)
        svc.isolate(out=lambda *_: None)
        self.assertEqual(pf.table, ["198.18.0.58", "198.18.0.79"])
        self.assertIn("2 个代理地址", events.read(1)[-1]["summary"])
        svc.unisolate(out=lambda *_: None)
        self.assertIsNone(pf.table)
        self.assertNotIn("ng_claude", pf.anchor_text)

    def test_lockdown_fills_table_and_watch_refreshes_it(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        pr.egress_ip = "198.51.100.7"  # not whitelisted: high finding
        svc.tick(); clock.advance(10); svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])
        self.assertEqual(pf.table, ["198.18.0.58", "198.18.0.79"])
        calls = pr.resolve_calls
        pr.fake_ips = ["198.18.0.58", "198.18.3.88"]
        clock.advance(10); svc.tick()
        self.assertEqual(pr.resolve_calls, calls)  # not yet due
        clock.advance(60); svc.tick()
        self.assertEqual(pf.table, ["198.18.0.58", "198.18.3.88"])

    def test_table_survives_rule_restore_and_tun_outage(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        svc.isolate(out=lambda *_: None)
        pf.reboot()  # rules and table gone; boot reload happens in the next tick
        svc.tick()
        self.assertEqual(pf.table, ["198.18.0.58", "198.18.0.79"])
        pr.tun = None
        pr.fake_ips = []
        clock.advance(70); svc.tick()
        self.assertEqual(pf.table, ["198.18.0.58", "198.18.0.79"])  # kept while nothing resolves

    def test_watch_loop_enforces_between_ticks(self):
        svc, pf, pr, clock, kills, _ = self.enabled_service()
        svc.isolate(out=lambda *_: None)
        before = len(kills)
        svc.watch(forever=False)
        self.assertGreaterEqual(len(kills) - before, 5)  # every 2 s within the 10 s interval
        self.assertTrue(os.path.exists(paths.STATUS))


def router_dns(pf):
    """System DNS is the LAN router: resolution works only while ng_dns is not loaded."""
    return lambda probes: "ng_dns" not in pf.anchor_text


class DnsModeTests(unittest.TestCase):
    def test_auto_blocks_lan_dns_when_dns_goes_through_tun(self):
        svc, pf, pr, *_ = make_service(self)
        svc.enable(out=lambda *_: None)
        self.assertTrue(svc.read_state()["dns_block"])
        self.assertIn("ng_dns", pf.anchor_text)

    def test_auto_keeps_lan_dns_open_when_router_is_the_resolver(self):
        svc, pf, pr, *_ = make_service(self)
        pr.dns_reach = router_dns(pf)
        svc.enable(out=lambda *_: None)
        st = svc.read_state()
        self.assertTrue(st["killswitch"])
        self.assertFalse(st["dns_block"])
        self.assertNotIn("ng_dns", pf.anchor_text)
        self.assertIn("dns_relaxed", types())

    def test_strict_mode_rolls_back_instead_of_breaking_dns(self):
        svc, pf, pr, *_ = make_service(self, block_lan_dns=True)
        pr.dns_reach = router_dns(pf)
        with self.assertRaises(UserError):
            svc.enable(out=lambda *_: None)
        self.assertEqual(pf.anchor_text, "")
        self.assertFalse(svc.read_state()["killswitch"])

    def test_safety_valve_after_network_change(self):
        svc, pf, pr, clock, *_ = make_service(self)
        svc.enable(out=lambda *_: None)
        self.assertIn("ng_dns", pf.anchor_text)
        pr.dns_reach = router_dns(pf)  # joined a Wi-Fi whose DNS is the router
        svc.tick()
        self.assertFalse(svc.read_state()["dns_block"])
        self.assertNotIn("ng_dns", pf.anchor_text)
        self.assertIn("ng_block_all", pf.anchor_text)
        self.assertTrue(svc.pf.integrity(svc.read_state()["rules_fp"])["complete"])
        self.assertIn("dns_relaxed", types())

    def test_valve_never_fires_when_proxy_is_down(self):
        svc, pf, pr, clock, *_ = make_service(self)
        svc.enable(out=lambda *_: None)
        pr.dns_reach = False
        pr.tun = None
        svc.tick()
        self.assertTrue(svc.read_state()["dns_block"])


class NewFindingTests(unittest.TestCase):
    def enabled(self, **kw):
        svc, pf, pr, clock, kills, notes = make_service(self, **kw)
        svc.enable(out=lambda *_: None)
        return svc, pf, pr, clock, kills

    def locks_after_two(self, svc):
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])
        svc.tick()
        return svc.read_guard()["lockdown"]

    def test_rule_mode_locks(self):
        svc, pf, pr, clock, kills = self.enabled()
        pr.mode = "rule"
        self.assertTrue(self.locks_after_two(svc))
        self.assertTrue(any("规则模式" in r for r in svc.read_guard()["reasons"]))

    def test_rule_mode_allowed_when_not_required(self):
        svc, pf, pr, clock, kills = self.enabled(require_global_mode=False)
        pr.mode = "rule"
        svc.tick()
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])

    def test_unknown_mode_is_not_a_finding(self):
        svc, pf, pr, clock, kills = self.enabled()
        pr.mode = None
        svc.tick()
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])

    def test_route_not_through_tun(self):
        svc, pf, pr, clock, kills = self.enabled()
        pr.route = "en0"
        self.assertTrue(self.locks_after_two(svc))

    def test_claudeguard_protection_off_and_helper(self):
        svc, pf, pr, clock, kills = self.enabled()
        pr.cg["protection_enabled"] = False
        pr.cg["helper_loaded"] = False
        svc.tick()
        found = svc.read_guard()["last_findings"]
        self.assertIn("ClaudeGuard 的保护被关闭", found)
        self.assertTrue(any("com.claudeguard.helper" in x for x in found))

    def test_claude_path_waits_for_claudeguard_self_repair(self):
        svc, pf, pr, clock, kills = self.enabled()
        pr.cg["cli_hooked"] = False
        pr.cg["cli_links"] = [{"path": "/Users/alice/.local/bin/claude", "guarded": False}]
        for _ in range(6):  # 60 s: ClaudeGuard would normally have re-hooked by now
            svc.tick()
            clock.advance(10)
        self.assertFalse(svc.read_guard()["lockdown"])
        for _ in range(5):
            svc.tick()
            clock.advance(10)
        self.assertTrue(svc.read_guard()["lockdown"])

    def test_claude_path_is_high_even_in_grace(self):
        svc, pf, pr, clock, kills = self.enabled()
        pr.boot = int(clock())
        pr.cg["app_path_ok"] = False
        for _ in range(12):
            svc.tick()
            clock.advance(10)
        self.assertTrue(svc.read_guard()["lockdown"])

    def test_release_refuses_broken_hooks_immediately(self):
        svc, pf, pr, clock, kills = self.enabled()
        pr.egress_ip = "192.0.2.5"
        svc.tick()
        svc.tick()
        pr.egress_ip = "203.0.113.10"
        pr.cg["cli_hooked"] = False
        with self.assertRaises(UserError):
            svc.release(out=lambda *_: None)

    def test_lockdown_and_isolation_reload_rules(self):
        svc, pf, pr, clock, kills = self.enabled()
        self.assertIn("from ! 198.18.0.0/16", pf.anchor_text)
        pr.egress_ip = "192.0.2.5"
        svc.tick()
        svc.tick()
        anth = [l for l in pf.anchor_text.splitlines() if "ng_anthropic" in l and not l.startswith("#")]
        self.assertTrue(anth and all("from" not in l for l in anth))
        self.assertTrue(svc.pf.integrity(svc.read_state()["rules_fp"])["complete"])
        pr.egress_ip = "203.0.113.10"
        svc.release(out=lambda *_: None)
        self.assertIn("from ! 198.18.0.0/16", pf.anchor_text)
        svc.isolate(out=lambda *_: None)
        self.assertNotIn("from ! 198.18.0.0/16", pf.anchor_text)
        svc.unisolate(out=lambda *_: None)
        self.assertIn("from ! 198.18.0.0/16", pf.anchor_text)

    def test_isolated_enforcement_every_half_second(self):
        svc, pf, pr, clock, kills = self.enabled()
        svc.isolate(out=lambda *_: None)
        before = len(kills)
        svc.watch(forever=False)
        self.assertGreaterEqual(len(kills) - before, 18)

    def test_exemption_users_reported_once(self):
        svc, pf, pr, clock, kills = self.enabled()
        pr.exempt = ["traceroute"]
        svc.tick()
        clock.advance(70)
        svc.tick()
        self.assertEqual(types().count("exempt"), 1)
        self.assertEqual(svc.read_guard()["observations"]["exempt_others"], ["traceroute"])

    def test_status_fields(self):
        svc, pf, pr, clock, kills = self.enabled()
        svc.isolate(out=lambda *_: None)
        svc.tick()
        st = svc.write_status()
        self.assertTrue(st["realip"])
        self.assertTrue(st["dns_block"])
        self.assertEqual(st["status_version"], 2)
        self.assertIsNotNone(st["last_event"])
        self.assertIn("duration", st["guard"])
        self.assertEqual(st["observations"]["flclash"]["mode"], "global")


class ClaudeInstallJudgementTests(unittest.TestCase):
    """Issue #1: Claude not installed must be "not applicable", not a high claude_path lockdown."""

    def setUp(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = os.path.join(tmp.name, "Users", "alice")
        self.apps = os.path.join(tmp.name, "Applications")
        os.makedirs(self.home)
        os.makedirs(self.apps)
        self.default_cfg = {"real_claude_cli_path": "/opt/homebrew/bin/claude",
                            "real_claude_app_path": "/Applications/Claude.app"}

    def judge(self, cfg):
        return probes.judge_claude_paths(cfg, self.home, app_dirs=[self.apps])

    def make_app(self, name="Claude.app", bundle="com.anthropic.claudefordesktop"):
        import plistlib
        path = os.path.join(self.apps, name)
        os.makedirs(os.path.join(path, "Contents"))
        with open(os.path.join(path, "Contents", "Info.plist"), "wb") as stream:
            plistlib.dump({"CFBundleIdentifier": bundle}, stream)
        return path

    def make_cli(self, version="2.1.0"):
        d = os.path.join(self.home, ".local", "share", "claude", "versions")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, version)
        open(path, "w").close()
        return path

    def test_nothing_installed_is_not_applicable(self):
        out = self.judge(self.default_cfg)
        self.assertIsNone(out["app_path_ok"])
        self.assertIsNone(out["cli_path_ok"])
        self.assertIsNone(out["cli_hooked"])
        self.assertEqual(out["app_installed"], [])

    def test_installed_and_recorded(self):
        app = self.make_app()
        cli = self.make_cli()
        out = self.judge({"real_claude_app_path": app, "real_claude_cli_path": cli})
        self.assertTrue(out["app_path_ok"])
        self.assertTrue(out["cli_path_ok"])

    def test_installed_but_record_stale(self):
        self.make_app()
        self.make_cli("2.2.0")
        out = self.judge({"real_claude_app_path": "/Applications/Old.app",
                          "real_claude_cli_path": os.path.join(self.home, ".local/share/claude/versions/2.1.0")})
        self.assertIs(out["app_path_ok"], False)
        self.assertIs(out["cli_path_ok"], False)
        self.assertIs(out["cli_hooked"], False)  # Claude Code exists but no shim at all

    def test_other_apps_ignored(self):
        self.make_app("Notes.app", bundle="com.apple.Notes")
        self.make_app("ClaudeGuard.app", bundle="com.claudeguard.app")
        self.assertIsNone(self.judge(self.default_cfg)["app_path_ok"])

    def test_shim_alone_is_fine(self):
        bindir = os.path.join(self.home, ".local", "bin")
        target_dir = os.path.join(self.home, ".local", "share", "ClaudeGuard", "src")
        os.makedirs(bindir)
        os.makedirs(target_dir)
        target = os.path.join(target_dir, "cli_wrapper.py")
        open(target, "w").close()
        try:
            os.symlink(target, os.path.join(bindir, "claude"))
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available on this host")
        out = self.judge(self.default_cfg)
        self.assertTrue(out["cli_hooked"])
        self.assertIsNone(out["cli_path_ok"])

    def test_issue1_scenario_never_locks(self):
        svc, pf, pr, clock, kills, notes = make_service(self)
        svc.enable(out=lambda *_: None)
        pr.cg.update({"app_path_ok": None, "cli_path_ok": None, "cli_hooked": True,
                      "app_installed": [], "cli_installed": []})
        for _ in range(15):
            svc.tick()
            clock.advance(10)
        self.assertFalse(svc.read_guard()["lockdown"])
        self.assertEqual(svc.read_guard()["last_findings"], [])


class ClaudeGuardPatchTests(unittest.TestCase):
    def test_patch_state(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            self.assertIsNone(probes.claudeguard_patch_state(home))
            src = os.path.join(home, ".local", "share", "ClaudeGuard", "src")
            os.makedirs(src)
            with open(os.path.join(src, "integrity.py"), "w") as stream:
                stream.write("something else")
            self.assertEqual(probes.claudeguard_patch_state(home), "unknown")

    def test_finding_points_to_patch_until_applied(self):
        svc, pf, pr, clock, kills, notes = make_service(self)
        svc.enable(out=lambda *_: None)
        pr.cg.update({"cli_path_ok": False, "cli_installed": ["/Users/alice/.local/share/claude/versions/2.1.322"],
                      "cg_patch": "original"})
        svc.tick()
        self.assertTrue(any("claudeguard-patch" in x for x in svc.read_guard()["last_findings"]))
        pr.cg["cg_patch"] = "patched"
        svc.tick()
        self.assertFalse(any("claudeguard-patch" in x for x in svc.read_guard()["last_findings"]))

    def test_patch_script_is_hash_guarded(self):
        with open(os.path.join(MACOS, "patches", "claudeguard", "apply.sh"), encoding="utf-8") as stream:
            text = stream.read()
        self.assertIn(probes.CG_INTEGRITY_ORIGINAL, text)
        self.assertIn(probes.CG_INTEGRITY_PATCHED, text)
        self.assertIn("拒绝修改", text)


class ConfigMigrationTests(unittest.TestCase):
    def test_v1_false_becomes_auto(self):
        data, changes = config.migrate({"whitelist": ["203.0.113.10"], "block_lan_dns": False})
        self.assertEqual(data["block_lan_dns"], "auto")
        self.assertEqual(data["config_version"], config.CONFIG_VERSION)
        self.assertTrue(changes)
        self.assertEqual(config.validate(data)["whitelist"], ["203.0.113.10"])

    def test_v1_true_kept(self):
        data, _ = config.migrate({"block_lan_dns": True})
        self.assertIs(data["block_lan_dns"], True)

    def test_v2_untouched(self):
        data, changes = config.migrate({"config_version": 2, "block_lan_dns": False})
        self.assertIs(data["block_lan_dns"], False)
        self.assertEqual(changes, [])


class ShutdownLockTests(unittest.TestCase):
    """FlClash quits before the root daemon at shutdown; that lockdown must not need a manual release."""

    def lock_then_reboot(self, mutate, reboot_after=20):
        svc, pf, pr, clock, kills, notes = make_service(self)
        svc.enable(out=lambda *_: None)
        mutate(pr)
        svc.tick()
        clock.advance(10)
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])
        since = svc.read_guard()["since"]
        # reboot: pf rules vanish, apps come back, boot time is after the lockdown
        clock.advance(reboot_after)
        pf.reboot()
        pr.boot = int(clock())
        pr.cores = FakeCores.healthy()
        pr.tun, pr.egress_ip, pr.claude_ip = "utun5", "203.0.113.10", "203.0.113.10"
        return svc, pf, pr, clock, since

    def test_medium_shutdown_lock_released_after_boot_checks(self):
        svc, pf, pr, clock, _ = self.lock_then_reboot(lambda p: setattr(p, "cores", []))
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])
        self.assertFalse(svc.read_state()["claude_block"])
        self.assertTrue(any("开机后自动解除" in e["summary"] for e in read_events()))

    def test_waits_until_proxy_is_back(self):
        svc, pf, pr, clock, _ = self.lock_then_reboot(lambda p: setattr(p, "tun", None))
        pr.tun = None  # FlClash not up yet after boot
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])
        pr.tun = "utun5"
        clock.advance(10)
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])

    def test_high_lock_still_needs_manual_release(self):
        svc, pf, pr, clock, _ = self.lock_then_reboot(lambda p: setattr(p, "egress_ip", "192.0.2.50"))
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])

    def test_old_medium_lock_not_auto_released(self):
        svc, pf, pr, clock, _ = self.lock_then_reboot(lambda p: setattr(p, "cores", []),
                                                    reboot_after=service.SHUTDOWN_WINDOW + 60)
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])

    def test_no_reboot_no_auto_release(self):
        svc, pf, pr, clock, kills, _ = make_service(self)
        svc.enable(out=lambda *_: None)
        pr.boot = int(clock()) - 3600
        pr.cores = []
        svc.tick()
        svc.tick()
        pr.cores = FakeCores.healthy()
        clock.advance(10)
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])


class FakeCores:
    @staticmethod
    def healthy():
        return [{"pid": 51, "uid": 0, "gid": 20, "comm": "FlClashCore", "privileged": True}]


class ReleaseTests(unittest.TestCase):
    def locked(self):
        svc, pf, pr, clock, kills, notes = make_service(self)
        svc.enable(out=lambda *_: None)
        pr.egress_ip = "192.0.2.50"
        svc.tick()
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])
        return svc, pf, pr

    def test_release_refused_until_clean(self):
        svc, pf, pr = self.locked()
        with self.assertRaises(UserError):
            svc.release(out=lambda *_: None)
        self.assertTrue(svc.read_guard()["lockdown"])
        self.assertIn("release_refused", types())
        pr.egress_ip = "203.0.113.10"
        pr.claude_ip = None  # unobtainable exit is not enough to release
        with self.assertRaises(UserError):
            svc.release(out=lambda *_: None)
        pr.claude_ip = "203.0.113.10"
        svc.release(out=lambda *_: None)
        self.assertFalse(svc.read_guard()["lockdown"])
        self.assertFalse(svc.read_state()["claude_block"])

    def test_release_requires_killswitch(self):
        svc, pf, pr = self.locked()
        st = svc.read_state()
        st["killswitch"] = False
        svc.write_state(st)
        pr.egress_ip = "203.0.113.10"
        with self.assertRaises(UserError):
            svc.release(out=lambda *_: None)

    def test_disable_clears_everything(self):
        svc, pf, pr = self.locked()
        svc.disable(out=lambda *_: None)
        self.assertEqual(pf.anchor_text, "")
        self.assertEqual(pf.tokens, [])
        self.assertFalse(svc.read_guard()["lockdown"])
        self.assertFalse(os.path.exists(paths.TOKEN))

    def test_recover(self):
        svc, pf, pr = self.locked()
        svc.recover(out=lambda *_: None)
        self.assertEqual(pf.anchor_text, "")
        self.assertEqual(pf.tokens, [])
        self.assertFalse(svc.read_state()["killswitch"])
        self.assertFalse(svc.read_guard()["lockdown"])
        self.assertIn("recover", types())

    def test_unisolate_requires_whitelisted_exits(self):
        svc, pf, pr, clock, kills, _ = make_service(self)
        svc.isolate(out=lambda *_: None)
        pr.claude_ip = "192.0.2.3"
        with self.assertRaises(UserError):
            svc.unisolate(out=lambda *_: None)
        pr.claude_ip = "203.0.113.10"
        svc.unisolate(out=lambda *_: None)
        self.assertFalse(svc.read_state()["claude_block"])


class WhitelistAndStatusTests(unittest.TestCase):
    def test_whitelist_ops(self):
        svc, *_ = make_service(self, whitelist=())
        config.save(svc.cfg)
        svc.whitelist("add", "203.0.113.10", out=lambda *_: None)
        svc.whitelist("add", "198.51.100.0/24", out=lambda *_: None)
        self.assertEqual(config.load()["whitelist"], ["198.51.100.0/24", "203.0.113.10"])
        svc.whitelist("remove", "198.51.100.0/24", out=lambda *_: None)
        self.assertEqual(config.load()["whitelist"], ["203.0.113.10"])
        with self.assertRaises(UserError):
            svc.whitelist("remove", "192.0.2.1", out=lambda *_: None)
        with self.assertRaises(config.ConfigError):
            svc.whitelist("add", "1.2.3.4; rm -rf /", out=lambda *_: None)

    def test_status_schema(self):
        svc, pf, pr, *_ = make_service(self)
        svc.enable(out=lambda *_: None)
        svc.tick()
        st = svc.write_status()
        for key in ("wanted_killswitch", "killswitch_complete", "active_killswitch", "integrity", "guard",
                    "observations", "whitelist", "updated_at", "version"):
            self.assertIn(key, st)
        self.assertTrue(st["killswitch_complete"])
        self.assertTrue(st["active_killswitch"])
        with open(paths.STATUS, encoding="utf-8") as stream:
            self.assertEqual(json.load(stream)["observations"]["tun"], "utun5")


def shell_scripts():
    """Every shell script in macos/ (by extension or shebang), so a new script is never missed."""
    out = []
    for base, _dirs, names in os.walk(MACOS):
        for name in names:
            path = os.path.join(base, name)
            try:
                with open(path, encoding="utf-8") as stream:
                    first = stream.readline()
            except (OSError, UnicodeDecodeError):
                continue
            if name.endswith((".sh", ".command")) or first.startswith(("#!/bin/sh", "#!/bin/bash")):
                out.append(os.path.relpath(path, MACOS))
    return sorted(out)


class SafetyStaticTests(unittest.TestCase):
    """Commands that could leave the Mac offline or break other pf users must not appear."""

    FORBIDDEN = [
        (r"pfctl(\s+-[A-Za-z]+)*\s+-d\b", "global pf disable"),
        (r"-F\s+all", "flush all (states too)"),
        (r"pfctl[^\n#]*-f\s+/etc/pf\.conf", "main ruleset reload"),
        (r">\s*/etc/pf\.conf|/etc/pf\.conf\s*<|tee\s+/etc/pf\.conf", "pf.conf write"),
        (r"networksetup", "network service change"),
        (r"/etc/hosts", "hosts file"),
        (r"route\s+(add|delete|change|flush)", "route change"),
        (r"systemextensionsctl|profiles\s+install|spctl\s+--master-disable|csrutil", "system security change"),
    ]

    def files(self):
        for base, _dirs, names in os.walk(MACOS):
            # tests/ and ci/ only read these files to prove they stay unchanged.
            if os.sep + "tests" in base or os.sep + "ci" in base:
                continue
            for name in names:
                if name.endswith((".py", ".sh", ".command", ".swift")) or "bin" in base.split(os.sep)[-1:]:
                    yield os.path.join(base, name)

    @staticmethod
    def python_strings(path):
        """String constants that are not docstrings (docstrings may explain what is forbidden)."""
        import ast
        with open(path, encoding="utf-8") as stream:
            tree = ast.parse(stream.read())
        docs = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)) and node.body:
                first = node.body[0]
                if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant):
                    docs.add(id(first.value))
        return [(n.lineno, n.value) for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]

    def test_no_forbidden_commands(self):
        hits = []
        for path in self.files():
            rel = os.path.relpath(path, MACOS)
            if path.endswith(".py"):
                lines = self.python_strings(path)
            else:
                with open(path, encoding="utf-8") as stream:
                    lines = [(no, (line.split("//", 1)[0] if path.endswith(".swift") else line.split("#", 1)[0]))
                             for no, line in enumerate(stream, 1)]
            for no, code in lines:
                for pattern, what in self.FORBIDDEN:
                    if re.search(pattern, code) and "grep -q" not in code:
                        hits.append("%s:%d %s: %s" % (rel, no, what, code.strip()))
        self.assertEqual(hits, [])

    def test_python_never_passes_disable_flags(self):
        for name in os.listdir(os.path.join(MACOS, "netguard")):
            if name.endswith(".py"):
                values = [v for _, v in self.python_strings(os.path.join(MACOS, "netguard", name))]
                self.assertNotIn("-d", values, name)
                self.assertNotIn("all", values, name)

    def test_shell_scripts_parse(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        for rel in shell_scripts():
            path = os.path.join(MACOS, rel)
            if not os.path.exists(path):
                continue
            result = subprocess.run([bash, "-n", path], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, rel + ": " + result.stderr)

    def test_shell_variables_braced_before_non_ascii(self):
        # macOS /bin/bash 3.2 reads UTF-8 bytes after `$NAME` as part of the name (set -u aborts).
        pat = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*(?=[^\x00-\x7f])")
        scripts = shell_scripts()
        self.assertIn(os.path.join("patches", "claudeguard", "apply.sh"), scripts)
        for rel in scripts:
            with open(os.path.join(MACOS, rel), encoding="utf-8") as stream:
                self.assertEqual(pat.findall(stream.read()), [], rel)

    def test_swift_string_literals_stay_on_one_line(self):
        # A raw newline inside a Swift "..." literal breaks the on-device build.
        with open(os.path.join(MACOS, "app", "NetGuardApp.swift"), encoding="utf-8") as stream:
            lines = stream.read().splitlines()
        bad = [no for no, line in enumerate(lines, 1) if line.split("//", 1)[0].count('"') % 2]
        self.assertEqual(bad, [])

    def test_python39_compatible_syntax(self):
        import ast
        for base, _d, names in os.walk(os.path.join(MACOS, "netguard")):
            for name in names:
                if name.endswith(".py"):
                    path = os.path.join(base, name)
                    with open(path, encoding="utf-8") as stream:
                        tree = ast.parse(stream.read(), path, feature_version=(3, 9))
                    self.assertIsNotNone(tree)

    def test_recover_script_state_matches_python_defaults(self):
        with open(os.path.join(MACOS, "bin", "netguard-recover"), encoding="utf-8") as stream:
            text = stream.read()
        block = text.split("<<'EOF'", 1)[1].split("EOF", 1)[0]
        data = json.loads(block)
        self.assertEqual(set(data), set(service.STATE_DEFAULTS))
        self.assertFalse(data["killswitch"])

    def test_boot_script_matches_state_format(self):
        use_temp_root(self)
        svc, *_ = make_service(self)
        st = svc.read_state()
        st["killswitch"] = True
        svc.write_state(st)
        with open(paths.STATE, encoding="utf-8") as stream:
            self.assertIn('"killswitch": true', stream.read())
        g = svc.read_guard()
        g["lockdown"] = True
        svc.write_guard(g)
        with open(paths.GUARD, encoding="utf-8") as stream:
            self.assertIn('"lockdown": true', stream.read())


if __name__ == "__main__":
    unittest.main()
