"""proxy_down = "direct": other programs may use the real IP when the proxy is off, Claude may not."""
import unittest

from fakes import make_service

from netguard import config, events, pfrules, service
from netguard.service import UserError

AUX = ["23.239.4.93", "2600:3c01::1", "34.120.108.227"]


def types():
    return [e["type"] for e in events.read(1000)]


def direct_service(testcase, **kw):
    svc, pf, pr, clock, kills, notes = make_service(testcase, proxy_down="direct", **kw)
    svc._spawn = lambda fn: fn()  # resolve synchronously in tests
    svc.sleep = lambda s: None
    return svc, pf, pr, clock, kills, notes


def enabled(testcase, **kw):
    svc, pf, pr, clock, kills, notes = direct_service(testcase, **kw)
    config.save(svc.cfg)
    svc.enable(out=lambda *_: None)
    return svc, pf, pr, clock, kills, notes


class RenderTests(unittest.TestCase):
    def test_direct_rules(self):
        cfg = config.validate({})
        text = pfrules.render(cfg, 0, 20, direct=True, direct_block=["34.120.108.227", "2600:3c01::1"])
        self.assertNotIn("ng_block_all", text)
        self.assertNotIn("ng_core", text)
        self.assertIn('block return out quick inet from ! 198.18.0.0/16 to { 160.79.104.0/23, 153.61.224.0/22 }', text)
        self.assertIn("table <ng_direct> persist { 2600:3c01::1, 34.120.108.227 }", text)
        self.assertIn('block return out quick inet from ! 198.18.0.0/16 to <ng_direct> label "ng_direct_block"', text)
        self.assertIn('block return out quick inet6 from ! fdfe:dcba:9876::/48 to <ng_direct>', text)
        rules = [l for l in text.splitlines() if l and not l.startswith("#")]
        self.assertEqual(rules[-1], 'pass out all keep state label "ng_direct"')  # last match: the rest goes direct

    def test_isolated_direct_rules_refuse_the_tun_too(self):
        text = pfrules.render(config.validate({}), 0, 20, isolate=True, direct=True, direct_block=AUX)
        self.assertIn('block return out quick inet to <ng_direct> label "ng_direct_block"', text)
        self.assertIn("table <ng_claude> persist", text)

    def test_empty_table_is_still_declared(self):
        text = pfrules.render(config.validate({}), 0, 20, direct=True)
        self.assertIn("table <ng_direct> persist\n", text + "\n")


class EnableTests(unittest.TestCase):
    def test_enable_fills_table_and_proves_it_blocks(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        st = svc.read_state()
        self.assertTrue(st["killswitch"] and st["direct"])
        self.assertFalse(st["dns_block"])  # the router is the only resolver with the proxy off
        self.assertEqual(sorted(st["direct_block"]), AUX)  # 160.79.104.10 is already covered by the ranges
        self.assertEqual(pf.direct, AUX)  # canary removed again
        self.assertEqual(pf.direct_ops[:2], [["add", "1.0.0.1"], ["delete", "1.0.0.1"]][:len(pf.direct_ops[:2])])
        self.assertIn(["add", "1.0.0.1"], pf.direct_ops)
        self.assertIn(["delete", "1.0.0.1"], pf.direct_ops)
        self.assertTrue(svc.integrity(st)["complete"])
        self.assertEqual(st["direct_check"]["moved"], [])

    def test_canary_leak_rolls_back(self):
        svc, pf, pr, clock, kills, notes = direct_service(self)
        pr.bypass = True
        with self.assertRaises(UserError):
            svc.enable(out=lambda *_: None)
        st = svc.read_state()
        self.assertFalse(st["killswitch"])
        self.assertFalse(st["direct"])
        self.assertEqual(pf.anchor_text, "")

    def test_table_flushed_by_someone_else_is_restored(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        pf.direct = []
        svc.tick()
        self.assertEqual(pf.direct, AUX)
        self.assertIn("rules_restored", types())


class ProxyDownTests(unittest.TestCase):
    def test_proxy_off_isolates_claude_at_once_without_probing_the_real_ip(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        calls = getattr(pr, "egress_calls", 0)
        pr.tun = None
        svc.tick()
        g = svc.read_guard()
        self.assertTrue(g["lockdown"])
        self.assertEqual(g["reason_codes"], ["proxy_down"])
        self.assertTrue(svc.read_state()["claude_block"])
        self.assertEqual(len(kills), 1)
        self.assertEqual(getattr(pr, "egress_calls", 0), calls)
        self.assertFalse(any("代理未就绪" in t for t, _ in notes))
        self.assertIn("ng_claude", pf.anchor_text)  # isolated: Anthropic refused through the TUN too

    def test_proxy_off_isolates_even_inside_the_boot_grace_period(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        pr.boot = int(clock()) - 10
        pr.tun = None
        pr.cores = []
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])

    def test_proxy_back_and_all_checks_pass_releases_automatically(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        pr.tun = None
        svc.tick()
        clock.advance(10)
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])  # still off: stays isolated
        pr.tun = "utun5"
        clock.advance(10)
        svc.tick()
        self.assertFalse(svc.read_guard()["lockdown"])
        self.assertFalse(svc.read_state()["claude_block"])
        self.assertIn("release", types())
        self.assertTrue(any("代理已恢复" in t for t, _ in notes))

    def test_proxy_back_on_a_wrong_exit_stays_locked(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        pr.tun = None
        svc.tick()
        pr.tun = "utun5"
        pr.egress_ip = pr.claude_ip = "192.0.2.9"
        clock.advance(10)
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])

    def test_other_lockdowns_are_not_lifted_automatically(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        pr.egress_ip = "192.0.2.9"
        svc.tick()
        self.assertEqual(svc.read_guard()["reason_codes"], ["egress"])
        pr.egress_ip = "203.0.113.10"
        clock.advance(10)
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])  # needs a manual release, as before

    def test_fast_check_notices_the_proxy_going_away(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        svc.tick()
        clock.advance(4)
        self.assertFalse(svc.fast_egress_due())
        pr.tun = None
        clock.advance(4)
        self.assertTrue(svc.fast_egress_due())

    def test_strict_mode_does_not_resolve_or_auto_release(self):
        svc, pf, pr, clock, kills, notes = make_service(self)
        svc._spawn = lambda fn: fn()
        svc.enable(out=lambda *_: None)
        pr.tun = None
        svc.tick(); clock.advance(200); svc.tick(); svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])
        self.assertEqual(svc.read_guard()["reason_codes"], ["tun"])
        pr.tun = "utun5"
        clock.advance(10)
        svc.tick()
        self.assertTrue(svc.read_guard()["lockdown"])
        self.assertFalse(getattr(pr, "resolve_public_calls", []))
        self.assertIn("ng_block_all", pf.anchor_text)


class HostTableTests(unittest.TestCase):
    def test_main_host_outside_the_ranges_is_blocked_and_locks(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        pr.public_answers = {"claude.ai": ["160.79.104.10", "198.51.100.44"], "assets.claude.ai": ["34.120.108.227"]}
        clock.advance(service.DIRECT_REFRESH + 1)
        svc.tick()  # resolves (in a thread; synchronously in tests)
        svc.tick()  # the next check loads the result into the table
        self.assertIn("198.51.100.44", pf.direct)
        self.assertEqual(svc.read_state()["direct_check"]["moved"], ["198.51.100.44"])
        clock.advance(10)
        svc.tick()
        g = svc.read_guard()
        self.assertTrue(g["lockdown"])
        self.assertIn("anthropic_moved", g["reason_codes"])

    def test_proxy_off_resolves_with_the_system_resolver(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        svc.tick()
        pr.tun = None
        pr.public_answers = {"assets.claude.ai": ["34.120.108.99"]}  # a CDN answering by location
        svc.tick()
        clock.advance(10)
        svc.tick()
        self.assertEqual(pr.resolve_public_calls[-1], "system")
        self.assertIn("34.120.108.99", pf.direct)

    def test_old_addresses_expire(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        pr.public_answers = {"assets.claude.ai": ["34.120.108.227"]}
        clock.advance(service.DIRECT_KEEP + 1)
        svc.tick()
        svc.tick()
        self.assertEqual(sorted(svc.read_state()["direct_block"]), ["34.120.108.227"])
        self.assertEqual(pf.direct, ["34.120.108.227"])

    def test_no_resolution_right_after_enable(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        calls = len(pr.resolve_public_calls)
        svc.tick()
        self.assertEqual(len(pr.resolve_public_calls), calls)  # enable just resolved

    def test_failed_resolution_keeps_the_table(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        pr.public_answers = {}
        clock.advance(service.DIRECT_REFRESH + 1)
        svc.tick()
        svc.tick()
        self.assertEqual(pf.direct, AUX)
        calls = len(pr.resolve_public_calls)
        svc.tick()
        self.assertEqual(len(pr.resolve_public_calls), calls)  # no retry storm after a failure


class SwitchAndVerifyTests(unittest.TestCase):
    def test_switch_modes_while_enabled(self):
        svc, pf, pr, clock, kills, notes = make_service(self)
        svc._spawn = lambda fn: fn()
        config.save(svc.cfg)
        svc.enable(out=lambda *_: None)
        self.assertIn("ng_block_all", pf.anchor_text)
        svc.set_proxy_down("direct", out=lambda *_: None)
        self.assertIn('label "ng_direct"', pf.anchor_text)
        self.assertNotIn("ng_block_all", pf.anchor_text)
        self.assertEqual(config.load()["proxy_down"], "direct")
        svc.set_proxy_down("block", out=lambda *_: None)
        self.assertIn("ng_block_all", pf.anchor_text)
        self.assertFalse(svc.read_state()["direct"])

    def test_failed_switch_restores_setting_and_rules(self):
        svc, pf, pr, clock, kills, notes = make_service(self)
        svc._spawn = lambda fn: fn()
        config.save(svc.cfg)
        svc.enable(out=lambda *_: None)
        pr.bypass = True  # the canary self-test fails
        with self.assertRaises(UserError):
            svc.set_proxy_down("direct", out=lambda *_: None)
        self.assertEqual(config.load()["proxy_down"], "block")
        self.assertIn("ng_block_all", pf.anchor_text)
        self.assertTrue(svc.read_state()["killswitch"])

    def test_cleanup_setting(self):
        svc, *_ = make_service(self)
        config.save(svc.cfg)
        svc.set_cleanup("desktop", out=lambda *_: None)
        self.assertEqual(config.load()["claude_cleanup"], "desktop")
        self.assertEqual(svc.engine.cfg["claude_cleanup"], "desktop")
        with self.assertRaises(UserError):
            svc.set_cleanup("everything", out=lambda *_: None)

    def test_foreign_permits_in_direct_mode(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        pf.foreign = {"com.apple/zzz.Late": "pass out all\n"}  # after NetGuard, not quick
        self.assertEqual(svc.foreign_permits(direct=True), [])
        pf.foreign = {"com.apple/100.Early": "pass out quick all\n"}  # before NetGuard and quick
        self.assertEqual(len(svc.foreign_permits(direct=True)), 1)

    def test_verify(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        lines = []
        self.assertTrue(svc.verify(out=lines.append), "\n".join(lines))
        text = "\n".join(lines)
        self.assertIn("Claude 主站解析在 Anthropic 网段内", text)
        self.assertIn("绑定 en0 访问拦截表中的地址被拒绝", text)
        self.assertNotIn("放行身份", text)
        pr.bypass = True
        self.assertFalse(svc.verify(out=lambda *_: None))
        self.assertEqual(pf.direct, AUX)  # canary always removed

    def test_disable_leaves_no_table_behind(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        svc.disable(out=lambda *_: None)
        self.assertIsNone(pf.direct)
        self.assertEqual(pf.anchor_text, "")

    def test_status_reports_mode(self):
        svc, pf, pr, clock, kills, notes = enabled(self)
        st = svc.write_status()
        self.assertTrue(st["direct"])
        self.assertEqual(st["proxy_down"], "direct")
        self.assertEqual(st["direct_block"], 3)


if __name__ == "__main__":
    unittest.main()
