"""Self-driven proxy-down drill: verdicts for pass, leak, TUN that never stops, and rescue."""
import os
import unittest

from fakes import make_service

from netguard import drill as drill_mod
from netguard.drill import Drill, DrillAbort


class FakeDrill(Drill):
    """Simulates FlClash quitting/reopening on a fake clock; the real Service decides lockdown."""

    def __init__(self, svc, pr, clock, tun_stops=True, comes_back=True, leak_ip=None):
        super().__init__(svc, out=lambda *_: None, clock=clock, sleep=self._sleep,
                         log_path=os.devnull)
        self.pr, self.fclock = pr, clock
        self.tun_stops, self.comes_back, self.leak_ip = tun_stops, comes_back, leak_ip
        self.opened = self.recovered = False
        self.next_tick = clock() + 10

    def _sleep(self, s):
        self.fclock.advance(s)
        while self.fclock() >= self.next_tick:  # the daemon keeps ticking every 10 s
            self.svc.tick()
            self.next_tick += 10

    def quit_flclash(self):
        if self.tun_stops:
            self.pr.tun, self.pr.cores = None, []

    def stop_core(self):
        pass

    def open_flclash(self):
        self.opened = True
        if self.comes_back:
            self.pr.tun = "utun5"
            self.pr.cores = [{"pid": 9, "uid": 0, "gid": 20, "comm": "FlClashCore", "privileged": True}]

    def gateway(self):
        return "192.168.1.1"

    def gateway_probe(self, gw):
        return True

    def public_probe(self):
        if self.pr.tun:
            return True, "203.0.113.10"
        if self.leak_ip:
            return True, self.leak_ip
        return False, None

    def recover(self):
        self.recovered = True


def ready(test):
    svc, pf, pr, clock, kills, notes = make_service(test)
    svc.enable(out=lambda *_: None)
    return svc, pr, clock


class DrillTests(unittest.TestCase):
    def test_pass(self):
        svc, pr, clock = ready(self)
        r = FakeDrill(svc, pr, clock).run()
        self.assertTrue(r["passed"], r)
        self.assertEqual(r["public_succeeded_while_down"], 0)
        self.assertLessEqual(r["lockdown_after_seconds"], 40)
        self.assertFalse(r["rescued"])
        self.assertTrue(svc.read_guard()["lockdown"])  # left for acceptance item 4 (release)

    def test_leak_fails(self):
        svc, pr, clock = ready(self)
        r = FakeDrill(svc, pr, clock, leak_ip="198.51.100.77").run()
        self.assertFalse(r["passed"])
        self.assertGreater(r["real_ip_leaks"], 0)

    def test_tun_that_never_stops_is_reported_not_passed(self):
        svc, pr, clock = ready(self)
        d = FakeDrill(svc, pr, clock, tun_stops=False)
        with self.assertRaises(DrillAbort):
            d.run()
        self.assertTrue(d.opened)

    def test_rescue_when_proxy_does_not_return(self):
        svc, pr, clock = ready(self)
        d = FakeDrill(svc, pr, clock, comes_back=False)
        r = d.run()
        self.assertTrue(d.recovered)
        self.assertTrue(r["rescued"])
        self.assertFalse(r["passed"])

    def test_refuses_in_grace_or_lockdown(self):
        svc, pr, clock = ready(self)
        pr.boot = int(clock())
        with self.assertRaises(DrillAbort):
            FakeDrill(svc, pr, clock).run()
        pr.boot = 0
        g = svc.read_guard()
        g["lockdown"] = True
        svc.write_guard(g)
        with self.assertRaises(DrillAbort):
            FakeDrill(svc, pr, clock).run()

    def test_refuses_without_killswitch(self):
        svc, pf, pr, clock, kills, notes = make_service(self)
        with self.assertRaises(DrillAbort):
            FakeDrill(svc, pr, clock).run()

    def test_timing_constants_are_safe(self):
        self.assertLessEqual(drill_mod.RECOVER_SECONDS, 300)
        self.assertGreaterEqual(drill_mod.DOWN_SECONDS, 30)


if __name__ == "__main__":
    unittest.main()
