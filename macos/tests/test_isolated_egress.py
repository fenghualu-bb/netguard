"""Isolation must remain enforced until the same Claude HTTPS exit is verified."""
import os
import subprocess
import tempfile
import unittest

from fakes import make_service
from netguard import config, paths
from netguard.probes import Probes
from netguard.service import UserError


class IsolatedProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, 'config.yaml')
        self.calls = []
        self.owner = 'p50\nu0\n'
        self.curl_rc = 0
        self.curl_body = 'ip=203.0.113.10\n'
        self.probe = Probes(config.validate({}), runner=self.run_fake)
        self.probe.flclash_config = lambda: {'source': 'config.yaml', 'path': self.path}
        self.probe.find_core = lambda: [{'pid': 50, 'uid': 0, 'gid': 20, 'privileged': True}]
        self.write('mixed-port: 7890\nsocks-port: 0\n')

    def write(self, text):
        with open(self.path, 'w') as stream:
            stream.write(text)

    def run_fake(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[0] == '/usr/sbin/lsof':
            return subprocess.CompletedProcess(argv, 0, self.owner, '')
        self.assertEqual(argv[0], paths.CURL)
        return subprocess.CompletedProcess(argv, self.curl_rc, self.curl_body, '')

    def test_same_https_endpoint_through_verified_loopback_socks(self):
        url = self.probe.cfg['claude_check_url']
        self.assertEqual(self.probe.claude_egress(url, isolated=True), '203.0.113.10')
        self.assertIn('-iTCP:7890', self.calls[0])
        curl = self.calls[1]
        self.assertEqual(curl[-1], url)
        self.assertEqual(curl[curl.index('--socks5-hostname') + 1], '127.0.0.1:7890')
        self.assertEqual(curl[curl.index('--noproxy') + 1], '')
        self.assertEqual(curl[1], '-q')  # .curlrc cannot weaken TLS or redirect this probe
        self.assertNotIn('-k', curl)
        self.assertNotIn('--insecure', curl)

    def test_unisolated_egress_still_uses_direct_tun_probe(self):
        self.assertEqual(self.probe.claude_egress('https://claude.ai/cdn-cgi/trace'), '203.0.113.10')
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn('--socks5-hostname', self.calls[0])
        self.assertEqual(self.calls[0][self.calls[0].index('--noproxy') + 1], '*')

    def test_untrusted_or_ambiguous_listener_never_gets_a_request(self):
        for owner in ('', 'p60\nu501\n', 'p50\nu501\n', 'p50\n',
                      'p50\nu0\np60\nu501\n', 'p60\nu0\n'):
            with self.subTest(owner=owner):
                self.owner = owner
                self.calls.clear()
                self.assertIsNone(self.probe.claude_egress('https://claude.ai/', isolated=True))
                self.assertFalse(any(c[0] == paths.CURL for c in self.calls))

    def test_missing_or_unprivileged_core_fails_closed(self):
        for cores in ([], [{'pid': 50, 'privileged': False}]):
            self.probe.find_core = lambda: cores
            self.assertIsNone(self.probe.claude_egress('https://claude.ai/', isolated=True))
        self.assertEqual(self.calls, [])

    def test_ports_are_validated_and_cannot_supply_remote_proxy(self):
        for yaml in ('mixed-port: -1\n', 'mixed-port: 65536\n', 'mixed-port: example.com:7890\n',
                     'mixed-port: 7890\nmixed-port: 7891\n', 'mixed-port: 0\n',
                     '  mixed-port: 7890\n', 'mixed-port: 7890; echo bad\n'):
            with self.subTest(yaml=yaml):
                self.write(yaml)
                self.calls.clear()
                self.assertIsNone(self.probe.claude_egress('https://claude.ai/', isolated=True))
                self.assertEqual(self.calls, [])

    def test_socks_only_config_and_quoted_port(self):
        self.write('mixed-port: 0\nsocks-port: "7891" # local\n')
        self.assertEqual(self.probe.isolated_proxy(), '127.0.0.1:7891')
        self.assertIn('-iTCP:7891', self.calls[0])

    def test_missing_config_or_listener_query_failure_fails_closed(self):
        os.unlink(self.path)
        self.assertIsNone(self.probe.isolated_proxy())
        self.write('mixed-port: 7890\n')
        self.probe.runner = lambda argv, **kw: subprocess.CompletedProcess(argv, 1, 'p50\nu0\n', '')
        self.assertIsNone(self.probe.isolated_proxy())

    def test_failed_tls_timeout_or_unparseable_trace_has_no_fallback(self):
        for code, body in ((28, ''), (60, 'ip=203.0.113.10\n'), (0, '<html>blocked</html>')):
            with self.subTest(code=code, body=body):
                self.curl_rc, self.curl_body = code, body
                self.calls.clear()
                self.assertIsNone(self.probe.claude_egress('https://claude.ai/', isolated=True))
                self.assertEqual(len(self.calls), 2)


class IsolationReleaseRegressionTests(unittest.TestCase):
    def setup_locked(self):
        svc, pf, pr, *_ = make_service(self)
        svc.enable(out=lambda *_: None)
        pr.egress_ip = '192.0.2.50'
        svc.tick()
        self.assertTrue(svc.read_guard()['lockdown'])
        self.assertTrue(pf.table)
        pr.egress_ip = '203.0.113.10'
        ordinary = pr.egress
        def direct(url, max_time=8):
            return None if 'claude' in url and pf.table else ordinary(url, max_time)
        def control(url, isolated=False, max_time=8):
            self.assertTrue(isolated)
            self.assertTrue(svc.read_state()['claude_block'])
            self.assertTrue(pf.table)  # do not clear isolation in order to pass
            return pr.claude_ip
        pr.egress = direct
        pr.claude_egress = control
        return svc, pf, pr

    def test_release_checks_same_endpoint_while_fake_ip_table_is_still_populated(self):
        svc, pf, pr = self.setup_locked()
        svc.release(out=lambda *_: None)
        self.assertFalse(svc.read_guard()['lockdown'])
        self.assertFalse(svc.read_state()['claude_block'])
        self.assertFalse(pf.table)

    def test_release_keeps_isolation_if_claude_probe_fails_or_exit_is_not_allowed(self):
        svc, pf, pr = self.setup_locked()
        for ip in (None, '192.0.2.50'):
            pr.claude_ip = ip
            with self.assertRaises(UserError):
                svc.release(out=lambda *_: None)
            self.assertTrue(svc.read_guard()['lockdown'])
            self.assertTrue(svc.read_state()['claude_block'])
            self.assertTrue(pf.table)

    def test_proxy_success_does_not_bypass_other_release_checks(self):
        for failure in ('tun', 'ordinary', 'mode', 'helper', 'foreign_rule'):
            with self.subTest(failure=failure):
                svc, pf, pr = self.setup_locked()
                if failure == 'tun':
                    pr.tun = None
                elif failure == 'ordinary':
                    pr.egress_ip = '192.0.2.50'
                elif failure == 'mode':
                    pr.mode = 'rule'
                elif failure == 'helper':
                    pr.cg['helper_loaded'] = False
                else:
                    pf.main_extra = ['pass out all flags any keep state']
                with self.assertRaises(UserError):
                    svc.release(out=lambda *_: None)
                self.assertTrue(svc.read_state()['claude_block'])
                self.assertTrue(pf.table)

    def test_unisolate_also_checks_before_dropping_fake_ip_table(self):
        svc, pf, pr, *_ = make_service(self)
        svc.enable(out=lambda *_: None)
        svc.isolate(out=lambda *_: None)
        def control(url, isolated=False, **kw):
            self.assertTrue(isolated)
            self.assertTrue(pf.table)
            self.assertTrue(svc.read_state()['claude_block'])
            return '203.0.113.10'
        pr.claude_egress = control
        svc.unisolate(out=lambda *_: None)
        self.assertFalse(svc.read_state()['claude_block'])
        self.assertFalse(pf.table)
