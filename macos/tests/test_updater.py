"""The automatic updater: when it installs, how it checks, and that it never downgrades."""
import json
import os
import time
import unittest
from unittest import mock

from fakes import use_temp_root
from netguard import updater

SHA_OLD = "a" * 40
SHA_NEW = "b" * 40
POLICY = dict(updater.DEFAULT_POLICY)


class FakeGitHub:
    def __init__(self, head=SHA_NEW, ci=True, files=("macos/netguard/service.py",)):
        self.head, self.ci, self.files, self.calls = head, ci, list(files), []

    def __call__(self, path):
        self.calls.append(path)
        if path.startswith("repos/fenghualu-bb/netguard/commits/main"):
            return {"sha": self.head}
        if "/compare/" in path:
            return {"files": [{"filename": f} for f in self.files]}
        if "/actions/runs?" in path:
            run = {"id": 7, "head_sha": self.head, "name": "macOS NetGuard", "head_branch": "main",
                   "status": "completed", "conclusion": "success" if self.ci else "failure", "html_url": "u"}
            return {"workflow_runs": [run]}
        if "/jobs" in path:
            return {"jobs": [{"name": n, "conclusion": "success"} for n in POLICY["jobs"]]}
        raise AssertionError(path)


class Base(unittest.TestCase):
    def setUp(self):
        root = use_temp_root(self)
        for name, value in (("STATE", "update-state.json"), ("POLICY", "update-policy.json"), ("WORK", "updates"),
                            ("LAST_BACKUP", "last-backup")):
            patcher = mock.patch.object(updater, name, os.path.join(root, value))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.root = root
        mock.patch.object(updater, "tell", lambda *a: None).start()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(updater, "console_uid", lambda: 501).start()

    def state(self, installed=SHA_OLD):
        st = updater.load_state()
        st["installed"] = installed
        return st


class DecideTests(Base):
    def test_current(self):
        gh = FakeGitHub(head=SHA_OLD)
        self.assertEqual(updater.decide(POLICY, self.state(), 1000, gh)[0], "current")

    def test_waits_24_hours_after_first_seeing_a_commit(self):
        gh, st = FakeGitHub(), self.state()
        action, sha, note = updater.decide(POLICY, st, 1000, gh)
        self.assertEqual((action, sha), ("wait", SHA_NEW))
        self.assertIn("24", note)
        self.assertEqual(updater.decide(POLICY, st, 1000 + 23 * 3600, gh)[0], "wait")
        self.assertEqual(updater.decide(POLICY, st, 1000 + 24 * 3600 + 1, gh)[0], "install")

    def test_old_commit_date_cannot_skip_the_wait(self):
        # A fast-forward merge keeps the original commit date; only the first sighting counts.
        gh, st = FakeGitHub(), self.state()
        self.assertEqual(updater.decide(POLICY, st, 5000, gh)[0], "wait")

    def test_needs_ci_on_that_exact_commit(self):
        gh, st = FakeGitHub(ci=False), self.state()
        st["first_seen"] = {SHA_NEW: 0}
        action, _, note = updater.decide(POLICY, st, 10 ** 6, gh)
        self.assertEqual(action, "wait")
        self.assertIn("CI", note)

    def test_now_skips_only_the_wait_never_ci(self):
        gh, st = FakeGitHub(ci=False), self.state()
        self.assertEqual(updater.decide(POLICY, st, 1000, gh, force=True)[0], "wait")
        gh.ci = True
        self.assertEqual(updater.decide(POLICY, st, 1000, gh, force=True)[0], "install")

    def test_commits_without_macos_changes_are_only_recorded(self):
        gh, st = FakeGitHub(files=("admin/netguard.ps1", "README.md")), self.state()
        self.assertEqual(updater.decide(POLICY, st, 1000, gh)[0], "record")

    def test_bad_commit_is_not_retried(self):
        gh, st = FakeGitHub(), self.state()
        st["bad"] = [SHA_NEW]
        self.assertEqual(updater.decide(POLICY, st, 10 ** 6, gh)[0], "skip")

    def test_no_console_user_waits(self):
        gh, st = FakeGitHub(), self.state()
        st["first_seen"] = {SHA_NEW: 0}
        with mock.patch.object(updater, "console_uid", lambda: None):
            self.assertEqual(updater.decide(POLICY, st, 10 ** 6, gh)[0], "wait")


class UpdateFlowTests(Base):
    def test_success_records_the_commit(self):
        gh, st = FakeGitHub(), self.state()
        st["first_seen"] = {SHA_NEW: 0}
        out = updater.update_netguard(POLICY, st, 10 ** 6, fetch=gh, installer=lambda *a: (True, "ok"))
        self.assertTrue(out["ok"])
        self.assertEqual(st["installed"], SHA_NEW)

    def test_failure_marks_bad_and_keeps_the_old_commit(self):
        gh, st = FakeGitHub(), self.state()
        st["first_seen"] = {SHA_NEW: 0}
        out = updater.update_netguard(POLICY, st, 10 ** 6, fetch=gh, installer=lambda *a: (False, "rolled back"))
        self.assertFalse(out["ok"])
        self.assertEqual(st["installed"], SHA_OLD)
        self.assertIn(SHA_NEW, st["bad"])

    def test_rollback_never_restores_an_older_backup(self):
        old_backup = os.path.join(self.root, "backup-old")
        os.makedirs(os.path.join(old_backup, "lib"))
        with open(updater.LAST_BACKUP, "w") as stream:
            stream.write(old_backup + "\n")
        os.utime(updater.LAST_BACKUP, (1000, 1000))
        services = []
        with mock.patch.object(updater, "ensure_services", lambda: services.append(1)):
            ok, note = updater.rollback("x", since=time.time())
        self.assertFalse(ok)
        self.assertIn("原版本未受影响", note)
        self.assertEqual(services, [1])  # the installer had stopped the daemon: bring it back

    def test_health_check(self):
        now = time.time()
        with mock.patch.object(updater, "daemon_ok", lambda label: True):
            good = lambda: {"updated_at": now + 1, "version": "1.2.0-mac", "wanted_killswitch": True,
                            "killswitch_complete": True}
            self.assertTrue(updater.healthy("1.2.0-mac", now, good, sleep=lambda s: None)[0])
            broken = lambda: dict(good(), killswitch_complete=False)
            ok, why = updater.healthy("1.2.0-mac", now, broken, sleep=lambda s: None, deadline=0.01)
            self.assertFalse(ok)
            old = lambda: dict(good(), version="1.1.0-mac")
            ok, why = updater.healthy("1.2.0-mac", now, old, sleep=lambda s: None, deadline=0.01)
            self.assertIn("1.1.0-mac", why)


class ClaudeGuardFollowTests(Base):
    def pin(self, **kw):
        path = os.path.join(self.root, "pin.json")
        data = {"kind": "pkg", "version": "2.2", "url": "https://x/ClaudeGuard.pkg", "sha256": "0" * 64}
        data.update(kw)
        with open(path, "w") as stream:
            json.dump(data, stream)
        return path

    def test_source_pin_keeps_the_existing_install(self):
        out = updater.follow_claudeguard(POLICY, {}, 0, pin_path=self.pin(kind="source", version="61b61e1"))
        self.assertEqual(out["action"], "keep")

    def test_pkg_pin_installs_once_and_checks_it_runs(self):
        st, installs = {}, []
        out = updater.follow_claudeguard(POLICY, st, 0, pin_path=self.pin(), installer=installs.append,
                                         running=lambda: True, sleep=lambda s: None)
        self.assertEqual(out["action"], "installed")
        self.assertEqual(st["claudeguard_installed"], "2.2")
        out = updater.follow_claudeguard(POLICY, st, 0, pin_path=self.pin(), installer=installs.append)
        self.assertEqual((out["action"], len(installs)), ("current", 1))

    def test_not_running_afterwards_stops_retrying(self):
        st = {}
        out = updater.follow_claudeguard(POLICY, st, 0, pin_path=self.pin(), installer=lambda p: None,
                                         running=lambda: False, sleep=lambda s: None)
        self.assertEqual(out["action"], "failed")
        out = updater.follow_claudeguard(POLICY, st, 0, pin_path=self.pin(), installer=lambda p: 1 / 0)
        self.assertEqual(out["action"], "skip")

    def test_wrong_hash_is_refused(self):
        st = {}
        with mock.patch.object(updater, "download", lambda url, target, timeout=900: open(target, "wb").write(b"x")):
            out = updater.follow_claudeguard(POLICY, st, 0, pin_path=self.pin())
        self.assertEqual(out["action"], "failed")
        self.assertIn("哈希不符", out["note"])

    def test_shipped_pin_is_valid(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, "upstream", "claudeguard.json")) as stream:
            pin = json.load(stream)
        self.assertIn(pin["kind"], ("source", "pkg"))
        if pin["kind"] == "pkg":
            self.assertTrue(pin["url"].startswith("https://github.com/fenghualu-bb/netguard/releases/download/"))
            self.assertRegex(pin["sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()


class ArchiveTests(Base):
    def make(self, target, members):
        import io
        import tarfile
        with tarfile.open(target, "w:gz") as tar:
            for name, kind in members:
                info = tarfile.TarInfo(name)
                if kind == "file":
                    data = b"#!/bin/bash\n"
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
                elif kind == "dir":
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755  # as in GitHub's tarballs
                    tar.addfile(info)
                else:
                    info.type = tarfile.SYMTYPE
                    info.linkname = "/etc/passwd"
                    tar.addfile(info)

    def fetch(self, members):
        with mock.patch.object(updater, "download", lambda url, target, timeout=900: self.make(target, members)):
            return updater.fetch_tree(POLICY, SHA_NEW)

    def test_normal_archive(self):
        tree = self.fetch([("netguard-x", "dir"), ("netguard-x/macos", "dir"), ("netguard-x/macos/install.sh", "file")])
        self.assertTrue(os.path.isfile(os.path.join(tree, "macos", "install.sh")))
        self.assertEqual(oct(os.stat(updater.WORK).st_mode & 0o777), "0o700")

    def test_links_and_escapes_are_refused(self):
        for bad in (("netguard-x/macos/link", "link"), ("../evil", "file"), ("/abs", "file")):
            with self.subTest(bad=bad):
                with self.assertRaises(updater.UpdateError):
                    self.fetch([("netguard-x/macos/install.sh", "file"), bad])
