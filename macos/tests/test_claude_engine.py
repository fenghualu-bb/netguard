"""The merged Claude process engine (identification from ClaudeExitGuard, isolation, cleanup)."""
import errno
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

from netguard import claude, config, procs

APP = "/Applications/Claude.app"
MAIN = APP + "/Contents/MacOS/Claude"
HELPER = APP + "/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper"
SUPPORT = "/Users/a/Library/Application Support/Claude/claude-code/2.1.3/x/claude.app/Contents/MacOS/claude"
NATIVE = "/Users/a/.local/share/claude/versions/2.1.3"
SHIPIT = "/Users/a/Library/Caches/com.anthropic.claudefordesktop.ShipIt/ShipIt"
UID = 501


def row(pid, ppid, path, uid=UID, start=None):
    return {"pid": pid, "ppid": ppid, "uid": uid, "ruid": uid, "gid": 20, "path": path, "comm": path,
            "start": start if start is not None else (1000 + pid, 0)}


class World:
    """A fake process table with signals that act on it."""

    def __init__(self, rows):
        self.rows = {r["pid"]: r for r in rows}
        self.signals = []
        self.ignore_term = set()
        self.refuse = {}
        self.args = {}
        self.t = 100.0

    def snapshot(self):
        return list(self.rows.values())

    def clock(self):
        return self.t

    def send(self, r, sig):
        self.signals.append((r["pid"], sig))
        if r["pid"] in self.refuse:
            return self.refuse[r["pid"]]
        live = self.rows.get(r["pid"])
        if live is None or live["start"] != r["start"] or live["path"] != r["path"]:
            return errno.ESRCH
        if sig == signal.SIGKILL or r["pid"] not in self.ignore_term:
            self.exit(r["pid"])
        return 0

    def exit(self, pid):
        self.rows.pop(pid, None)
        for other in self.rows.values():
            if other["ppid"] == pid:
                other["ppid"] = 1  # re-parented to launchd, as on macOS

    def engine(self, **cfg):
        return claude.Engine(config.validate(cfg), snapshot=self.snapshot, sender=self.send, clock=self.clock,
                             args_of=lambda pid: self.args.get(pid, []), roots=lambda: [APP], own_pid=lambda: 99999)


def desktop_tree():
    return [row(10, 1, MAIN), row(11, 10, HELPER), row(12, 10, SUPPORT), row(13, 12, "/bin/zsh"),
            row(14, 13, "/opt/homebrew/bin/node"), row(15, 14, "/usr/bin/python3")]


class RoleTests(unittest.TestCase):
    def test_roles(self):
        r = lambda path, argv=(): claude.role(path, list(argv), [APP])  # noqa: E731
        self.assertEqual(r(MAIN), "main")
        self.assertEqual(r(HELPER), "helper")
        self.assertEqual(r(SUPPORT), "helper")
        self.assertEqual(r("/Users/a/Applications/Claude.app/Contents/MacOS/Claude"), "helper")
        self.assertEqual(r(SHIPIT), "updater")
        self.assertEqual(r(APP + "/Contents/Frameworks/Squirrel.framework/Resources/ShipIt"), "updater")
        self.assertEqual(r(NATIVE), "cli")
        self.assertEqual(r("/opt/homebrew/Caskroom/claude-code/2.1.3/claude"), "cli")
        self.assertEqual(r("/opt/homebrew/bin/node", ["node", "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js"]), "cli")
        for path in ("/Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuardMenuBar",
                     "/Users/a/Applications/ClaudeExitGuard.app/Contents/MacOS/ClaudeExitGuard",
                     "/Applications/NetGuard.app/Contents/MacOS/NetGuard", "/Library/NetGuard/bin/netguard",
                     "/usr/local/bin/claude-monitor", "/Applications/Codex.app/Contents/MacOS/Codex", "/bin/zsh"):
            self.assertIsNone(r(path), path)

    def test_inline_shell_commands_never_exempt_a_process(self):
        # Claude Code runs every command as `zsh -c "<text>"`; mentioning a guard path in that
        # text must not turn the shell into a guard.
        self.assertFalse(claude.excluded("/bin/zsh", ["/bin/zsh", "-c", "cat /Library/NetGuard/status.json"]))
        self.assertFalse(claude.excluded("/usr/bin/python3", ["python3", "-m", "x", "/Library/NetGuard/a.py"]))
        self.assertTrue(claude.excluded("/usr/bin/python3", ["python3", "-I", "/Library/NetGuard/lib/netguard_main.py"]))
        self.assertTrue(claude.excluded("/usr/bin/python3", ["python3", "/Users/a/.local/share/ClaudeGuard/src/x.py"]))


class ClassifyTests(unittest.TestCase):
    def test_process_tree_is_followed(self):
        w = World(desktop_tree() + [row(30, 1, "/bin/zsh"), row(31, 13, "/usr/bin/sudo", uid=0)])
        view = w.engine().classify()
        roles = {e["row"]["pid"]: e["role"] for e in view["entries"]}
        self.assertEqual(roles, {10: "main", 11: "helper", 12: "helper", 13: "descendant", 14: "descendant",
                                 15: "descendant"})
        self.assertTrue(view["main_running"])

    def test_guard_children_are_not_followed(self):
        w = World(desktop_tree() + [row(16, 13, "/usr/bin/python3")])
        w.args[16] = ["python3", "/Users/a/.local/share/ClaudeGuard/src/cli_wrapper.py"]
        self.assertNotIn(16, [e["row"]["pid"] for e in w.engine().classify()["entries"]])

    def test_children_stay_tracked_after_reparenting(self):
        w = World(desktop_tree())
        eng = w.engine()
        eng.classify()
        w.exit(12)  # the built-in Claude Code exits; its shell is re-parented to launchd
        w.exit(10)
        w.exit(11)
        view = eng.classify()
        self.assertEqual(sorted(e["row"]["pid"] for e in view["entries"]), [13, 14, 15])
        self.assertFalse(view["main_running"])

    def test_pid_reuse_is_not_tracked(self):
        w = World(desktop_tree())
        eng = w.engine()
        eng.classify()
        w.exit(10); w.exit(11); w.exit(12); w.exit(13); w.exit(14); w.exit(15)
        w.rows[13] = row(13, 1, "/bin/zsh", start=(9999, 0))  # same pid, another program
        self.assertEqual(eng.classify()["entries"], [])


class IsolationTests(unittest.TestCase):
    def test_isolation_kills_everything_including_updater_and_children(self):
        w = World(desktop_tree() + [row(20, 1, SHIPIT), row(21, 1, NATIVE),
                                    row(22, 1, "/Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuardMenuBar")])
        killed = w.engine().isolate_now()
        self.assertEqual(killed, 8)
        self.assertEqual(sorted(p for p, s in w.signals), [10, 11, 12, 13, 14, 15, 20, 21])
        self.assertTrue(all(s == signal.SIGKILL for _, s in w.signals))
        self.assertIn(22, w.rows)


class CleanupTests(unittest.TestCase):
    def quit_desktop(self, w):
        w.exit(10)

    def run_until_done(self, w, eng, uid=UID, seconds=8):
        result = None
        for _ in range(int(seconds / 0.5)):
            out = eng.cleanup_step(uid)
            result = out or result
            w.t += 0.5
        return result

    def test_nothing_happens_while_desktop_runs(self):
        w = World(desktop_tree() + [row(21, 1, NATIVE)])
        eng = w.engine()
        self.assertIsNone(self.run_until_done(w, eng))
        self.assertEqual(w.signals, [])

    def test_leftovers_are_ended_after_quit_with_term_then_kill(self):
        w = World(desktop_tree())
        eng = w.engine()
        eng.cleanup_step(UID)
        w.ignore_term = {14}  # a node MCP server that ignores SIGTERM
        self.quit_desktop(w)
        eng.cleanup_step(UID)
        self.assertEqual(w.signals, [])  # debounce: helpers may still be exiting on their own
        result = self.run_until_done(w, eng)
        self.assertEqual(sorted(p["pid"] for p in result["cleaned"]), [11, 12, 13, 14, 15])
        self.assertEqual(result["failed"], [])
        self.assertIn((14, signal.SIGTERM), w.signals)
        self.assertIn((14, signal.SIGKILL), w.signals)
        self.assertNotIn((11, signal.SIGKILL), w.signals)  # exited on SIGTERM
        self.assertEqual(eng.status()["last_cleanup"], result)

    def test_reopening_claude_cancels_cleanup(self):
        w = World(desktop_tree())
        eng = w.engine()
        eng.cleanup_step(UID)
        self.quit_desktop(w)
        eng.cleanup_step(UID)
        w.t += 2.5
        w.rows[40] = row(40, 1, MAIN)  # reopened just before the signals would go out
        self.assertIsNone(self.run_until_done(w, eng))
        self.assertEqual(w.signals, [])

    def test_updater_is_left_alone_after_quit(self):
        w = World([row(20, 1, SHIPIT), row(11, 1, HELPER)])
        result = self.run_until_done(w, w.engine())
        self.assertEqual([p["pid"] for p in result["cleaned"]], [11])
        self.assertIn(20, w.rows)

    def test_policies(self):
        for policy, expected in (("full", [21]), ("desktop", []), ("off", [])):
            with self.subTest(policy=policy):
                w = World([row(21, 1, NATIVE)])
                self.run_until_done(w, w.engine(claude_cleanup=policy))
                self.assertEqual(sorted(set(p for p, _ in w.signals)), expected)

    def test_other_users_are_never_cleaned(self):
        w = World([row(11, 1, HELPER, uid=502)])
        self.assertIsNone(self.run_until_done(w, w.engine()))
        self.assertEqual(w.signals, [])
        self.assertIsNone(self.run_until_done(w, w.engine(), uid=None))

    def test_failure_is_reported_and_retried_rarely(self):
        w = World([row(11, 1, HELPER)])
        w.refuse[11] = errno.EPERM
        eng = w.engine()
        result = self.run_until_done(w, eng, seconds=6)
        self.assertEqual([p["pid"] for p in result["failed"]], [11])
        self.assertEqual(len(w.signals), 1)
        self.run_until_done(w, eng, seconds=31)
        self.assertEqual(len(w.signals), 2)


@unittest.skipUnless(procs.available(), "libproc only on macOS")
class RealProcessTests(unittest.TestCase):
    """Real processes, real kernel table, real signals, confined to a mock Claude.app tree."""

    def setUp(self):
        # The kernel reports resolved paths (/var -> /private/var).
        self.tmp = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.app = os.path.join(self.tmp, "Claude.app")
        os.makedirs(os.path.join(self.app, "Contents", "MacOS"))
        self.main_path = os.path.join(self.app, "Contents", "MacOS", "Claude")
        # macOS kills copies of its own platform binaries, so build a tiny stand-in that, like
        # Claude, starts child processes (two `sleep`s) and keeps running.
        source = os.path.join(self.tmp, "mock.c")
        with open(source, "w") as stream:
            stream.write('#include <unistd.h>\nint main(void){for(int i=0;i<2;i++)'
                         'if(fork()==0){execl("/bin/sleep","sleep","60",(char*)0);_exit(1);}'
                         'pause();return 0;}\n')
        clang = shutil.which("clang") or "/usr/bin/clang"
        if subprocess.run([clang, "-o", self.main_path, source], capture_output=True).returncode != 0:
            self.skipTest("clang not available")
        self.ours = set()

    def tree(self):
        """Only processes started by this test (directly or below the mock app)."""
        rows = procs.snapshot()
        changed = True
        while changed:
            changed = False
            for r in rows:
                if r["pid"] not in self.ours and (r["ppid"] in self.ours or r["path"].startswith(self.tmp)):
                    self.ours.add(r["pid"])
                    changed = True
        return [r for r in rows if r["pid"] in self.ours]

    def guarded_send(self, r, sig):
        self.assertIn(r["pid"], self.ours, "would signal a process outside the test")
        return procs.signal_if_same(r, sig)

    def engine(self):
        cfg = config.validate({"claude_app_paths": [self.app]})
        return claude.Engine(cfg, snapshot=self.tree, sender=self.guarded_send, roots=lambda: [self.app])

    def test_quit_app_leftovers_are_ended(self):
        main = subprocess.Popen([self.main_path])
        self.addCleanup(lambda: main.poll() is None and main.kill())
        self.ours.add(main.pid)
        eng = self.engine()
        deadline = time.monotonic() + 5  # a freshly built binary is assessed on first launch
        while True:
            view = eng.classify()
            if sum(e["role"] == "descendant" for e in view["entries"]) == 2 or time.monotonic() > deadline:
                break
            time.sleep(0.1)
        self.assertTrue(view["main_running"])
        children = [e["row"]["pid"] for e in view["entries"] if e["role"] == "descendant"]
        self.assertEqual(len(children), 2)
        os.kill(main.pid, signal.SIGKILL)  # "quit": the children are re-parented to launchd
        main.wait()
        result = None
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not result:
            result = eng.cleanup_step(os.getuid())
            time.sleep(0.2)
        self.assertIsNotNone(result)
        self.assertEqual(sorted(p["pid"] for p in result["cleaned"]), sorted(children))
        for pid in children:
            self.assertIsNone(procs.current(pid))

    def test_signal_refuses_a_reused_pid(self):
        sleeper = subprocess.Popen(["/bin/sleep", "30"])
        self.addCleanup(lambda: sleeper.poll() is None and sleeper.kill())
        self.ours.add(sleeper.pid)
        live = procs.current(sleeper.pid)
        stale = dict(live, start=(live["start"][0] - 5, 0))
        self.assertEqual(procs.signal_if_same(stale, signal.SIGKILL), errno.ESRCH)
        self.assertIsNone(sleeper.poll())
        self.assertEqual(procs.signal_if_same(live, signal.SIGKILL), 0)
        sleeper.wait(5)

    def test_snapshot_matches_the_kernel(self):
        me = procs.current(os.getpid())
        self.assertEqual(me["ppid"], os.getppid())
        self.assertEqual(me["uid"], os.geteuid())
        self.assertIsNotNone(me["start"])
        self.assertTrue(os.path.isabs(me["path"]))
        self.assertIn(os.getpid(), [r["pid"] for r in procs.snapshot()])


if __name__ == "__main__":
    unittest.main()


class ServiceIntegrationTests(unittest.TestCase):
    """The daemon wiring: one scanner thread, events, notifications and status."""

    def service(self, world):
        from fakes import make_service
        svc, pf, pr, clock, kills, notes = make_service(self)
        svc._killer = None
        svc.engine = world.engine()
        pr.user = ("alice", UID)
        return svc, notes

    def test_cleanup_is_recorded_and_notified(self):
        from netguard import events
        w = World([row(11, 1, HELPER), row(13, 11, "/bin/zsh")])
        svc, notes = self.service(w)
        for _ in range(12):
            svc.cleanup_claude()
            w.t += 0.5
        last = [e for e in events.read(50) if e["type"] == "cleanup"]
        self.assertEqual(len(last), 1)
        self.assertIn("结束了 2 个残留进程", last[0]["summary"])
        self.assertTrue(any("已清理 Claude 残留进程" in t for t, _ in notes))

    def test_scanner_thread_cleans_when_free_and_isolates_when_blocked(self):
        import threading
        w = World(desktop_tree())
        svc, _ = self.service(w)
        calls = []
        svc.engine.cleanup_step = lambda uid: calls.append("cleanup")
        svc.engine.isolate_now = lambda: calls.append("isolate") or 0
        stop = threading.Event()
        waits = []

        def wait(seconds):
            waits.append(seconds)
            if len(waits) == 2:
                state = svc.read_state()
                state["claude_block"] = True
                svc.write_state(state)
            if len(waits) >= 4:
                stop.set()
        svc.enforcer_loop(stop, wait=wait)
        self.assertEqual(calls, ["cleanup", "cleanup", "isolate", "isolate"])
        self.assertEqual(waits, [0.5, 0.5, 0.25, 0.25])

    def test_watch_with_scanner_thread_does_not_scan_again(self):
        w = World(desktop_tree())
        svc, _ = self.service(w)
        svc.isolate(out=lambda *_: None)
        isolations = []
        svc.engine.isolate_now = lambda: isolations.append(1) or 0
        svc.start_enforcer = lambda: None  # the thread is tested separately
        class Done(Exception):
            pass

        def stop_sleeping(seconds):
            raise Done()
        svc.sleep = stop_sleeping
        with self.assertRaises(Done):
            svc.watch(forever=True)
        self.assertEqual(isolations, [])  # only the enforcer thread ends Claude now

    def test_status_lists_claude_processes(self):
        w = World(desktop_tree())
        svc, _ = self.service(w)
        svc.engine.classify()
        st = svc.write_status()
        self.assertEqual(st["claude"]["count"], 6)
        self.assertTrue(st["claude"]["main_running"])
        self.assertEqual(st["claude"]["policy"], "full")
        self.assertEqual({p["role"] for p in st["claude"]["processes"]}, {"main", "helper", "descendant"})
