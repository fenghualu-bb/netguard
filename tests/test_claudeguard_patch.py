"""ClaudeGuard 守护进程本地补丁（分级处置 + 保护记录）的离线测试。
全部替身：不访问网络、不改 WFP、不结束任何真实进程。用 ClaudeGuard 的 venv 运行。"""
import contextlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

GUARD = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "ClaudeGuard"
sys.path.insert(0, str(GUARD))
PATCH = Path(__file__).resolve().parents[1] / "patches" / "claudeguard" / "runtime.py"
spec = importlib.util.spec_from_file_location("netguard_runtime_snapshot", PATCH)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class Stop(Exception):
    pass


class FakeSettings:
    def __init__(self, directory):
        self.path = Path(directory) / "config.json"
        self.data = {"cli_path": r"C:\x\cli.exe", "desktop_path": r"C:\x\claude.exe", "protection_enabled": True,
                     "network_guard_enabled": True, "check_interval": 3, "ip_check_mode": "http", "allowed_ips": ["1.1.1.1"]}
    def load(self): return dict(self.data)


def run_daemon(steps, start=1000.0):
    """steps: 每轮 (verdict 或 Exception, publish 是否抛错, 经过的秒数)。返回 (事件列表, 结束调用次数)。"""
    with tempfile.TemporaryDirectory() as d:
        s = FakeSettings(d)
        clock = {"t": start}
        it = iter(steps)
        current = {}
        kills = []

        def fake_check(data, _dir):
            v, pub_err, _ = current["step"]
            if isinstance(v, Exception): raise v
            return dict(v)

        def fake_publish(settings, data, verdict):
            v, pub_err, _ = current["step"]
            if pub_err and verdict.get("state") != "blocked": raise RuntimeError(pub_err)
            return {"ready": True}

        def fake_sleep(_):
            try:
                current["step"] = next(it)
            except StopIteration:
                raise Stop()
            clock["t"] += current["step"][2]

        current["step"] = next(it)
        clock["t"] += current["step"][2]
        with patch.object(runtime, "check", fake_check), patch.object(runtime.network, "publish", fake_publish), \
             patch.object(runtime, "enforce", lambda paths: kills.append(1) or []), \
             patch.object(runtime, "running_targets", lambda paths: 2), \
             patch.object(runtime.time, "time", lambda: clock["t"]), patch.object(runtime.time, "sleep", fake_sleep), \
             patch.object(runtime, "atomic_json", lambda *a, **k: None),              patch.object(runtime.logging, "basicConfig", lambda **k: None),              patch.object(runtime, "InstanceLock", lambda path: contextlib.nullcontext()):
            try:
                runtime.daemon(s)
            except Stop:
                pass
        p = s.path.with_name(runtime.EVENTS_NAME)
        events = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []
        return events, len(kills)


OK = {"state": "allowed", "ip": "1.1.1.1"}
OFF = {"state": "offline", "ip": None}
BAD = {"state": "blocked", "ip": "9.9.9.9"}


class PatchTests(unittest.TestCase):
    def types(self, events): return [e["type"] for e in events]

    def test_brief_offline_cuts_network_but_does_not_kill(self):
        ev, kills = run_daemon([(OK, None, 0), (OFF, None, 3), (OFF, None, 3), (OK, None, 3)])
        self.assertEqual(kills, 0)
        self.assertEqual(self.types(ev), ["net_block", "net_restore"])
        self.assertEqual(ev[0]["severity"], "低")
        self.assertTrue(ev[0]["reasons"][0]["why"])

    def test_sustained_offline_kills_after_10s_and_records(self):
        ev, kills = run_daemon([(OFF, None, 0), (OFF, None, 4), (OFF, None, 4), (OFF, None, 4)])
        self.assertGreaterEqual(kills, 1)
        kill = [e for e in ev if e["type"] == "kill"][0]
        self.assertIn("持续", kill["summary"])
        self.assertEqual(kill["severity"], "低")
        self.assertEqual(kill["detail"]["killed"], 2)

    def test_confirmed_wrong_ip_kills_immediately(self):
        ev, kills = run_daemon([(OK, None, 0), (BAD, None, 3)])
        self.assertEqual(kills, 1)
        kill = [e for e in ev if e["type"] == "kill"][0]
        self.assertEqual(kill["severity"], "高")
        self.assertIn("立即", kill["summary"])
        self.assertIn("9.9.9.9", kill["reasons"][0]["text"])

    def test_helper_stale_is_medium_and_debounced(self):
        ev, kills = run_daemon([(OK, None, 0), (OK, "网络助手未就绪：网络助手状态过期", 3), (OK, None, 3)])
        self.assertEqual(kills, 0)
        self.assertEqual(ev[0]["type"], "net_block")
        self.assertEqual(ev[0]["severity"], "中")
        self.assertEqual(ev[-1]["type"], "net_restore")

    def test_helper_stale_sustained_kills(self):
        stale = "网络助手未就绪：网络助手状态过期"
        ev, kills = run_daemon([(OK, stale, 0), (OK, stale, 4), (OK, stale, 4), (OK, stale, 4)])
        self.assertGreaterEqual(kills, 1)
        self.assertEqual([e for e in ev if e["type"] == "kill"][0]["severity"], "中")

    def test_wrong_ip_followed_by_error_still_immediate(self):
        ev, kills = run_daemon([(OK, None, 0), (BAD, "网络助手未就绪：网络助手状态过期", 3)])
        self.assertEqual(kills, 1)
        self.assertEqual([e for e in ev if e["type"] == "kill"][0]["severity"], "高")

    def test_path_changed_is_high_and_immediate(self):
        ev, kills = run_daemon([(OK, None, 0), (OK, "网络助手未就绪：程序路径已变化，请重新安装网络助手", 3)])
        self.assertEqual(kills, 1)
        self.assertEqual([e for e in ev if e["type"] == "kill"][0]["severity"], "高")

    def test_every_event_has_reason_level_and_explanation(self):
        ev, _ = run_daemon([(OFF, None, 0), (OFF, None, 6), (OFF, None, 6), (BAD, None, 3), (OK, None, 3)])
        for e in ev:
            self.assertEqual(e["source"], "ClaudeGuard")
            self.assertIn(e["severity"], ("高", "中", "低"))
            if e["type"] != "net_restore":
                self.assertTrue(e["reasons"] and all(r["text"] and r["level"] and r["why"] for r in e["reasons"]))


if __name__ == "__main__":
    unittest.main()
