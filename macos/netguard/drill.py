"""`netguard drill`: a self-driven proxy-down acceptance test (no human timing needed).

Sequence (root):
  1. preconditions: kill switch complete, no lockdown, outside the grace period, exit whitelisted;
  2. quit FlClash in the user's session (and stop its core if the TUN survives), until the TUN is gone;
  3. stay down for DOWN_SECONDS, sampling every 2 s: a public HTTPS request (must fail: if it
     succeeds the exit IP is recorded and the drill reports a LEAK), the LAN gateway (should work)
     and the guard state (lockdown expected about 20 s after the TUN disappeared);
  4. reopen FlClash and wait for the TUN and a whitelisted exit;
  5. safety net: if the network is not back within RECOVER_SECONDS, run the offline recovery so the
     Mac is never left without network.
Every sample is written to /Library/NetGuard/drill-<time>.jsonl; the summary is printed.
The lockdown triggered by the drill is left in place on purpose (acceptance item 4 is `release`).
"""
import json
import os
import re
import time

from . import config, paths, util

DOWN_SECONDS = 45
QUIT_TIMEOUT = 25
RECOVER_SECONDS = 180
SAMPLE_EVERY = 2


class DrillAbort(RuntimeError):
    pass


class Drill:
    def __init__(self, svc, out=print, clock=time.time, sleep=time.sleep, log_path=None):
        self.svc = svc
        self.p = svc.probes
        self.cfg = svc.cfg
        self.out = out
        self.clock = clock
        self.sleep = sleep
        self.log_path = log_path or os.path.join(paths.ROOT, "drill-%s.jsonl" % time.strftime("%Y%m%d-%H%M%S"))
        self.samples = []

    # ---- actions in the console user's session (overridable in tests) ----
    def as_user(self, args, timeout=30):
        user = self.p.console_user()
        if not user:
            raise DrillAbort("没有登录的桌面用户")
        name, uid = user
        return util.run([paths.LAUNCHCTL, "asuser", str(uid), paths.SUDO, "-u", name] + list(args), timeout=timeout)

    def quit_flclash(self):
        self.as_user([paths.OSASCRIPT, "-e", 'quit app "FlClash"'])

    def stop_core(self):
        import signal
        for core in self.p.find_core():
            try:
                os.kill(core["pid"], signal.SIGTERM)
            except OSError:
                pass

    def open_flclash(self):
        self.as_user(["/usr/bin/open", "-a", "FlClash"])

    def gateway(self):
        out = util.run([paths.ROUTE, "-n", "get", "default"]).stdout
        for line in (out or "").splitlines():
            if "gateway:" in line:
                return line.split(":", 1)[1].strip()
        return None

    def public_probe(self):
        """(succeeded, exit ip). Runs as root (uid 0, gid 0): not covered by the core exemption."""
        r = util.run([paths.CURL, "-s", "--noproxy", "*", "-m", "3", self.cfg["check_url"]], timeout=6)
        if r.returncode != 0:
            return False, None
        match = re.search(r"(?m)^ip=(\S+)", r.stdout or "")
        return True, match.group(1) if match else None

    def gateway_probe(self, gw):
        if not gw:
            return None
        r = util.run([paths.CURL, "-s", "-o", "/dev/null", "-m", "3", "-w", "%{http_code}", "http://%s/" % gw], timeout=6)
        return (r.stdout or "").strip() not in ("", "000")

    def recover(self):
        return util.run([os.path.join(paths.ROOT, "bin", "netguard-recover")], timeout=60)

    # ---- sampling ----
    def sample(self, phase, gw):
        ok, ip = self.public_probe()
        guard = self.svc.read_guard()
        row = {"t": round(self.clock(), 1), "phase": phase, "tun": self.p.tun_interface(),
               "public_ok": ok, "public_ip": ip,
               "public_ip_whitelisted": config.ip_in_whitelist(ip, self.cfg["whitelist"]) if ip else None,
               "gateway_ok": self.gateway_probe(gw), "lockdown": bool(guard.get("lockdown")),
               "findings": guard.get("last_findings") or []}
        self.samples.append(row)
        try:
            with open(self.log_path, "a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        except OSError:
            pass
        return row

    # ---- the drill ----
    def preconditions(self):
        state = self.svc.read_state()
        guard = self.svc.read_guard()
        integ = self.svc.pf.integrity(state.get("rules_fp"))
        if not (state["killswitch"] and integ["complete"]):
            raise DrillAbort("断网保护未开启或不完整，不做断线演练")
        if guard["lockdown"]:
            raise DrillAbort("当前处于锁定，先解除再演练")
        if self.svc.grace_info()["active"]:
            raise DrillAbort("处于开机/登录/唤醒宽限期，等宽限期结束后再演练（否则无法验证锁定）")
        if not self.p.tun_interface():
            raise DrillAbort("TUN 当前不在，无法演练")
        ok, ip = self.public_probe()
        if not ok or not config.ip_in_whitelist(ip, self.cfg["whitelist"]):
            raise DrillAbort("演练前出口不正常（%s），不演练" % ip)

    def run(self):
        self.preconditions()
        gw = self.gateway()
        self.out("演练开始：记录写入 %s" % self.log_path)
        self.sample("before", gw)

        self.out("1/3 退出 FlClash，等待 TUN 消失……")
        self.quit_flclash()
        start = self.clock()
        stopped_core = False
        while self.p.tun_interface():
            if self.clock() - start > QUIT_TIMEOUT:
                if stopped_core:
                    self.open_flclash()
                    raise DrillAbort("退出 FlClash 后 TUN 仍在，演练无效（已重新打开 FlClash）")
                self.stop_core()
                stopped_core = True
                start = self.clock()
            self.sleep(1)
        down_at = self.clock()
        self.out("2/3 TUN 已消失，保持断开 %d 秒并每 %d 秒采样……" % (DOWN_SECONDS, SAMPLE_EVERY))
        while self.clock() - down_at < DOWN_SECONDS:
            self.sample("down", gw)
            self.sleep(SAMPLE_EVERY)

        self.out("3/3 重新打开 FlClash，等待网络恢复……")
        self.open_flclash()
        back_at = None
        reopen = self.clock()
        while self.clock() - reopen < RECOVER_SECONDS:
            row = self.sample("recover", gw)
            if row["tun"] and row["public_ok"] and row["public_ip_whitelisted"]:
                back_at = self.clock()
                break
            self.sleep(SAMPLE_EVERY)
        rescued = False
        if back_at is None:
            self.out("网络 %d 秒内没有恢复：自动执行紧急恢复，避免断网。" % RECOVER_SECONDS)
            self.recover()
            rescued = True
        return self.verdict(down_at, back_at, rescued)

    def verdict(self, down_at, back_at, rescued):
        down = [s for s in self.samples if s["phase"] == "down"]
        leaks = [s for s in down if s["public_ok"]]
        bad_ip = [s for s in leaks if s["public_ip"] and not s["public_ip_whitelisted"]]
        locked = [s for s in self.samples if s["phase"] in ("down", "recover") and s["lockdown"]]
        lock_after = round(locked[0]["t"] - down_at, 1) if locked else None
        gw_down = [s["gateway_ok"] for s in down if s["gateway_ok"] is not None]
        result = {
            "down_samples": len(down),
            "public_succeeded_while_down": len(leaks),
            "real_ip_leaks": len(bad_ip),
            "gateway_ok_while_down": sum(1 for g in gw_down if g),
            "gateway_samples": len(gw_down),
            "lockdown_after_seconds": lock_after,
            "network_back_after_seconds": round(back_at - down_at - DOWN_SECONDS, 1) if back_at else None,
            "rescued": rescued,
            "log": self.log_path,
        }
        result["passed"] = bool(down) and not leaks and lock_after is not None and lock_after <= 40 \
            and back_at is not None and not rescued
        return result
