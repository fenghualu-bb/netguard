"""NetGuard state machine: kill switch, automatic protection (watch), lockdown and release.

Behaviour follows Windows NetGuard 1.3.5:
- watch checks every 10 s; a finding must be seen 2 times in a row before it acts;
- in the 180 s after boot / login / wake, medium findings (core, TUN, ClaudeGuard)
  are recorded once and deferred; high findings still count;
- a confirmed finding isolates Claude (lockdown); only a manual `release` that passes
  every check lifts it.

macOS-specific safety (the reason a previous attempt left the Mac offline):
- `enable` refuses unless the FlClash core runs privileged (TUN authorized), the TUN is up
  and the exit is whitelisted, i.e. unless the permit for the proxy core can actually work;
- after loading the rules it re-checks DNS, the proxied exit and that a direct connection
  fails. Any failure rolls back immediately. If `enable` itself dies, the daemon rolls it
  back at the pending deadline;
- `recover` (and the shell-only recover script) removes NetGuard's rules without network.
"""
import copy
import os
import time

from . import VERSION, claude, config, events, notify, paths, pfrules, probes as probes_mod, util

CONFIRM = 2
INTERVAL = 10
ENFORCE_EVERY = 2
ENFORCE_ISOLATED = 0.5  # while Claude is isolated, relaunches are ended within half a second
GRACE_SECONDS = 180
PENDING_SECONDS = 120
SHUTDOWN_WINDOW = 600  # a medium-only lockdown this close before boot came from the shutdown
CLAUDE_PATH_SETTLE = 90  # ClaudeGuard re-attaches its hooks every 60 s after a Claude update
EXEMPT_CHECK_EVERY = 60
DNS_PROBLEM = "DNS 解析失败"

STATE_DEFAULTS = {"killswitch": False, "claude_block": False, "core_uid": 0, "core_gid": None,
                  "rules_fp": None, "pending": None, "dns_block": False}
GUARD_DEFAULTS = {"enabled": True, "lockdown": False, "since": 0, "reasons": [], "reason_codes": [], "bad_streak": 0,
                  "last_check": 0, "last_findings": [], "triggers": 0, "grace_until": 0,
                  "grace_noted": 0, "observations": {}}


class UserError(RuntimeError):
    """A refusal that is explained to the user; nothing unsafe happened."""


def _with_defaults(data, defaults):
    out = copy.deepcopy(defaults)
    if isinstance(data, dict):
        for key, value in data.items():
            out[key] = value
    return out


class Service:
    def __init__(self, cfg=None, probes=None, pf=None, clock=time.time, notifier=None, killer=None,
                 sleeper=time.sleep):
        self.cfg = cfg if cfg is not None else config.load()
        self.probes = probes or probes_mod.Probes(self.cfg)
        self.pf = pf or pfrules.PF()
        self.clock = clock
        self.sleep = sleeper
        self._notifier = notifier
        self._killer = killer
        self.resume_at = 0
        self._last_kill_event = 0
        self._first_seen = {}
        self._last_exempt_check = 0
        self._exempt_seen = set()

    # ------------------------------------------------------------------ io
    def read_state(self):
        return _with_defaults(util.read_json(paths.STATE, {}), STATE_DEFAULTS)

    def write_state(self, state):
        util.write_json(paths.STATE, state)

    def read_guard(self):
        return _with_defaults(util.read_json(paths.GUARD, {}), GUARD_DEFAULTS)

    def write_guard(self, guard):
        util.write_json(paths.GUARD, guard)

    def read_token(self):
        try:
            with open(paths.TOKEN, "r", encoding="ascii") as stream:
                text = stream.read().strip()
        except OSError:
            return None
        return text if text.isdigit() else None

    def write_token(self, token):
        if token:
            util.write_text(paths.TOKEN, token + "\n", mode=0o600)

    def clear_token(self):
        for path in (paths.TOKEN, paths.ANCHOR_FILE):
            try:
                os.unlink(path)
            except OSError:
                pass

    def notify(self, title, message, key=None, every=300):
        if self._notifier:
            return self._notifier(title, message, key)
        try:
            return notify.send(self.probes, title, message, key=key, every=every)
        except Exception:
            return False

    def kill_claude(self):
        if self._killer:
            return self._killer()
        return claude.stop(claude.find(self.probes, self.cfg))

    # ------------------------------------------------------------------ pf
    def apply_rules(self, core_gid, state=None):
        state = state if state is not None else self.read_state()
        text = pfrules.render(self.cfg, 0, core_gid, dns_block=bool(state.get("dns_block")),
                              isolate=bool(state.get("claude_block")))
        self.pf.load(text)
        util.write_text(paths.ANCHOR_FILE, text, mode=0o644)
        token = self.pf.acquire_token(self.read_token())
        self.write_token(token)
        return pfrules.fingerprint(self.pf.anchor_rules())

    def remove_rules(self):
        self.pf.flush()
        self.pf.release_token(self.read_token())
        self.clear_token()

    def token_live(self):
        token = self.read_token()
        try:
            return pfrules.token_in_references(token, self.pf.references())
        except pfrules.PFError:
            return False

    def ensure_rules(self, state):
        """Re-establish wanted rules (after boot, a foreign `pfctl -d`, a flush). Never weakens."""
        integ = self.pf.integrity(state.get("rules_fp"))
        live = self.token_live()
        if integ.get("read_error") or (integ["rules_match"] and integ["pf_enabled"] and live):
            # A missing main-ruleset reference (Internet Sharing) cannot be fixed without
            # rewriting the main ruleset, which NetGuard never does: it stays a finding.
            integ["token_live"] = live
            return integ
        if state.get("core_gid") in (None, 0):
            integ["token_live"] = live
            integ["error"] = integ.get("error") or "缺少代理内核的用户组，需重新开启断网保护"
            return integ
        try:
            fp = self.apply_rules(state["core_gid"], state)
            restored = not (integ["rules_match"] and integ["pf_enabled"])
            state["rules_fp"] = fp
            self.write_state(state)
            if restored:
                events.add("rules_restored", "已重新加载断网保护规则（开机后或规则被外部清除）")
                util.log("rules restored", "watch")
            integ = self.pf.integrity(fp)
        except pfrules.PFError as exc:
            integ["error"] = str(exc)
        integ["token_live"] = self.token_live()
        return integ

    def refresh_rules(self, state):
        """Reload after claude_block/dns_block changed (Anthropic isolation, DNS mode)."""
        if state.get("killswitch") and state.get("core_gid"):
            state["rules_fp"] = self.apply_rules(state["core_gid"], state)
        self.write_state(state)

    def rollback(self, state, prev, reason):
        state["dns_block"] = bool(prev.get("dns_block"))
        if prev.get("killswitch") and prev.get("core_gid"):
            state["rules_fp"] = self.apply_rules(prev["core_gid"], state)
        else:
            self.remove_rules()
            state["rules_fp"] = None
        state["killswitch"] = bool(prev.get("killswitch"))
        state["core_gid"] = prev.get("core_gid")
        state["pending"] = None
        self.write_state(state)
        events.add("rollback", reason, [events.finding("killswitch", reason)])
        util.log("rollback: " + reason)

    def handle_pending(self, state):
        # Called with the state lock held. `enable` keeps the lock for its whole run, so a
        # pending change seen here belongs to an `enable` that died: roll it back now.
        pending = state.get("pending")
        if not pending:
            return False
        self.rollback(state, pending.get("prev") or {}, "开启断网保护的操作未在时限内完成自检，已自动恢复到操作前的状态")
        return True

    # ------------------------------------------------------------------ observation
    def observe(self, state, integ=None, require=False):
        f = []
        obs = {"checked_at": int(self.clock())}
        cfg = self.cfg
        wl = cfg["whitelist"]
        if require and not wl:
            f.append(events.finding("egress", "白名单为空，无法验证安全解除"))
        ip = self.probes.egress(cfg["check_url"])
        obs["egress"] = ip
        obs["egress_ok"] = config.ip_in_whitelist(ip, wl)
        if require and not ip:
            f.append(events.finding("egress", "普通出口未取得，保持锁定"))
        if ip and wl and not obs["egress_ok"]:
            f.append(events.finding("egress", "普通出口 %s 不在白名单" % ip))
        cip = self.probes.egress(cfg["claude_check_url"])
        obs["claude_egress"] = cip
        obs["claude_egress_ok"] = config.ip_in_whitelist(cip, wl)
        if require and not cip:
            f.append(events.finding("egress_claude", "claude.ai 出口未取得，保持锁定"))
        if cip and wl and not obs["claude_egress_ok"]:
            f.append(events.finding("egress_claude", "claude.ai 出口 %s 不在白名单" % cip))
        cores = self.probes.find_core()
        obs["core"] = {"running": bool(cores), "privileged": any(c["privileged"] for c in cores),
                       "uid": cores[0]["uid"] if cores else None, "gid": cores[0]["gid"] if cores else None}
        if not cores:
            f.append(events.finding("core", "FlClash 内核未运行"))
        elif not obs["core"]["privileged"]:
            f.append(events.finding("core", "FlClash 内核未获授权（TUN 未开启），断网保护会拦住它的流量"))
        tun = self.probes.tun_interface()
        obs["tun"] = tun
        obs["route"] = self.probes.route_interface()
        if not tun:
            f.append(events.finding("tun", "TUN 虚拟网卡未连接"))
        elif obs["route"] and obs["route"] != tun:
            f.append(events.finding("tun", "TUN 已连接，但公网流量没有经过它（路由指向 %s）" % obs["route"]))
        obs["flclash_ui"] = self.probes.flclash_ui()
        fl = self.probes.flclash_config()
        obs["flclash"] = fl
        if cfg["require_global_mode"] and fl.get("mode") in ("rule", "direct"):
            f.append(events.finding("mode", "FlClash 是%s模式，不是全局模式" % {"rule": "规则", "direct": "直连"}[fl["mode"]]))
        if state.get("killswitch") and integ is not None:
            obs["integrity"] = integ
            # As on Windows: a failed read is not proof of missing rules (shown in status only).
            if not integ.get("complete") and not integ.get("read_error"):
                f.append(events.finding("killswitch", "断网保护规则不完整" + (
                    "（pf 主规则集缺少 com.apple/* 锚点，可能开启了“互联网共享”）"
                    if integ.get("pf_enabled") and not integ.get("main_anchor_ref") else "")))
        if cfg["require_claudeguard"]:
            cg = self.probes.claudeguard()
            obs["claudeguard"] = cg
            if not cg["installed"] or not cg["fresh"]:
                f.append(events.finding("guard_daemon", "ClaudeGuard 未运行或状态过期"))
            else:
                if cg.get("protection_enabled") is False:
                    f.append(events.finding("guard_off", "ClaudeGuard 的保护被关闭"))
                if cg.get("error"):
                    f.append(events.finding("guard_helper", "ClaudeGuard 执行出错：%s" % str(cg["error"])[:120]))
            if cg["installed"]:
                if cg.get("helper_loaded") is False:
                    f.append(events.finding("guard_helper", "ClaudeGuard 的 root 网络助手（com.claudeguard.helper）未运行"))
                broken = []
                if cg.get("cli_hooked") is False:
                    loose = [l["path"] for l in cg.get("cli_links") or [] if not l["guarded"]]
                    broken.append("claude 命令没有经过 ClaudeGuard" + ("（%s）" % "、".join(loose) if loose else "（缺少钩子）"))
                if cg.get("cli_path_ok") is False:
                    hint = "" if cg.get("cg_patch") == "patched" else                         "（ClaudeGuard 61b61e1 不识别新版原生安装，运行 /Library/NetGuard/bin/claudeguard-patch 修复）"
                    broken.append("Claude Code 已安装（%s），但 ClaudeGuard 记录的路径已失效%s"
                                  % ("、".join(cg.get("cli_installed") or [])[:160], hint))
                if cg.get("app_path_ok") is False:
                    broken.append("Claude 桌面版已安装（%s），但 ClaudeGuard 记录的是 %s"
                                  % ("、".join(cg.get("app_installed") or []), cg.get("app_path")))
                if broken:
                    f.append(events.finding("claude_path", "；".join(broken)))
        return f, obs

    def settle(self, findings):
        """claude_path counts only after it persists past ClaudeGuard's own 60 s self-repair."""
        now = self.clock()
        keys = set(x["key"] for x in findings)
        for key in list(self._first_seen):
            if key not in keys:
                del self._first_seen[key]
        for key in keys:
            self._first_seen.setdefault(key, now)
        return [x for x in findings
                if x["key"] != "claude_path" or now - self._first_seen[x["key"]] >= CLAUDE_PATH_SETTLE]

    def grace_info(self):
        now = self.clock()
        user = self.probes.console_user()
        if not user:
            return {"active": True, "until": now + GRACE_SECONDS, "anchor": int(now), "reason": "尚无用户登录"}
        anchors = [float(self.resume_at), float(self.probes.boot_time() or 0), float(self.probes.wake_time() or 0)]
        login = self.probes.login_time(user[1])
        if login:
            anchors.append(float(login))
        anchor = max(anchors)
        return {"active": now - anchor < GRACE_SECONDS, "until": anchor + GRACE_SECONDS,
                "anchor": int(anchor), "reason": "开机 / 登录 / 唤醒"}

    # ------------------------------------------------------------------ watch
    def dns_safety_valve(self, state, obs):
        """With block_lan_dns "auto", never leave the Mac without DNS (the previous failure mode).

        If the router DNS is blocked, the proxy is healthy and DNS no longer resolves (for example
        after joining another Wi-Fi), LAN DNS is reopened, which leaks only queried names to the
        router, never the real IP to Anthropic. Recorded and notified; `enable` tries strict again.
        """
        if not (state.get("killswitch") and state.get("dns_block") and self.cfg["block_lan_dns"] == "auto"):
            return False
        core = obs.get("core") or {}
        if not (core.get("privileged") and obs.get("tun")):
            return False
        if self.probes.dns_reachable() or self.probes.dns_reachable():
            return False
        state["dns_block"] = False
        self.refresh_rules(state)
        events.add("dns_relaxed", "系统 DNS 指向局域网路由器，拦截它会导致无法解析：已改为放行局域网 DNS"
                                  "（只向路由器暴露查询的域名，不泄露真实 IP）")
        self.notify("NetGuard：已放行局域网 DNS", "当前网络的 DNS 是路由器，为保证能上网已放行；重新开启断网保护时会再尝试拦截。",
                    key="dns-relaxed", every=3600)
        return True

    def check_exemption(self, state, obs):
        if not state.get("killswitch") or not state.get("core_gid"):
            return
        now = self.clock()
        if now - self._last_exempt_check < EXEMPT_CHECK_EVERY:
            obs["exempt_others"] = sorted(self._exempt_seen)
            return
        self._last_exempt_check = now
        try:
            names = set(self.probes.exemption_users(state["core_gid"], self.cfg["core_names"]))
        except Exception:
            names = set()
        new = names - self._exempt_seen
        self._exempt_seen = names
        obs["exempt_others"] = sorted(names)
        if new:
            events.add("exempt", "注意：%s 以 root 身份联网，与 FlClash 内核共用放行身份，可绕过断网保护直连"
                       % "、".join(sorted(new)), [events.finding("killswitch", "放行身份被其他程序使用")])
            self.notify("NetGuard：发现其他程序直连", "、".join(sorted(new)) + " 以 root 身份联网，可能使用真实 IP。",
                        key="exempt-" + ",".join(sorted(new)), every=3600)

    def tick(self):
        started = self.clock()
        with util.StateLock():
            state = self.read_state()
            guard = self.read_guard()
            self.handle_pending(state)
            integ = self.ensure_rules(state) if state["killswitch"] else None
            findings, obs = self.observe(state, integ)
            if self.dns_safety_valve(state, obs):
                integ = self.ensure_rules(state)
            self.check_exemption(state, obs)
            obs["dns_block"] = bool(state.get("dns_block"))
            guard["last_check"] = int(self.clock())
            guard["last_findings"] = [x["text"] for x in findings]
            guard["observations"] = obs
            guard["duration"] = round(self.clock() - started, 1)
            findings = self.settle(findings)
            grace = self.grace_info()
            guard["grace_until"] = int(grace["until"]) if grace["active"] else 0
            if state["killswitch"] and not grace["active"] and \
                    any(x["key"] in ("core", "tun") for x in findings):
                self.notify("NetGuard：代理未就绪，已阻断直连",
                            "现在只能访问局域网。请打开 FlClash 并开启 TUN；急救见“NetGuard 紧急恢复”。",
                            key="proxy-down", every=600)
            if not guard["enabled"]:
                guard["bad_streak"] = 0
                self.write_guard(guard)
                return guard
            if guard["lockdown"]:
                if self.shutdown_artifact(guard):
                    self.try_boot_release(state, guard, integ)
                self.write_guard(guard)
                return guard
            if grace["active"]:
                deferred = [x for x in findings if events.RISK.get(x["key"], ("高",))[0] != "高"]
                if deferred and float(guard["grace_noted"]) != float(grace["anchor"]):
                    left = int(grace["until"] - self.clock())
                    events.add("grace", "宽限期内（%s，还剩约 %d 秒）：中危异常暂不锁定，高危异常照常锁定"
                               % (grace["reason"], left), deferred)
                    guard["grace_noted"] = grace["anchor"]
                findings = [x for x in findings if x not in deferred]
            if not findings:
                if guard["bad_streak"] > 0:
                    events.add("recovered", "异常在确认前已恢复，未触发保护")
                guard["bad_streak"] = 0
                self.write_guard(guard)
                return guard
            guard["bad_streak"] = int(guard["bad_streak"]) + 1
            if guard["bad_streak"] == 1:
                events.add("suspect", "发现异常，等待确认（%d 次）" % CONFIRM, findings)
            if guard["bad_streak"] >= CONFIRM:
                if state["claude_block"]:
                    if guard["bad_streak"] == CONFIRM:
                        events.add("info", "Claude 已处于隔离（真实 IP 模式），不重复动作", findings)
                    self.write_guard(guard)
                    return guard
                guard["lockdown"] = True
                guard["since"] = int(self.clock())
                guard["reasons"] = [x["text"] for x in findings]
                guard["reason_codes"] = sorted(set(x["key"] for x in findings))
                guard["triggers"] = int(guard["triggers"]) + 1
                state["claude_block"] = True
                try:
                    self.refresh_rules(state)  # Anthropic ranges now refused through the TUN too
                except pfrules.PFError as exc:
                    self.write_state(state)
                    util.log("隔离规则加载失败：%s" % exc, "watch")
                killed = self.kill_claude()
                summary = "已触发保护：Claude 已隔离，结束 %d 个 Claude 进程" % killed
                events.add("trigger", summary, findings, {"killed": killed})
                util.log(summary, "watch")
                self.notify("NetGuard 已锁定 Claude", "；".join(guard["reasons"])[:180] +
                            "。恢复后在 NetGuard 工作台点“解除锁定”。", key="trigger", every=60)
            self.write_guard(guard)
            return guard

    def shutdown_artifact(self, guard):
        """A lockdown caused only by medium findings in the minutes before this boot.

        At shutdown/restart macOS quits FlClash and ClaudeGuard before stopping the root
        daemon, so the watch sees "core/TUN/ClaudeGuard not running" twice and locks. The
        kill switch was intact (otherwise a high `killswitch` finding would be in the codes),
        so nothing leaked. Such a lockdown may be lifted after boot, but only through the
        same full checks as a manual `release`.
        """
        codes = guard.get("reason_codes") or []
        if not codes or any(events.RISK.get(c, ("高",))[0] == "高" for c in codes):
            return False
        boot = float(self.probes.boot_time() or 0)
        since = float(guard.get("since") or 0)
        return boot > 0 and since > 0 and 0 <= boot - since <= SHUTDOWN_WINDOW

    def try_boot_release(self, state, guard, integ):
        if not state["killswitch"]:
            return False
        findings, _ = self.observe(state, integ, require=True)
        if findings:
            return False  # keep locked; retried every tick until everything is ready
        state["claude_block"] = False
        self.refresh_rules(state)
        guard.update({"lockdown": False, "bad_streak": 0, "reasons": [], "reason_codes": []})
        events.add("release", "开机后自动解除：锁定发生在关机过程中（代理先于 NetGuard 退出，仅中危），"
                              "开机后全部检查通过，Claude 可以使用")
        util.log("开机后自动解除关机过程中产生的锁定", "watch")
        return True

    def enforce_isolation(self):
        state = self.read_state()
        if not state["claude_block"]:
            return 0
        killed = self.kill_claude()
        if killed and self.clock() - self._last_kill_event > 60:
            events.add("kill", "隔离期间结束了 %d 个重新启动的 Claude 进程" % killed)
            self._last_kill_event = self.clock()
        return killed

    def write_status(self):
        state = self.read_state()
        guard = self.read_guard()
        try:
            integ = self.pf.integrity(state.get("rules_fp"))
            integ["token_live"] = self.token_live()
        except Exception as exc:  # status must always be written
            integ = {"complete": False, "error": str(exc)}
        wanted = bool(state["killswitch"])
        last = events.read(1)
        status = {
            "status_version": 2, "platform": "macos", "version": VERSION, "updated_at": int(self.clock()),
            "wanted_killswitch": wanted,
            "killswitch_complete": bool(wanted and integ.get("complete")),
            "active_killswitch": bool(wanted and integ.get("complete") and integ.get("token_live")),
            "integrity": integ, "pending": state.get("pending"),
            "claude_block": bool(state["claude_block"]),
            "realip": bool(state["claude_block"] and not guard.get("lockdown")),
            "dns_block": bool(state.get("dns_block")),
            "guard": {k: guard.get(k) for k in ("enabled", "lockdown", "since", "reasons", "bad_streak",
                                                "last_check", "last_findings", "triggers", "grace_until",
                                                "duration")},
            "confirm": CONFIRM, "interval": INTERVAL,
            "observations": guard.get("observations") or {},
            "whitelist": self.cfg["whitelist"], "block_lan_dns": self.cfg["block_lan_dns"],
            "require_claudeguard": self.cfg["require_claudeguard"],
            "require_global_mode": self.cfg["require_global_mode"],
            "last_event": last[-1] if last else None,
            "source": util.read_json(paths.SOURCE, None),
        }
        util.write_json(paths.STATUS, status, mode=0o644)
        return status

    def watch(self, forever=True):
        prev = None
        while True:
            start = self.clock()
            if prev and start - prev > 60:
                self.resume_at = start  # slept: restart the grace period
            prev = start
            try:
                self.tick()
            except Exception as exc:
                util.log("自动防护检查出错：%s" % exc, "watch")
                try:
                    events.add("guard_error", "自动防护检查出错：%s" % exc, [events.finding("error", str(exc))])
                except Exception:
                    pass
            try:
                self.write_status()
            except Exception as exc:
                util.log("写状态出错：%s" % exc, "watch")
            while True:
                blocked = False
                try:
                    blocked = self.read_state()["claude_block"]
                    if blocked:
                        self.enforce_isolation()
                except Exception as exc:
                    util.log("隔离执行出错：%s" % exc, "watch")
                left = INTERVAL - (self.clock() - start)
                if left <= 0:
                    break
                self.sleep(min(ENFORCE_ISOLATED if blocked else ENFORCE_EVERY, left))
            if not forever:
                return

    # ------------------------------------------------------------------ commands
    def _require_whitelist(self):
        if not self.cfg["whitelist"]:
            raise UserError("白名单为空。先运行：sudo /Library/NetGuard/bin/netguard whitelist import-claudeguard"
                            " 或 whitelist add <IP>")

    def preflight(self):
        """Everything that must be true for the kill switch to leave a working network."""
        self._require_whitelist()
        cores = self.probes.find_core()
        if not cores:
            raise UserError("FlClash 内核没有运行。请先打开 FlClash，开启 TUN 并确认能上网，再开启断网保护。")
        privileged = [c for c in cores if c["privileged"]]
        if not privileged:
            raise UserError("FlClash 内核没有以 root 运行（TUN 未授权）。请在 FlClash 里开启 TUN 并按提示输入密码授权内核；"
                            "否则断网保护会把代理自己也拦住，整机断网。已拒绝开启。")
        gids = sorted(set(c["gid"] for c in privileged))
        if len(gids) != 1:
            raise UserError("发现多个用户组不同的 FlClash 内核进程 %s，无法确定放行对象。" % gids)
        if not self.probes.tun_interface():
            raise UserError("没有找到 FlClash 的 TUN 网卡（%s）。请在 FlClash 开启 TUN。" % self.cfg["tun_v4"])
        ip = self.probes.egress(self.cfg["check_url"])
        if not ip:
            raise UserError("当前无法通过代理联网，拒绝开启，以免整机断网。")
        if not config.ip_in_whitelist(ip, self.cfg["whitelist"]):
            raise UserError("当前出口 %s 不在白名单，请先让 FlClash 回到正常节点再开启。" % ip)
        return gids[0], ip

    def post_check(self):
        problems = []
        if not (self.probes.dns_reachable() and self.probes.dns_ok()):
            problems.append(DNS_PROBLEM)
        ip = self.probes.egress(self.cfg["check_url"])
        if not ip:
            problems.append("开启后无法通过代理联网")
        elif not config.ip_in_whitelist(ip, self.cfg["whitelist"]):
            problems.append("开启后出口 %s 不在白名单" % ip)
        physical = self.probes.physical_interfaces()
        for iface in physical:
            target = self.cfg["bypass_probe_targets"][0]
            if self.probes.direct_bypass(iface, target):
                problems.append("绑定物理网卡 %s 直连仍能联网：断网保护没有生效" % iface)
        return problems, ip, physical

    def enable(self, out=print):
        gid, before = self.preflight()
        mode = self.cfg["block_lan_dns"]
        attempts = [True, False] if mode == "auto" else [bool(mode)]
        with util.StateLock():
            state = self.read_state()
            prev = {k: state.get(k) for k in ("killswitch", "core_gid", "dns_block")}
            state["pending"] = {"deadline": self.clock() + PENDING_SECONDS, "prev": prev}
            state["killswitch"] = True
            state["core_uid"] = 0
            state["core_gid"] = gid
            problems, after, physical = [], None, []
            for dns_block in attempts:
                state["dns_block"] = dns_block
                self.write_state(state)
                try:
                    state["rules_fp"] = self.apply_rules(gid, state)
                    self.write_state(state)
                    out("规则已加载（局域网 DNS：%s），正在自检（DNS、代理出口、直连是否被拦）……"
                        % ("拦截" if dns_block else "放行"))
                    self.sleep(2)
                    problems, after, physical = self.post_check()
                except Exception as exc:
                    problems, after, physical = ["加载或自检出错：%s" % exc], None, []
                if not problems or not (dns_block and mode == "auto" and DNS_PROBLEM in problems):
                    break
                out("拦截局域网 DNS 后无法解析（系统 DNS 是路由器），改为放行局域网 DNS 再试……")
            if problems:
                self.rollback(state, prev, "开启断网保护后自检未通过，已恢复操作前状态：" + "；".join(problems))
                raise UserError("开启后自检未通过，已自动恢复，网络不受影响：\n- " + "\n- ".join(problems))
            state["pending"] = None
            self.write_state(state)
        if mode == "auto" and not state["dns_block"]:
            events.add("dns_relaxed", "开启时发现系统 DNS 是局域网路由器：局域网 DNS 保持放行（只暴露查询的域名，不泄露真实 IP）")
        events.add("config", "断网保护已开启（出口 %s；局域网 DNS %s）" % (after, "拦截" if state["dns_block"] else "放行"),
                   [events.finding("user", "用户开启断网保护")])
        util.log("已开启，出口 %s" % after, "enable")
        if not physical:
            out("提示：没找到活动的物理网卡，未做直连拦截测试。")
        out("断网保护已开启，出口 %s。直连已被拦截，代理流量正常。" % after)

    def disable(self, out=print):
        with util.StateLock():
            state = self.read_state()
            self.remove_rules()
            state.update({"killswitch": False, "claude_block": False, "rules_fp": None, "pending": None})
            self.write_state(state)
            guard = self.read_guard()
            if guard["lockdown"]:
                guard.update({"lockdown": False, "bad_streak": 0})
                self.write_guard(guard)
                events.add("release", "关闭断网保护时一并解除了自动防护锁定（用户操作，未做检查）")
        events.add("config", "断网保护已关闭（代理断开时可能经真实 IP 联网）", [events.finding("user", "用户关闭断网保护")])
        util.log("已关闭", "disable")
        out("断网保护已关闭，Claude 隔离已解除。")

    def release(self, out=print):
        with util.StateLock():
            state = self.read_state()
            guard = self.read_guard()
            if not guard["lockdown"]:
                out("当前没有自动防护锁定。")
                return
            if not state["killswitch"]:
                raise UserError("断网保护未开启，拒绝解除锁定（与 Windows 版相同）。先开启断网保护再解除；"
                                "或用“关闭断网保护”，它会一并解除锁定但不做检查。")
            integ = self.ensure_rules(state)
            findings, _ = self.observe(state, integ, require=True)
            if findings:
                events.add("release_refused", "解除被拒绝：检查仍未通过，保持锁定", findings)
                raise UserError("仍有异常，保持锁定：" + "；".join(x["text"] for x in findings))
            state["claude_block"] = False
            self.refresh_rules(state)
            guard.update({"lockdown": False, "bad_streak": 0, "reasons": [], "reason_codes": []})
            self.write_guard(guard)
            events.add("release", "检查全部通过，已解除锁定，Claude 可以重新打开")
        util.log("已解除自动防护锁定", "release")
        out("已解除锁定，Claude 可以重新打开。")

    def set_guard(self, enabled, out=print):
        with util.StateLock():
            guard = self.read_guard()
            guard["enabled"] = bool(enabled)
            guard["bad_streak"] = 0
            self.write_guard(guard)
        events.add("config", "自动防护已开启" if enabled else "自动防护已关闭（不影响断网保护规则和现有锁定）")
        out("自动防护已%s。" % ("开启" if enabled else "关闭"))

    def isolate(self, out=print):
        with util.StateLock():
            state = self.read_state()
            state["claude_block"] = True
            self.refresh_rules(state)
        killed = self.kill_claude()
        events.add("isolate", "已隔离 Claude（用户进入真实 IP 模式），结束 %d 个进程" % killed,
                   [events.finding("user", "用户进入真实 IP 模式")])
        out("Claude 已隔离：已结束 %d 个进程，重新打开也会被立即结束。" % killed)

    def unisolate(self, out=print):
        with util.StateLock():
            if self.read_guard()["lockdown"]:
                raise UserError("当前处于自动防护锁定，请用“解除锁定”（会先完整检查）。")
            ip = self.probes.egress(self.cfg["check_url"])
            cip = self.probes.egress(self.cfg["claude_check_url"])
            wl = self.cfg["whitelist"]
            if not wl or not config.ip_in_whitelist(ip, wl) or not config.ip_in_whitelist(cip, wl):
                raise UserError("出口尚未回到白名单（普通出口 %s，Claude 看到 %s），保持隔离。请先把 FlClash 切回正常模式。"
                                % (ip, cip))
            state = self.read_state()
            state["claude_block"] = False
            self.refresh_rules(state)
        events.add("unisolate", "已解除 Claude 隔离（出口 %s 已核实在白名单）" % ip,
                   [events.finding("user", "用户退出真实 IP 模式")])
        out("已解除 Claude 隔离，出口 %s。" % ip)

    def recover(self, out=print):
        """Emergency: remove NetGuard's rules even if the lock is held by a stuck process."""
        lock = util.StateLock(timeout=10)
        try:
            lock.__enter__()
        except util.CommandError:
            lock = None
            out("状态锁被占用，直接执行急救。")
        try:
            try:
                self.remove_rules()
            except pfrules.PFError as exc:
                out("移除规则时出错（继续）：%s" % exc)
            state = self.read_state()
            state.update({"killswitch": False, "claude_block": False, "rules_fp": None, "pending": None,
                          "dns_block": False})
            self.write_state(state)
            guard = self.read_guard()
            guard.update({"lockdown": False, "bad_streak": 0})
            self.write_guard(guard)
        finally:
            if lock is not None:
                lock.__exit__(None, None, None)
        events.add("recover", "执行了紧急恢复：已移除 NetGuard 的 pf 规则并关闭断网保护",
                   [events.finding("user", "用户执行紧急恢复")])
        util.log("紧急恢复", "recover")
        out("已移除 NetGuard 的全部 pf 规则，断网保护已关闭。若仍不能上网，问题不在 NetGuard（见 README 排查）。")

    def whitelist(self, op, value=None, out=print):
        if op == "list":
            for entry in self.cfg["whitelist"] or ["（白名单为空）"]:
                out(entry)
            return
        with util.StateLock():
            cfg = config.load()
            wl = list(cfg["whitelist"])
            if op == "add":
                entry = config.normalize_whitelist_entry(value)
                if entry not in wl:
                    wl.append(entry)
            elif op == "remove":
                entry = config.normalize_whitelist_entry(value)
                if entry not in wl:
                    raise UserError("白名单里没有 %s" % entry)
                wl.remove(entry)
            elif op == "import-claudeguard":
                user = self.probes.console_user()
                imported = config.claudeguard_whitelist(user[0]) if user else []
                if not imported:
                    raise UserError("没有从 ClaudeGuard 读到白名单（~/.config/claudeguard/config.json 的 allowed_ips）。")
                wl = sorted(set(wl) | set(imported))
            else:
                raise UserError("未知操作：%s" % op)
            cfg["whitelist"] = wl
            self.cfg = config.save(cfg)
            self.probes.cfg = self.cfg
        events.add("config", "白名单已更新（%s），共 %d 项" % (op, len(self.cfg["whitelist"])),
                   [events.finding("user", "用户修改白名单")])
        for entry in self.cfg["whitelist"] or ["（白名单为空）"]:
            out(entry)

    def verify(self, out=print):
        state = self.read_state()
        integ = self.pf.integrity(state.get("rules_fp")) if state["killswitch"] else None
        if integ is not None:
            integ["token_live"] = self.token_live()
        findings, obs = self.observe(state, integ, require=True)
        rows = []

        def row(ok, label, detail=""):
            rows.append(ok)
            out("%s %s%s" % ("✅" if ok else "❌", label, ("：" + detail) if detail else ""))

        row(bool(self.cfg["whitelist"]), "白名单", "%d 项" % len(self.cfg["whitelist"]))
        row(obs["egress_ok"], "普通出口在白名单", str(obs["egress"]))
        row(obs["claude_egress_ok"], "claude.ai 出口在白名单", str(obs["claude_egress"]))
        row(obs["core"]["running"] and obs["core"]["privileged"], "FlClash 内核以 root 运行（TUN 已授权）")
        row(bool(obs["tun"]), "TUN 网卡", str(obs["tun"]))
        row(bool(obs["tun"]) and obs.get("route") == obs["tun"], "公网流量经过 TUN", "路由接口 %s" % obs.get("route"))
        mode = (obs.get("flclash") or {}).get("mode")
        if self.cfg["require_global_mode"]:
            row(mode == "global", "FlClash 全局模式", {"global": "全局", "rule": "规则", "direct": "直连"}.get(mode, "读不到配置"))
        row(state["killswitch"], "断网保护已开启")
        if integ is not None:
            row(integ["complete"], "pf 规则完整", "pf=%s 锚点引用=%s 规则=%s 条" % (
                integ["pf_enabled"], integ["main_anchor_ref"], integ["rule_count"]))
            row(integ.get("token_live", False), "pf 启用引用（token）有效")
            row(self.probes.dns_ok() and self.probes.dns_reachable(), "DNS 解析正常（含不经缓存的直接查询）")
            out("ℹ️ 局域网 DNS：%s（设置 %s）" % ("拦截" if state.get("dns_block") else "放行", self.cfg["block_lan_dns"]))
            physical = self.probes.physical_interfaces()
            for iface in physical:
                leaked = self.probes.direct_bypass(iface, self.cfg["bypass_probe_targets"][0])
                row(not leaked, "绑定 %s 直连被拦截" % iface)
            others = self.probes.exemption_users(state.get("core_gid"), self.cfg["core_names"]) \
                if state.get("core_gid") else []
            row(not others, "没有其他程序使用代理内核的放行身份联网", "、".join(others))
        if self.cfg["require_claudeguard"]:
            cg = obs.get("claudeguard") or {}
            row(cg.get("installed") and cg.get("fresh"), "ClaudeGuard 正在运行",
                "状态 %s，%s 秒前更新" % (cg.get("state"), cg.get("age")))
            row(cg.get("protection_enabled") is not False, "ClaudeGuard 保护开启")
            row(cg.get("helper_loaded") is True, "ClaudeGuard root 网络助手在运行")
            out("ℹ️ ClaudeGuard 兼容补丁：%s" % {"patched": "已应用", "original": "未应用（原版 61b61e1）",
                                               "unknown": "未知版本（ClaudeGuard 可能已升级）"}.get(cg.get("cg_patch"), "—"))
            row(cg.get("cli_hooked") is not False, "claude 命令经过 ClaudeGuard",
                "、".join(l["path"] for l in cg.get("cli_links") or []) or "未安装 Claude Code（不适用）")
            def installed(key, ok_key):
                if cg.get(ok_key) is None:
                    return "未安装（不适用）"
                return "、".join(cg.get(key) or [])
            row(cg.get("app_path_ok") is not False and cg.get("cli_path_ok") is not False,
                "ClaudeGuard 跟上了已安装的 Claude", "桌面版：%s；Claude Code：%s" % (
                    installed("app_installed", "app_path_ok"), installed("cli_installed", "cli_path_ok")))
        guard = self.read_guard()
        row(not guard["lockdown"], "没有自动防护锁定", "；".join(guard.get("reasons") or []))
        out("界面绿色只表示当前检查通过；真实停代理、睡眠唤醒、切换网络需另行验收（见 macos/ACCEPTANCE.md）。")
        return all(rows)
