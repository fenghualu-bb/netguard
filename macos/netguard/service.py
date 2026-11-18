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
# An exit outside the whitelist is not a flaky reading: every second Claude keeps running,
# Anthropic sees a non-whitelisted IP. These lock on the first sighting (also inside grace).
IMMEDIATE = ("egress", "egress_claude", "proxy_down", "anthropic_moved")
# Direct mode: a lockdown caused only by the proxy being off lifts itself once the proxy is
# back and every release check passes (the same checks as a manual release).
AUTO_RELEASE_CODES = {"proxy_down", "core", "tun"}
DIRECT_REFRESH = 600          # re-resolve Claude's hosts for the ng_direct table this often
DIRECT_KEEP = 7 * 86400       # an address not seen for this long leaves the table
EGRESS_FAST = 3  # between full checks, the ordinary exit is re-read this often
ENFORCE_EVERY = 2
ENFORCE_ISOLATED = 0.25  # dedicated thread: a relaunched Claude is ended within about a quarter second
CLEANUP_EVERY = 0.5  # otherwise the same thread looks for leftovers of a quit Claude this often
GRACE_SECONDS = 180
PENDING_SECONDS = 120
SHUTDOWN_WINDOW = 600  # a medium-only lockdown this close before boot came from the shutdown
CLAUDE_PATH_SETTLE = 90  # ClaudeGuard re-attaches its hooks every 60 s after a Claude update
EXEMPT_CHECK_EVERY = 60
CLAUDE_TABLE_EVERY = 60  # re-resolve Claude's fake-ip addresses while isolated
DNS_PROBLEM = "DNS 解析失败"

STATE_DEFAULTS = {"killswitch": False, "claude_block": False, "core_uid": 0, "core_gid": None,
                  "rules_fp": None, "pending": None, "dns_block": False,
                  "direct": False, "direct_block": {}, "direct_check": None}
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
                 sleeper=time.sleep, engine=None):
        self.cfg = cfg if cfg is not None else config.load()
        self.probes = probes or probes_mod.Probes(self.cfg)
        self.pf = pf or pfrules.PF()
        self.engine = engine or claude.Engine(self.cfg, snapshot=self.probes.processes, roots=self._claude_roots)
        self.clock = clock
        self.sleep = sleeper
        self._notifier = notifier
        self._killer = killer
        self.resume_at = 0
        self._last_kill_event = 0
        self._first_seen = {}
        self._last_exempt_check = 0
        self._exempt_seen = set()
        self._claude_table = {"at": 0, "count": None}
        self._last_fast = 0
        self._cfg_stamp = self._config_stamp()
        self._direct = {"running": False, "result": None, "at": 0, "via": None}
        self._spawn = self._spawn_thread

    @staticmethod
    def _spawn_thread(fn):
        import threading
        threading.Thread(target=fn, name="netguard-direct-resolve", daemon=True).start()

    # ------------------------------------------------------------------ direct mode: Claude's hosts
    def resolve_direct_hosts(self, via):
        """Blocking (seconds). Real addresses of Claude's hosts and the main-host range check."""
        import ipaddress
        nets = [ipaddress.ip_network(n) for n in self.cfg["anthropic_v4"] + self.cfg["anthropic_v6"]]

        def inside(ip):
            addr = ipaddress.ip_address(ip)
            return any(addr.version == n.version and addr in n for n in nets)
        answers = self.probes.resolve_public(claude.MAIN_HOSTS + claude.AUX_HOSTS, via=via)
        moved = sorted(set(ip for h in claude.MAIN_HOSTS for ip in answers.get(h, []) if not inside(ip)))
        aux = sorted(set(ip for h in claude.AUX_HOSTS for ip in answers.get(h, []) if not inside(ip)))
        return {"at": int(self.clock()), "via": via, "aux": aux, "moved": moved,
                "answered": sum(1 for v in answers.values() if v)}

    def start_direct_refresh(self, via):
        if self._direct["running"]:
            return
        self._direct.update(running=True, at=self.clock(), via=via)

        def job():
            try:
                self._direct["result"] = self.resolve_direct_hosts(via)
            except Exception as exc:
                util.log("Claude 地址解析失败：%s" % exc, "direct")
            finally:
                self._direct["running"] = False
        self._spawn(job)

    def merge_direct(self, state, result):
        """Fold one resolution into the ng_direct table (kept DIRECT_KEEP). True if it changed."""
        if not result or not result.get("answered"):
            return False  # nothing resolved (offline): keep what is loaded
        now = int(self.clock())
        before = set(self.direct_block(state))
        table = dict(state.get("direct_block") or {})
        for ip in result["aux"] + result["moved"]:
            table[ip] = now
        table = {ip: seen for ip, seen in table.items() if now - int(seen) < DIRECT_KEEP}
        state["direct_block"] = table
        old_moved = set((state.get("direct_check") or {}).get("moved") or [])
        state["direct_check"] = {k: result[k] for k in ("at", "via", "moved", "answered")}
        if result["moved"] and set(result["moved"]) != old_moved:
            events.add("anthropic_moved", "Claude 主站解析到 Anthropic 网段以外的地址，已加入拦截表：%s"
                       % "、".join(result["moved"]), [events.finding("anthropic_moved", "主站地址不在官方网段")])
        return set(table) != before

    def direct_housekeeping(self, state, obs):
        """Called from tick with the lock held: apply a finished resolution, start the next."""
        if not self.direct_on(state):
            return
        result, self._direct["result"] = self._direct["result"], None
        if result and self.merge_direct(state, result):
            try:
                self.refresh_rules(state)
                util.log("直连模式拦截表更新为 %d 个地址" % len(state["direct_block"]), "direct")
            except pfrules.PFError as exc:
                util.log("直连模式拦截表加载失败：%s" % exc, "direct")
        elif result:
            self.write_state(state)
        via = "doh" if obs.get("proxy_up") else "system"
        check = state.get("direct_check") or {}
        last = max(float(check.get("at") or 0), float(self._direct["at"]))
        last_via = self._direct["via"] or check.get("via")
        if self.clock() - last >= DIRECT_REFRESH or via != last_via:
            self.start_direct_refresh(via)

    # ------------------------------------------------------------------ config
    @staticmethod
    def _config_stamp():
        try:
            info = os.stat(paths.CONFIG)
        except OSError:
            return None
        return (info.st_mtime_ns, info.st_size, info.st_ino)

    def reload_config(self):
        """Pick up `whitelist add/remove` made by another process (the long-running daemon).

        An unreadable or invalid file keeps the configuration already in use.
        """
        stamp = self._config_stamp()
        if stamp is None or stamp == self._cfg_stamp:
            return False
        try:
            cfg = config.load()
        except config.ConfigError as exc:
            util.log("config.json 无效，继续使用原配置：%s" % exc, "watch")
            self._cfg_stamp = stamp
            return False
        self._cfg_stamp = stamp
        self.cfg = cfg
        self.probes.cfg = cfg
        self.engine.cfg = cfg
        util.log("已重新读取配置（白名单 %d 项）" % len(cfg["whitelist"]), "watch")
        return True

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

    def _claude_roots(self):
        roots = [a.rstrip("/") for a in self.cfg["claude_app_paths"]]
        home = getattr(self.probes, "user_home", lambda: None)()
        if home:
            roots += probes_mod.find_claude_apps(home)
        return roots

    def kill_claude(self):
        if self._killer:
            return self._killer()
        return self.engine.isolate_now()

    def cleanup_claude(self):
        """Leftovers of a quit Claude Desktop (merged from ClaudeExitGuard). Never raises."""
        user = self.probes.console_user()
        result = self.engine.cleanup_step(user[1] if user else None)
        if not result:
            return None
        cleaned = [p["name"] for p in result["cleaned"]]
        failed = [p["name"] for p in result["failed"]]
        summary = "Claude 已退出，结束了 %d 个残留进程" % len(cleaned)
        if cleaned:
            summary += "：" + claude.summarize(cleaned)
        if failed:
            summary += "；%d 个未能结束：%s" % (len(failed), claude.summarize(failed))
        events.add("cleanup", summary, None, result)
        util.log(summary, "cleanup")
        self.notify("NetGuard：已清理 Claude 残留进程" if not failed else "NetGuard：有 Claude 残留进程未能结束",
                    summary[:180], key="cleanup", every=5)
        return result

    def enforcer_loop(self, stop, wait=None):
        """Dedicated thread: the only place that scans for Claude processes.

        While isolated it ends Claude every ENFORCE_ISOLATED seconds and never waits for a
        tick (whose exit probes can take seconds), so a relaunched Claude is ended within
        about a quarter of a second. Otherwise it cleans up after a quit Claude Desktop.
        """
        wait = wait or stop.wait
        while not stop.is_set():
            blocked = False
            try:
                blocked = self.read_state()["claude_block"]
                if blocked:
                    self.enforce_isolation()
                else:
                    self.cleanup_claude()
            except Exception as exc:
                util.log("Claude 进程检查出错：%s" % exc, "enforcer")
            wait(ENFORCE_ISOLATED if blocked else CLEANUP_EVERY)

    def start_enforcer(self):
        import threading
        stop = threading.Event()
        thread = threading.Thread(target=self.enforcer_loop, args=(stop,), name="netguard-enforcer", daemon=True)
        thread.start()
        return stop, thread

    # ------------------------------------------------------------------ pf
    @staticmethod
    def direct_on(state):
        return bool(state.get("killswitch") and state.get("direct"))

    @staticmethod
    def direct_block(state):
        return sorted((state.get("direct_block") or {}).keys())

    def integrity(self, state, fp=None):
        direct = bool(state.get("direct"))
        return self.pf.integrity(state.get("rules_fp") if fp is None else fp, direct=direct,
                                 direct_block=self.direct_block(state) if direct else None)

    def apply_rules(self, core_gid, state=None):
        state = state if state is not None else self.read_state()
        text = pfrules.render(self.cfg, 0, core_gid, dns_block=bool(state.get("dns_block")),
                              isolate=bool(state.get("claude_block")), direct=bool(state.get("direct")),
                              direct_block=self.direct_block(state))
        self.pf.load(text)
        util.write_text(paths.ANCHOR_FILE, text, mode=0o644)
        token = self.pf.acquire_token(self.read_token())
        self.write_token(token)
        if state.get("claude_block"):
            self.fill_claude_table()  # a reload empties the table
        else:
            self.pf.drop_claude_table()
            self._claude_table = {"at": 0, "count": None}
        return pfrules.fingerprint(self.pf.anchor_rules())

    def fill_claude_table(self):
        """Refuse Claude's fake-ip addresses through the TUN. Never raises; returns the count or None."""
        self._claude_table["at"] = self.clock()
        if not self.probes.tun_interface():
            return self._claude_table["count"]  # nothing resolves now; keep what is loaded
        try:
            addresses = self.probes.tun_addresses(claude.DOMAINS)
            self.pf.set_claude_table(addresses)
        except Exception as exc:
            util.log("隔离地址表更新失败：%s" % exc, "watch")
            return self._claude_table["count"]
        self._claude_table["count"] = len(addresses)
        return len(addresses)

    def claude_table_note(self):
        count = self._claude_table["count"]
        if count is None:
            return ""
        if count:
            return "；TUN 内同时拒绝 Claude 域名的 %d 个代理地址" % count
        return "；未取得 Claude 域名的代理地址（FlClash 未使用 fake-ip 时属正常）"

    def remove_rules(self):
        self.pf.flush()
        self.pf.drop_claude_table()
        self.pf.drop_direct_table()
        self._claude_table = {"at": 0, "count": None}
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
        integ = self.integrity(state)
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
            integ = self.integrity(state, fp)
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
        state["direct"] = bool(prev.get("direct"))
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
        elif state.get("killswitch") and not wl:
            # Without a whitelist no exit can be judged, so the exit guard would silently stop.
            f.append(events.finding("egress", "白名单为空，无法核对出口是否安全"))
        tun = self.probes.tun_interface()
        route = self.probes.route_interface()
        proxy_up = bool(tun) and (not route or route == tun)
        obs.update(tun=tun, route=route, proxy_up=proxy_up)
        direct_down = self.direct_on(state) and not proxy_up
        obs["proxy_down_direct"] = direct_down
        if direct_down:
            # Direct mode with the proxy off: the exit IS the real IP by the user's choice, so it
            # is not probed (nothing to learn, and no request needs to go out with it). Claude is
            # isolated until the proxy carries traffic again and every check below passes.
            obs.update(egress=None, egress_ok=False, claude_egress=None, claude_egress_ok=False)
            f.append(events.finding("proxy_down", "代理已断开（直连模式）：其他程序可用真实 IP 上网，Claude 保持隔离"))
        else:
            ip = self.probes.egress(cfg["check_url"])
            obs["egress"] = ip
            obs["egress_ok"] = config.ip_in_whitelist(ip, wl)
            if require and not ip:
                f.append(events.finding("egress", "普通出口未取得，保持锁定"))
            if ip and wl and not obs["egress_ok"]:
                f.append(events.finding("egress", "普通出口 %s 不在白名单" % ip))
            cip = self.probes.claude_egress(cfg["claude_check_url"], isolated=bool(state.get("claude_block")))
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
        if direct_down:
            pass  # reported once as proxy_down above
        elif not tun:
            f.append(events.finding("tun", "TUN 虚拟网卡未连接"))
        elif route and route != tun:
            f.append(events.finding("tun", "TUN 已连接，但公网流量没有经过它（路由指向 %s）" % route))
        obs["flclash_ui"] = self.probes.flclash_ui()
        fl = self.probes.flclash_config()
        obs["flclash"] = fl
        if cfg["require_global_mode"] and fl.get("mode") in ("rule", "direct") and not direct_down:
            f.append(events.finding("mode", "FlClash 是%s模式，不是全局模式" % {"rule": "规则", "direct": "直连"}[fl["mode"]]))
        moved = (state.get("direct_check") or {}).get("moved") if self.direct_on(state) else None
        if moved:
            f.append(events.finding("anthropic_moved", "Claude 主站解析到 Anthropic 网段以外的地址：%s"
                                    % "、".join(moved)[:160]))
        if state.get("killswitch") and integ is not None:
            obs["integrity"] = integ
            # As on Windows: a failed read is not proof of missing rules (shown in status only).
            if not integ.get("complete") and not integ.get("read_error"):
                f.append(events.finding("killswitch", "断网保护规则不完整" + (
                    "（pf 主规则集缺少 com.apple/* 锚点，可能开启了“互联网共享”）"
                    if integ.get("pf_enabled") and not integ.get("main_anchor_ref") else "")))
            if integ.get("complete"):
                permits = self.foreign_permits(direct=bool(state.get("direct")))
                obs["foreign_permits"] = ["%s：%s" % p for p in permits]
                if permits:
                    f.append(events.finding("pf_bypass", "其他防火墙规则可能绕过断网保护（共 %d 条，第一条在 %s：%s）"
                                            % (len(permits), permits[0][0], permits[0][1][:120])))
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

    def foreign_permits(self, direct=False):
        try:
            return self.pf.foreign_permits(direct=direct)
        except pfrules.PFError:
            return []  # a failed read is not proof of a bypass

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
        # In direct mode there is no default block, hence no proxy-core exemption to share.
        if not state.get("killswitch") or not state.get("core_gid") or state.get("direct"):
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
        self.reload_config()
        with util.StateLock():
            state = self.read_state()
            guard = self.read_guard()
            self.handle_pending(state)
            integ = self.ensure_rules(state) if state["killswitch"] else None
            if state["killswitch"] and state["claude_block"] and \
                    self.clock() - self._claude_table["at"] >= CLAUDE_TABLE_EVERY:
                self.fill_claude_table()
            findings, obs = self.observe(state, integ)
            if self.dns_safety_valve(state, obs):
                integ = self.ensure_rules(state)
            self.direct_housekeeping(state, obs)
            self.check_exemption(state, obs)
            obs["dns_block"] = bool(state.get("dns_block"))
            guard["last_check"] = int(self.clock())
            guard["last_findings"] = [x["text"] for x in findings]
            guard["observations"] = obs
            guard["duration"] = round(self.clock() - started, 1)
            findings = self.settle(findings)
            grace = self.grace_info()
            guard["grace_until"] = int(grace["until"]) if grace["active"] else 0
            if state["killswitch"] and not state.get("direct") and not grace["active"] and \
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
                elif self.proxy_down_artifact(state, guard) and obs.get("proxy_up"):
                    if self.try_boot_release(state, guard, integ, message=(
                            "代理已恢复：全部检查通过，自动解除直连模式下的 Claude 隔离")):
                        self.notify("NetGuard：代理已恢复", "全部检查通过，Claude 可以使用了。", key="proxy-back", every=5)
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
            immediate = any(x["key"] in IMMEDIATE for x in findings)
            if immediate and guard["bad_streak"] < CONFIRM:
                guard["bad_streak"] = CONFIRM  # confirmed now; no second reading
            elif guard["bad_streak"] == 1:
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
                summary = "已触发保护：Claude 已隔离，结束 %d 个 Claude 进程" % killed + self.claude_table_note()
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

    def proxy_down_artifact(self, state, guard):
        """Direct mode: a lockdown caused only by the proxy being off (nothing high besides it)."""
        codes = set(guard.get("reason_codes") or [])
        return self.direct_on(state) and "proxy_down" in codes and codes <= AUTO_RELEASE_CODES

    def try_boot_release(self, state, guard, integ, message=None):
        """Lift a lockdown automatically, but only through the full checks of a manual release."""
        if not state["killswitch"]:
            return False
        findings, _ = self.observe(state, integ, require=True)
        if findings:
            return False  # keep locked; retried every tick until everything is ready
        state["claude_block"] = False
        self.refresh_rules(state)
        guard.update({"lockdown": False, "bad_streak": 0, "reasons": [], "reason_codes": []})
        message = message or ("开机后自动解除：锁定发生在关机过程中（代理先于 NetGuard 退出，仅中危），"
                              "开机后全部检查通过，Claude 可以使用")
        events.add("release", message)
        util.log(message, "watch")
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
            integ = self.integrity(state)
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
            "claude_table": self._claude_table["count"] if state["claude_block"] else None,
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
            "claude": self.claude_status(),
            "proxy_down": self.cfg["proxy_down"],
            "direct": bool(state.get("direct")),
            "direct_block": len(state.get("direct_block") or {}),
            "direct_check": state.get("direct_check"),
        }
        util.write_json(paths.STATUS, status, mode=0o644)
        return status

    def claude_status(self):
        """The daemon's process view. A CLI command that rewrites status.json has not scanned
        anything itself, so it keeps the daemon's last view instead of showing zero."""
        current = self.engine.status()
        if current["checked_at"]:
            return current
        previous = (util.read_json(paths.STATUS, {}) or {}).get("claude")
        if isinstance(previous, dict):
            previous = dict(previous, policy=current["policy"])
            return previous
        return current

    def fast_egress_due(self):
        """Cheap exit re-check between full checks. True = run a full check now.

        Only while protection could still act: guard on, not locked, Claude not isolated.
        """
        if self.clock() - self._last_fast < EGRESS_FAST:
            return False
        self._last_fast = self.clock()
        self.reload_config()
        guard = self.read_guard()
        wl = self.cfg["whitelist"]
        state = self.read_state()
        if not guard["enabled"] or guard["lockdown"] or not wl or state["claude_block"]:
            return False
        if self.direct_on(state) and not self.probes.tun_interface():
            return True  # direct mode: the proxy went away, isolate Claude now (ifconfig, ~1 ms)
        ip = self.probes.egress(self.cfg["check_url"], max_time=2)
        return bool(ip) and not config.ip_in_whitelist(ip, wl)

    def watch(self, forever=True):
        prev = None
        if forever:
            self.start_enforcer()
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
                    # With forever=True the enforcer thread is the only process scanner; this
                    # loop used to end Claude as well, doubling the cost while isolated.
                    if blocked and not forever:
                        self.enforce_isolation()
                except Exception as exc:
                    util.log("隔离执行出错：%s" % exc, "watch")
                try:
                    if not blocked and self.fast_egress_due():
                        util.log("快速出口检查发现出口不在白名单，立即完整检查", "watch")
                        break  # the next full check locks on this first sighting
                except Exception as exc:
                    util.log("快速出口检查出错：%s" % exc, "watch")
                left = INTERVAL - (self.clock() - start)
                if left <= 0:
                    break
                self.sleep(min(ENFORCE_ISOLATED if blocked and not forever else ENFORCE_EVERY, left))
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

    def direct_canary(self):
        """Direct mode self-test: a non-TUN connection to an address in ng_direct must fail.

        A public canary (bypass_probe_targets[1]) is added to the table for the test only and
        removed afterwards; the Anthropic-range rules have the same shape. Nothing is sent to
        Anthropic. Returns (interfaces tested, interfaces that leaked).
        """
        canary = self.cfg["bypass_probe_targets"][-1]
        physical = self.probes.physical_interfaces()
        leaked = []
        self.pf.direct_table_add(canary)
        try:
            for iface in physical:
                if self.probes.direct_bypass(iface, canary):
                    leaked.append(iface)
        finally:
            self.pf.direct_table_delete(canary)
        return physical, leaked

    def post_check(self, direct=False):
        problems = []
        if not (self.probes.dns_reachable() and self.probes.dns_ok()):
            problems.append(DNS_PROBLEM)
        ip = self.probes.egress(self.cfg["check_url"])
        if not ip:
            problems.append("开启后无法通过代理联网")
        elif not config.ip_in_whitelist(ip, self.cfg["whitelist"]):
            problems.append("开启后出口 %s 不在白名单" % ip)
        if direct:
            physical, leaked = self.direct_canary()
            for iface in leaked:
                problems.append("绑定物理网卡 %s 仍能直连拦截表中的地址：直连模式的拦截没有生效" % iface)
            return problems, ip, physical
        physical = self.probes.physical_interfaces()
        for iface in physical:
            target = self.cfg["bypass_probe_targets"][0]
            if self.probes.direct_bypass(iface, target):
                problems.append("绑定物理网卡 %s 直连仍能联网：断网保护没有生效" % iface)
        return problems, ip, physical

    def enable(self, out=print):
        gid, before = self.preflight()
        direct = self.cfg["proxy_down"] == "direct"
        mode = self.cfg["block_lan_dns"]
        # Direct mode never blocks LAN DNS: with the proxy off the router is the only resolver.
        attempts = [False] if direct else ([True, False] if mode == "auto" else [bool(mode)])
        resolved = None
        if direct:
            out("直连模式：正在经代理解析 Claude 各网址的真实地址（约 10 秒）……")
            try:
                resolved = self.resolve_direct_hosts("doh")
            except Exception as exc:
                util.log("开启时解析 Claude 地址失败：%s" % exc, "enable")
        with util.StateLock():
            state = self.read_state()
            prev = {k: state.get(k) for k in ("killswitch", "core_gid", "dns_block", "direct")}
            state["pending"] = {"deadline": self.clock() + PENDING_SECONDS, "prev": prev}
            state["killswitch"] = True
            state["core_uid"] = 0
            state["core_gid"] = gid
            state["direct"] = direct
            if direct:
                self.merge_direct(state, resolved)
            problems, after, physical = [], None, []
            for dns_block in attempts:
                state["dns_block"] = dns_block
                self.write_state(state)
                try:
                    state["rules_fp"] = self.apply_rules(gid, state)
                    self.write_state(state)
                    if direct:
                        out("规则已加载（直连模式，拦截表 %d 个地址），正在自检（DNS、代理出口、拦截表是否生效）……"
                            % len(state["direct_block"]))
                    else:
                        out("规则已加载（局域网 DNS：%s），正在自检（DNS、代理出口、直连是否被拦）……"
                            % ("拦截" if dns_block else "放行"))
                    self.sleep(2)
                    problems, after, physical = self.post_check(direct=direct)
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
        if direct:
            events.add("config", "断网保护已开启（直连模式：代理断开时其他程序可用真实 IP，Claude 立即隔离；出口 %s；"
                       "拦截表 %d 个地址）" % (after, len(state["direct_block"])),
                       [events.finding("user", "用户开启断网保护（直连模式）")])
            util.log("已开启（直连模式），出口 %s" % after, "enable")
            if not physical:
                out("提示：没找到活动的物理网卡，未做拦截表测试。")
            out("断网保护已开启（直连模式），出口 %s。代理断开时浏览器等程序可以直连，Claude 会被立即隔离；"
                "Anthropic 网段和 Claude 的 %d 个其他地址只能经代理访问。" % (after, len(state["direct_block"])))
            return
        if mode == "auto" and not state["dns_block"]:
            events.add("dns_relaxed", "开启时发现系统 DNS 是局域网路由器：局域网 DNS 保持放行（只暴露查询的域名，不泄露真实 IP）")
        events.add("config", "断网保护已开启（出口 %s；局域网 DNS %s）" % (after, "拦截" if state["dns_block"] else "放行"),
                   [events.finding("user", "用户开启断网保护")])
        util.log("已开启，出口 %s" % after, "enable")
        if not physical:
            out("提示：没找到活动的物理网卡，未做直连拦截测试。")
        out("断网保护已开启，出口 %s。直连已被拦截，代理流量正常。" % after)

    def set_proxy_down(self, policy, out=print):
        """Switch between "block" (kill switch) and "direct", then re-run enable with its self-test.

        Only while the proxy works (enable's preflight); a failed self-test rolls everything back,
        including the setting.
        """
        if policy not in ("block", "direct"):
            raise UserError('只能是 block 或 direct')
        with util.StateLock():
            cfg = config.load()
            old = cfg["proxy_down"]
            cfg["proxy_down"] = policy
            self.cfg = config.save(cfg)
            self.probes.cfg = self.engine.cfg = self.cfg
            self._cfg_stamp = self._config_stamp()
        events.add("config", "代理断开时：%s" % ("允许直连（Claude 立即隔离）" if policy == "direct" else "整机断网"),
                   [events.finding("user", "用户切换代理断开时的处理方式")])
        if not self.read_state()["killswitch"]:
            out("已设置。断网保护尚未开启，开启时按此方式生效。")
            return
        try:
            self.enable(out=out)
        except Exception:
            with util.StateLock():
                cfg = config.load()
                cfg["proxy_down"] = old
                self.cfg = config.save(cfg)
                self.probes.cfg = self.engine.cfg = self.cfg
                self._cfg_stamp = self._config_stamp()
            events.add("config", "切换未完成，已恢复原设置（%s）" % old)
            raise

    def set_cleanup(self, policy, out=print):
        """Cleanup after quit: full / desktop / off. No pf change; the daemon reloads it within 10 s."""
        if policy not in claude.CLEANUP_POLICIES:
            raise UserError("只能是 full、desktop 或 off")
        with util.StateLock():
            cfg = config.load()
            cfg["claude_cleanup"] = policy
            self.cfg = config.save(cfg)
            self.probes.cfg = self.engine.cfg = self.cfg
            self._cfg_stamp = self._config_stamp()
        text = {"full": "Claude 退出后清理残留进程和单独运行的 Claude Code",
                "desktop": "Claude 退出后只清理桌面版的残留进程", "off": "Claude 退出后不清理残留进程"}[policy]
        events.add("config", text, [events.finding("user", "用户修改退出后清理设置")])
        out(text + "（10 秒内生效）。")

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
        events.add("isolate", "已隔离 Claude（用户进入真实 IP 模式），结束 %d 个进程" % killed + self.claude_table_note(),
                   [events.finding("user", "用户进入真实 IP 模式")])
        out("Claude 已隔离：已结束 %d 个进程，重新打开也会被立即结束。" % killed)

    def unisolate(self, out=print):
        with util.StateLock():
            if self.read_guard()["lockdown"]:
                raise UserError("当前处于自动防护锁定，请用“解除锁定”（会先完整检查）。")
            state = self.read_state()
            ip = self.probes.egress(self.cfg["check_url"])
            cip = self.probes.claude_egress(self.cfg["claude_check_url"], isolated=bool(state.get("claude_block")))
            wl = self.cfg["whitelist"]
            if not wl or not config.ip_in_whitelist(ip, wl) or not config.ip_in_whitelist(cip, wl):
                raise UserError("出口尚未回到白名单（普通出口 %s，Claude 看到 %s），保持隔离。请先把 FlClash 切回正常模式。"
                                % (ip, cip))
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
                if len(wl) == 1 and self.read_state()["killswitch"]:
                    raise UserError("断网保护开启时不能删除最后一个白名单 IP（删空后无法核对出口）。"
                                    "请先添加新的 IP，再删除 %s。" % entry)
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
            self._cfg_stamp = self._config_stamp()
        events.add("config", "白名单已更新（%s），共 %d 项" % (op, len(self.cfg["whitelist"])),
                   [events.finding("user", "用户修改白名单")])
        for entry in self.cfg["whitelist"] or ["（白名单为空）"]:
            out(entry)

    def verify(self, out=print):
        state = self.read_state()
        integ = self.integrity(state) if state["killswitch"] else None
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
            permits = self.foreign_permits(direct=bool(state.get("direct")))
            row(not permits, "没有其他防火墙规则能绕过断网保护",
                "；".join("%s：%s" % p for p in permits)[:300])
            row(self.probes.dns_ok() and self.probes.dns_reachable(), "DNS 解析正常（含不经缓存的直接查询）")
            if state.get("direct"):
                out("ℹ️ 代理断开时：允许直连（Claude 立即隔离，代理恢复且检查通过后自动解除）")
                row(bool(state.get("direct_block")), "Claude 其他地址拦截表", "%d 个地址" % len(state.get("direct_block") or {}))
                check = state.get("direct_check") or {}
                row(bool(check) and not check.get("moved"), "Claude 主站解析在 Anthropic 网段内",
                    ("尚未核对" if not check else "、".join(check.get("moved") or []) or
                     "%s 核对（%s）" % (time.strftime("%m-%d %H:%M", time.localtime(check.get("at", 0))),
                                     "经代理 DoH" if check.get("via") == "doh" else "系统 DNS")))
                with util.StateLock():  # the daemon must not reload the table during the test
                    physical, leaked = self.direct_canary()
                for iface in physical:
                    row(iface not in leaked, "绑定 %s 访问拦截表中的地址被拒绝" % iface)
            else:
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
