"""One engine that finds every Claude process, used for isolation and for cleanup after quit.

macOS pf cannot filter by program, so isolation means: every Claude process found is
terminated, and the daemon keeps terminating relaunches every 0.25 seconds until the
isolation is lifted (Windows uses a per-program WFP block for the same purpose).

Identification (merged from ClaudeExitGuard): the executable path as the kernel reports
it, never command-line text, plus the real process tree. Children that Claude starts
(shells, node/python MCP servers, dev servers) are followed, and stay tracked even after
they are re-parented to launchd when their Claude parent exits.

Cleanup after quit (also from ClaudeExitGuard): when Claude Desktop is no longer running,
processes it left behind are ended with SIGTERM, then SIGKILL; with the "full" policy a
stand-alone Claude Code is ended too. Every signal re-checks pid, start time and path.
"""
import errno
import os
import re
import signal
import threading
import time

from . import procs as procs_mod

# Names resolved through FlClash while Claude is isolated. With fake-ip DNS each name gets
# its own address in the TUN range; those addresses are refused through the TUN.
# Unlisted subdomains are not covered (ClaudeGuard's hosts block is the backstop).
DOMAINS = (
    "claude.ai", "www.claude.ai", "app.claude.ai", "api.claude.ai", "auth.claude.ai",
    "assets.claude.ai", "a-cdn.claude.ai", "a-api.claude.ai", "console.claude.ai", "status.claude.ai",
    "claude.com", "www.claude.com", "app.claude.com", "api.claude.com", "auth.claude.com",
    "console.claude.com", "code.claude.com", "docs.claude.com", "support.claude.com",
    "platform.claude.com", "status.claude.com",
    "claude.usercontent.com",
    "anthropic.com", "www.anthropic.com", "api.anthropic.com", "console.anthropic.com",
    "statsig.anthropic.com", "a-api.anthropic.com", "a-cdn.anthropic.com", "assets.anthropic.com",
    "desktop-app-updates.anthropic.com", "docs.anthropic.com", "support.anthropic.com",
    "status.anthropic.com", "events.anthropic.com", "feedback.anthropic.com",
    "anthropic.ai", "www.anthropic.ai", "api.anthropic.ai",
)

# Direct mode. MAIN_HOSTS must resolve inside Anthropic's ranges (checked every 10 minutes;
# otherwise the browser could open Claude with the real IP). AUX_HOSTS are Claude's other
# hosts (assets, CDN, user content, telemetry): their real addresses go into the ng_direct
# table. Status pages and anthropic.ai are left out on purpose: they sit on shared CloudFront
# / AWS addresses, so blocking them would also block unrelated sites.
MAIN_HOSTS = ("claude.ai", "www.claude.ai", "claude.com", "www.claude.com", "anthropic.com",
              "www.anthropic.com", "api.anthropic.com", "console.anthropic.com", "platform.claude.com",
              "code.claude.com")
AUX_HOSTS = ("assets.claude.ai", "a-cdn.claude.ai", "a-api.claude.ai", "app.claude.ai", "api.claude.ai",
             "auth.claude.ai", "a-cdn.anthropic.com", "a-api.anthropic.com", "assets.anthropic.com",
             "claude.usercontent.com", "statsig.anthropic.com", "events.anthropic.com",
             "feedback.anthropic.com", "desktop-app-updates.anthropic.com")

# Installed locations of the guards themselves; never a target, even as a Claude child.
GUARD_PATHS = ("/ClaudeExitGuard.app/", "/ClaudeGuard.app/", "/NetGuard.app/",
               "/.local/share/ClaudeGuard/", "/Library/NetGuard/")
INTERPRETERS = ("python", "node", "bun", "bash", "sh", "zsh", "dash", "perl", "ruby", "osascript")
SCRIPT_RUNTIMES = ("node", "nodejs", "bun")
SHIPIT = "/com.anthropic.claudefordesktop.ShipIt/"
USER_APP = re.compile(r"^/Users/[^/]+/Applications/Claude\.app/")
CLI_FRAGMENTS = ("/.local/share/claude/versions/", "/.claude/local/", "/Caskroom/claude-code/",
                 "/node_modules/@anthropic-ai/claude-code/")

DESKTOP_ROLES = ("main", "helper", "updater")
CLEANUP_POLICIES = ("full", "desktop", "off")
CLEANUP_DEBOUNCE = 2.0   # Claude must stay quit this long (helpers exit on their own first)
TERM_GRACE = 1.0         # SIGTERM, then SIGKILL after this
KILL_CONFIRM = 3.0       # after SIGKILL, give up and report failure after this
RETRY_FAILED = 30.0      # a process that could not be ended is retried this rarely
ROOTS_EVERY = 60.0       # re-discover installed Claude Desktop bundles
ROLE_NAMES = {"main": "Claude 桌面版", "helper": "Claude 辅助进程", "updater": "Claude 更新程序",
              "cli": "Claude Code", "descendant": "Claude 启动的子进程"}


INLINE_FLAGS = ("-c", "-e", "-m", "-p", "--eval", "--print")


def _program(path, argv):
    """The executable, plus the script file an interpreter runs. User arguments never count.

    `zsh -c "<command>"` (how Claude Code runs every shell command) and `python -m x` run
    text, not a script file: that text is the user's, so it never identifies the program.
    """
    found = [path]
    if os.path.basename(path).lower().startswith(INTERPRETERS):
        for token in argv[1:]:
            if token in INLINE_FLAGS:
                break
            if not token.startswith("-"):
                if token.startswith("/"):
                    found.append(token)
                break
    return found


def excluded(path, argv=()):
    return any(g in p for p in _program(path, list(argv)) for g in GUARD_PATHS)


def role(path, argv, roots):
    """main / helper / updater / cli, or None. `roots` are Claude Desktop bundle paths."""
    path = path or ""
    if excluded(path, argv):
        return None
    if SHIPIT in path:
        return "updater"
    for root in roots:
        if path.startswith(root + "/"):
            if os.path.basename(path) == "ShipIt":
                return "updater"
            return "main" if os.path.dirname(path) == root + "/Contents/MacOS" else "helper"
    if USER_APP.match(path):
        return "helper"
    if path.startswith("/Users/") and "/Library/Application Support/Claude/" in path:
        return "helper"  # Desktop-managed binaries, e.g. its built-in Claude Code
    if any(f in path for f in CLI_FRAGMENTS) or os.path.basename(path) == "claude":
        return "cli"
    if os.path.basename(path).lower() in SCRIPT_RUNTIMES and any(
            "/node_modules/@anthropic-ai/claude-code/" in a for a in argv[1:4]):
        return "cli"
    return None


def is_claude(comm, args, cfg):
    """Compatibility helper: one process given as ps-style comm and args text."""
    comm = comm or ""
    argv = (args or "").split()
    path = comm if comm.startswith("/") else (argv[0] if argv and argv[0].startswith("/") else comm)
    roots = [a.rstrip("/") for a in cfg["claude_app_paths"]]
    return role(path, argv, roots) is not None


def identity(row):
    return (row["pid"], row.get("start"), row["path"])


class Engine:
    """Classifies the process table and ends Claude processes. Thread-safe."""

    def __init__(self, cfg, snapshot=None, args_of=None, sender=None, clock=time.monotonic,
                 roots=None, own_pid=os.getpid, store=None):
        self.cfg = cfg
        self.snapshot = snapshot or procs_mod.snapshot
        self.args_of = args_of or procs_mod.arguments
        self.sender = sender or procs_mod.signal_if_same
        self.clock = clock
        self.roots_provider = roots or (lambda: [a.rstrip("/") for a in self.cfg["claude_app_paths"]])
        self.own_pid = own_pid
        self.lock = threading.RLock()
        self.tracked = {}        # identity -> origin ("desktop" / "cli")
        self.args_cache = {}
        self.residual_since = None
        self.attempts = {}       # identity -> {"row", "origin", "role", "term_at", "kill_at"}
        self.skip_until = {}     # identity -> clock() before which a failed target is not retried
        self._roots = None
        self._roots_at = 0
        self.batch = {"cleaned": [], "failed": []}
        self.last_cleanup = None
        self.last = {"main_running": False, "entries": [], "at": 0}
        # Which processes Claude started is known only while their parent lives. Persisting the
        # tracked identities lets a restarted daemon (an upgrade) still recognise children that
        # were re-parented to launchd. pid + start time + path rule out a reused pid.
        self.store = store
        self._saved = None
        self._load()

    # ---------------------------------------------------------------- persistence
    def _load(self):
        if not self.store:
            return
        from . import util
        data = util.read_json(self.store, None)
        if not isinstance(data, list):
            return
        for item in data:
            try:
                start = item["start"]
                key = (int(item["pid"]), (int(start[0]), int(start[1])), str(item["path"]))
                origin = item["origin"] if item["origin"] in ("desktop", "cli") else "desktop"
            except (KeyError, TypeError, ValueError, IndexError):
                continue
            self.tracked[key] = origin
        self._saved = set(self.tracked)

    def _persist(self):
        """Write the tracked identities when the set changed (root-only file)."""
        if not self.store:
            return
        keys = set(k for k in self.tracked if k[1] is not None)
        if keys == self._saved:
            return
        from . import util
        try:
            util.write_json(self.store, [{"pid": k[0], "start": list(k[1]), "path": k[2], "origin": self.tracked[k]}
                                         for k in sorted(keys)], mode=0o600)
            self._saved = keys
        except OSError:
            pass

    # ---------------------------------------------------------------- classify
    def _argv(self, row):
        key = identity(row)
        if key not in self.args_cache:
            self.args_cache[key] = self.args_of(row["pid"])
        return self.args_cache[key]

    def roots(self):
        now = self.clock()
        if self._roots is None or now - self._roots_at >= ROOTS_EVERY:
            try:
                self._roots = sorted(set(r.rstrip("/") for r in self.roots_provider()))
            except Exception:
                self._roots = self._roots or [a.rstrip("/") for a in self.cfg["claude_app_paths"]]
            self._roots_at = now
        return self._roots

    def classify(self, rows=None):
        rows = self.snapshot() if rows is None else rows
        roots = self.roots()
        live = set(identity(r) for r in rows)
        self.tracked = {k: v for k, v in self.tracked.items() if k in live}
        self.args_cache = {k: v for k, v in self.args_cache.items() if k in live}
        found = {}
        for row in rows:
            if row["pid"] <= 1 or row["pid"] == self.own_pid():
                continue
            base = os.path.basename(row["path"]).lower()
            argv = self._argv(row) if base in SCRIPT_RUNTIMES else []
            kind = role(row["path"], argv, roots)
            if kind:
                found[identity(row)] = {"row": row, "role": kind,
                                        "origin": "cli" if kind == "cli" else "desktop"}
            elif identity(row) in self.tracked:
                found[identity(row)] = {"row": row, "role": "descendant", "origin": self.tracked[identity(row)]}
        # Follow the real process tree: shells, node/python MCP servers, dev servers.
        by_pid = {e["row"]["pid"]: e for e in found.values()}
        changed = True
        while changed:
            changed = False
            for row in rows:
                key = identity(row)
                parent = by_pid.get(row["ppid"])
                if key in found or parent is None or row["uid"] != parent["row"]["uid"]:
                    continue
                if row["pid"] <= 1 or row["pid"] == self.own_pid():
                    continue
                if os.path.basename(row["path"]).lower().startswith(INTERPRETERS) and \
                        excluded(row["path"], self._argv(row)):
                    continue
                if excluded(row["path"]):
                    continue
                entry = {"row": row, "role": "descendant", "origin": parent["origin"]}
                found[key] = entry
                by_pid[row["pid"]] = entry
                changed = True
        for key, entry in found.items():
            self.tracked[key] = entry["origin"]
        self._persist()
        entries = sorted(found.values(), key=lambda e: e["row"]["pid"])
        self.last = {"main_running": any(e["role"] == "main" for e in entries), "entries": entries,
                     "at": time.time()}
        return self.last

    # ---------------------------------------------------------------- isolation
    def isolate_now(self):
        """SIGKILL every Claude process at once (like Windows Stop-Process -Force)."""
        with self.lock:
            entries = self.classify()["entries"]
            self.attempts.clear()
            self.residual_since = None
            killed = 0
            for entry in entries:
                if self.sender(entry["row"], signal.SIGKILL) == 0:
                    killed += 1
            return killed

    # ---------------------------------------------------------------- cleanup after quit
    def cleanup_step(self, console_uid):
        """One pass of cleanup after Claude Desktop quit. Returns a finished batch or None.

        Only the console user's processes are touched; the updater is left alone so a
        Claude update installed on quit is never interrupted.
        """
        with self.lock:
            now = self.clock()
            policy = self.cfg.get("claude_cleanup", "full")
            view = self.classify()
            if policy == "off" or view["main_running"] or console_uid is None:
                self.attempts.clear()
                self.residual_since = None
                self.batch = {"cleaned": [], "failed": []}
                return None
            live = {identity(e["row"]): e for e in view["entries"]}
            self.skip_until = {k: t for k, t in self.skip_until.items() if k in live and t > now}
            targets = [e for e in view["entries"]
                       if e["row"]["uid"] == console_uid and e["role"] != "updater"
                       and (e["origin"] == "desktop" or policy == "full")
                       and identity(e["row"]) not in self.skip_until]
            for key, attempt in list(self.attempts.items()):
                if key not in live:
                    self.batch["cleaned"].append(attempt)
                    del self.attempts[key]
            if not targets and not self.attempts:
                self.residual_since = None
                return self._finish_batch()
            if self.residual_since is None:
                self.residual_since = now
            if now - self.residual_since < CLEANUP_DEBOUNCE:
                return None
            # Claude may have been reopened while we decided: look once more before signalling.
            if any(e["role"] == "main" for e in self.classify()["entries"]):
                self.attempts.clear()
                self.residual_since = None
                return None
            for entry in targets:
                key = identity(entry["row"])
                if key in self.attempts or key in self.skip_until:
                    continue
                result = self.sender(entry["row"], signal.SIGTERM)
                if result == 0:
                    self.attempts[key] = dict(entry, term_at=now, kill_at=None)
                elif result != errno.ESRCH:  # ESRCH: already gone or replaced
                    self.batch["failed"].append(dict(entry, error=result))
                    self.skip_until[key] = now + RETRY_FAILED
            for key, attempt in list(self.attempts.items()):
                if attempt["kill_at"] is None and now - attempt["term_at"] >= TERM_GRACE:
                    result = self.sender(attempt["row"], signal.SIGKILL)
                    if result in (0, errno.ESRCH):
                        attempt["kill_at"] = now
                    else:
                        self.batch["failed"].append(dict(attempt, error=result))
                        self.skip_until[key] = now + RETRY_FAILED
                        del self.attempts[key]
                elif attempt["kill_at"] is not None and now - attempt["kill_at"] >= KILL_CONFIRM:
                    self.batch["failed"].append(dict(attempt, error=None))
                    self.skip_until[key] = now + RETRY_FAILED
                    del self.attempts[key]
            return None if self.attempts else self._finish_batch()

    def _finish_batch(self):
        batch, self.batch = self.batch, {"cleaned": [], "failed": []}
        if not batch["cleaned"] and not batch["failed"]:
            return None
        self.residual_since = None
        result = {"at": time.time(), "cleaned": [self.describe(a) for a in batch["cleaned"]],
                  "failed": [self.describe(a) for a in batch["failed"]]}
        self.last_cleanup = result
        return result

    # ---------------------------------------------------------------- status
    @staticmethod
    def describe(entry):
        row = entry["row"]
        return {"pid": row["pid"], "name": os.path.basename(row["path"]), "role": entry["role"],
                "origin": entry["origin"], "path": row["path"]}

    def status(self, limit=60):
        with self.lock:
            entries = self.last["entries"]
            return {"main_running": self.last["main_running"], "count": len(entries),
                    "processes": [self.describe(e) for e in entries[:limit]],
                    "checked_at": int(self.last["at"]), "policy": self.cfg.get("claude_cleanup", "full"),
                    "cleaning": len(self.attempts), "last_cleanup": self.last_cleanup}


def summarize(names):
    """'Claude Helper ×3、zsh ×2' for notifications."""
    counts = {}
    for name in names:
        counts[name] = counts.get(name, 0) + 1
    return "、".join("%s ×%d" % (n, c) if c > 1 else n for n, c in sorted(counts.items(), key=lambda x: -x[1]))
