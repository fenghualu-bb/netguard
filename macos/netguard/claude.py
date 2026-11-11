"""Find and stop Claude Desktop and Claude Code while NetGuard isolates Claude.

macOS pf cannot filter by program, so isolation means: every Claude process found is
terminated, and the daemon keeps terminating relaunches every 2 seconds until the
isolation is lifted (Windows uses a per-program WFP block for the same purpose).
"""
import os
import signal
import time

EXCLUDE = ("claudeguard", "netguard")


def is_claude(comm, args, cfg):
    comm = comm or ""
    args = args or ""
    lowered = (comm + " " + args).lower()
    if any(word in lowered for word in EXCLUDE):
        return False
    exe = comm if comm.startswith("/") else (args.split(" ", 1)[0] if args.startswith("/") else comm)
    for app in cfg["claude_app_paths"]:
        prefix = app.rstrip("/") + "/"
        if exe.startswith(prefix) or args.startswith(prefix):
            return True
    if exe.startswith("/Users/") and "/Applications/Claude.app/" in exe:
        return True  # ~/Applications/Claude.app
    base = os.path.basename(exe)
    if base == "claude":
        return True
    if "/.local/share/claude/versions/" in exe or "/.claude/local/" in exe:
        return True
    if "@anthropic-ai/claude-code" in args:
        return True
    return False


def find(probes, cfg):
    procs = probes.processes()
    argv = probes.process_args()
    mine = os.getpid()
    found = []
    for row in procs:
        if row["pid"] in (mine, 0, 1):
            continue
        if is_claude(row["comm"], argv.get(row["pid"], ""), cfg):
            found.append(row["pid"])
    return found


def stop(pids, grace=1.5):
    stopped = 0
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            stopped += 1
        except (ProcessLookupError, PermissionError):
            continue
    if not stopped:
        return 0
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        alive = [p for p in pids if _alive(p)]
        if not alive:
            break
        time.sleep(0.1)
    for pid in pids:
        if _alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    return stopped


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
