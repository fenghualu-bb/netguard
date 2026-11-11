"""Small helpers: subprocess without a shell, atomic JSON, the state lock and the log."""
import json
import os
import subprocess
import tempfile
import time

from . import paths


class CommandError(RuntimeError):
    pass


def now():
    return time.time()


def run(args, input=None, timeout=15, env=None):
    """Run a fixed argv (never a shell string). Returns CompletedProcess; never raises on rc."""
    base = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"}
    if env:
        base.update(env)
    try:
        return subprocess.run(list(args), input=input, capture_output=True, text=True,
                              timeout=timeout, env=base)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(args, 124, exc.stdout or "", "timeout after %ss" % timeout)
    except OSError as exc:
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as stream:
            return json.load(stream)
    except FileNotFoundError:
        return default
    except (OSError, ValueError):
        return default


def write_json(path, value, mode=0o644):
    directory = os.path.dirname(path) or "."
    fd, temp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def write_text(path, text, mode=0o644):
    directory = os.path.dirname(path) or "."
    fd, temp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


class StateLock:
    """One lock for the watch loop and every administrative command.

    flock is released by the kernel when the holder dies, so an interrupted
    `enable` can never wedge the daemon: the daemon then rolls the change back
    at the pending deadline.
    """

    def __init__(self, path=None, timeout=90.0):
        self.path = path or paths.LOCK
        self.timeout = timeout
        self.stream = None

    def __enter__(self):
        try:
            import fcntl
        except ImportError:  # Windows test hosts only
            return self
        self.stream = open(self.path, "a+")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    self.stream.close()
                    self.stream = None
                    raise CommandError("等待状态锁超时（另一个 NetGuard 操作仍在进行）")
                time.sleep(0.2)

    def __exit__(self, *exc):
        if self.stream is not None:
            self.stream.close()
            self.stream = None
        return False


def log(text, action="-"):
    line = "%s [%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), action, text)
    try:
        if os.path.exists(paths.LOG) and os.path.getsize(paths.LOG) > 1_000_000:
            os.replace(paths.LOG, paths.LOG + ".1")
        with open(paths.LOG, "a", encoding="utf-8") as stream:
            stream.write(line)
    except OSError:
        pass
