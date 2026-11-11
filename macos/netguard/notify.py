"""macOS notifications from the root daemon to the logged-in user."""
import time

from . import paths, util

_last = {}


def _quote(text):
    return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"') + '"'


def send(probes, title, message, key=None, every=300):
    """Show a notification in the console user's session; throttled per key."""
    key = key or (title + message)
    now = time.time()
    if now - _last.get(key, 0) < every:
        return False
    user = probes.console_user()
    if not user:
        return False
    name, uid = user
    script = "display notification %s with title %s sound name \"Basso\"" % (_quote(message), _quote(title))
    result = util.run([paths.LAUNCHCTL, "asuser", str(uid), paths.SUDO, "-u", name,
                       paths.OSASCRIPT, "-e", script], timeout=10)
    _last[key] = now
    return result.returncode == 0
