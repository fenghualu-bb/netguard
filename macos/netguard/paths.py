"""Fixed locations. Root-run code never takes them from the environment."""
import os


def _root():
    # Tests (never root) may relocate the data directory. A root process always
    # uses the protected location, so sudo/osascript environments cannot redirect it.
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        override = os.environ.get("NETGUARD_ROOT")
        if override:
            return override
    return "/Library/NetGuard"


ROOT = _root()


def p(name):
    return os.path.join(ROOT, name)


CONFIG = p("config.json")
STATE = p("state.json")
GUARD = p("guard.json")
STATUS = p("status.json")
EVENTS = p("events.jsonl")
LOG = p("netguard.log")
LOCK = p("state.lock")
TOKEN = p("pf-token")            # digits only; shared with the boot and recovery shell scripts
ANCHOR_FILE = p("anchor.rules")  # last loaded rules; re-applied by bin/netguard-boot before Python runs

# A child of the default `anchor "com.apple/*"` in /etc/pf.conf. NetGuard never edits
# /etc/pf.conf and never reloads the main ruleset. "zz." sorts after Apple's own anchors.
ANCHOR = "com.apple/zz.NetGuard"

PFCTL = "/sbin/pfctl"
CURL = "/usr/bin/curl"
PS = "/bin/ps"
IFCONFIG = "/sbin/ifconfig"
ROUTE = "/sbin/route"
SYSCTL = "/usr/sbin/sysctl"
LAUNCHCTL = "/bin/launchctl"
OSASCRIPT = "/usr/bin/osascript"
SUDO = "/usr/bin/sudo"
DSCACHEUTIL = "/usr/bin/dscacheutil"
