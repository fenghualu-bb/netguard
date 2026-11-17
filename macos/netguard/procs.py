"""The process table read straight from the kernel (libproc), without starting `ps`.

Each row carries the executable path as the kernel reports it (proc_pidpath), which a
process cannot fake through argv[0], plus the parent pid and the start time. pid + start
time identify a process even if its pid is later reused. Reading ~700 processes costs a
few milliseconds, versus ~25 ms of CPU for every `ps -axww` it replaces.

Rows are dicts compatible with the old `ps` parser: pid, uid (effective), gid (real
group), comm (= path), plus ppid, path, start.
"""
import ctypes
import os
import sys

from . import paths, util

PROC_PIDTBSDINFO = 3
SZOMB = 5
CTL_KERN = 1
KERN_PROCARGS2 = 49
PATH_MAX = 4096


class _BSDInfo(ctypes.Structure):
    # struct proc_bsdinfo, <sys/proc_info.h>; 136 bytes on every macOS since 10.5.
    _fields_ = [
        ("flags", ctypes.c_uint32), ("status", ctypes.c_uint32), ("xstatus", ctypes.c_uint32),
        ("pid", ctypes.c_uint32), ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
        ("ruid", ctypes.c_uint32), ("rgid", ctypes.c_uint32),
        ("svuid", ctypes.c_uint32), ("svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
        ("nfiles", ctypes.c_uint32), ("pgid", ctypes.c_uint32), ("pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32), ("e_tpgid", ctypes.c_uint32), ("nice", ctypes.c_int32),
        ("start_tvsec", ctypes.c_uint64), ("start_tvusec", ctypes.c_uint64),
    ]


class _ShortInfo(ctypes.Structure):
    # struct proc_bsdshortinfo (64 bytes): readable for every process even without root,
    # but without the start time.
    _fields_ = [
        ("pid", ctypes.c_uint32), ("ppid", ctypes.c_uint32), ("pgid", ctypes.c_uint32),
        ("status", ctypes.c_uint32), ("comm", ctypes.c_char * 16), ("flags", ctypes.c_uint32),
        ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32), ("ruid", ctypes.c_uint32),
        ("rgid", ctypes.c_uint32), ("svuid", ctypes.c_uint32), ("svgid", ctypes.c_uint32),
        ("rfu", ctypes.c_uint32),
    ]


PROC_PIDT_SHORTBSDINFO = 13
_lib = None


def _libproc():
    global _lib
    if _lib is None:
        if sys.platform != "darwin":
            raise OSError("libproc is macOS only")
        lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.proc_listallpids.restype = ctypes.c_int
        lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        lib.proc_pidinfo.restype = ctypes.c_int
        lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        lib.proc_pidpath.restype = ctypes.c_int
        _lib = lib
    return _lib


def available():
    try:
        _libproc()
        return ctypes.sizeof(_BSDInfo) == 136 and ctypes.sizeof(_ShortInfo) == 64
    except OSError:
        return False


def current(pid):
    """One process, or None if it is gone, a zombie or unreadable.

    The full record (with start time) is readable for every process as root (the daemon) and
    for one's own processes otherwise; other processes fall back to the short record.
    """
    lib = _libproc()
    pid = int(pid)
    info = _BSDInfo()
    if lib.proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, ctypes.byref(info), ctypes.sizeof(info)) == ctypes.sizeof(info):
        start = (int(info.start_tvsec), int(info.start_tvusec))
    else:
        info = _ShortInfo()
        if lib.proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, ctypes.byref(info),
                            ctypes.sizeof(info)) != ctypes.sizeof(info):
            return None
        start = None
    if info.status == SZOMB:
        return None
    buf = ctypes.create_string_buffer(PATH_MAX)
    if lib.proc_pidpath(pid, buf, PATH_MAX) <= 0:
        return None
    path = buf.value.decode("utf-8", "surrogateescape")
    return {"pid": int(info.pid), "ppid": int(info.ppid), "uid": int(info.uid), "ruid": int(info.ruid),
            "gid": int(info.rgid), "start": start, "path": path, "comm": path}


def _list_pids():
    lib = _libproc()
    capacity = max(lib.proc_listallpids(None, 0), 0) + 1024
    while True:
        buf = (ctypes.c_int * capacity)()
        count = lib.proc_listallpids(buf, ctypes.sizeof(buf))
        if count < 0:
            raise OSError(ctypes.get_errno(), "proc_listallpids failed")
        if count < capacity:
            return [buf[i] for i in range(count) if buf[i] > 0]
        capacity *= 2


def snapshot():
    rows = []
    for pid in _list_pids():
        row = current(pid)
        if row is not None:
            rows.append(row)
    return rows


def arguments(pid):
    """argv of a process (KERN_PROCARGS2). Other users' processes need root; [] if unreadable."""
    libc = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 3)(CTL_KERN, KERN_PROCARGS2, int(pid))
    size = ctypes.c_size_t(1024 * 1024)
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0 or size.value < 4:
        return []
    raw = buf.raw[:size.value]
    argc = int.from_bytes(raw[:4], sys.byteorder)
    if not 0 < argc < 8192:
        return []
    index = raw.find(b"\0", 4)  # skip the saved executable path
    if index < 0:
        return []
    while index < len(raw) and raw[index] == 0:
        index += 1
    args = []
    for _ in range(argc):
        end = raw.find(b"\0", index)
        if end < 0:
            break
        args.append(raw[index:end].decode("utf-8", "surrogateescape"))
        index = end + 1
    return args


def ps_snapshot(runner=util.run):
    """Fallback for hosts without libproc: same rows from `ps` (no start time)."""
    out = runner([paths.PS, "-axww", "-o", "pid=,ppid=,uid=,rgid=,comm="]).stdout
    rows = []
    for line in (out or "").splitlines():
        parts = line.strip().split(None, 4)
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        try:
            pid, ppid, uid, gid = (int(x) for x in parts[:4])
        except ValueError:
            continue
        rows.append({"pid": pid, "ppid": ppid, "uid": uid, "ruid": uid, "gid": gid, "start": None,
                     "path": parts[4].strip(), "comm": parts[4].strip()})
    return rows


def signal_if_same(row, sig):
    """Send `sig` only if the pid still runs the same program started at the same time.

    Returns 0 on success, or an errno (ESRCH when the process is gone or was replaced).
    """
    import errno
    if row["pid"] <= 1 or row["pid"] == os.getpid():
        return errno.EINVAL
    if row.get("start") is not None:
        fresh = current(row["pid"])
        if fresh is None or fresh["start"] != row["start"] or fresh["path"] != row["path"]:
            return errno.ESRCH
    try:
        os.kill(row["pid"], sig)
        return 0
    except ProcessLookupError:
        return errno.ESRCH
    except PermissionError:
        return errno.EPERM
